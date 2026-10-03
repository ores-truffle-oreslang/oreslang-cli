mod framing;
mod watcher;

use framing::{read_message, write_message};
use oreslang_compiler_client::{
    CheckResult, CompilerClientError, CompilerCommand, CompilerSupervisor,
};
use oreslang_protocol::{Diagnostic, DiagnosticSeverity};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Duration;
use watcher::PollingWatcher;

const SERVER_NAME: &str = "oreslang";
const MAX_LOG_MESSAGE: usize = 4096;

#[derive(Debug)]
enum Event {
    Rpc(Value),
    ReaderClosed,
    ReaderError(String),
    CheckCompleted {
        uri: String,
        generation: u64,
        result: Result<CheckResult, CompilerClientError>,
    },
    FileChanged(PathBuf),
}

#[derive(Debug)]
struct Document {
    path: Option<PathBuf>,
    text: String,
    version: Option<i64>,
    dirty: bool,
    generation: u64,
}

impl Document {
    fn replace_text(&mut self, text: String, version: Option<i64>) {
        self.text = text;
        self.version = version;
        self.dirty = true;
    }
}

pub fn run_stdio(command: CompilerCommand) -> io::Result<i32> {
    let (events, event_rx) = mpsc::channel::<Event>();

    let reader_events = events.clone();
    thread::Builder::new()
        .name("oreslang-lsp-reader".to_owned())
        .spawn(move || {
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin.lock());
            loop {
                match read_message(&mut reader) {
                    Ok(Some(message)) => {
                        if reader_events.send(Event::Rpc(message)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = reader_events.send(Event::ReaderClosed);
                        break;
                    }
                    Err(error) => {
                        let _ = reader_events.send(Event::ReaderError(error.to_string()));
                        break;
                    }
                }
            }
        })
        .expect("spawn Oreslang LSP reader");

    let (watcher, changed_rx) = PollingWatcher::start(Duration::from_millis(700));
    let watcher_events = events.clone();
    thread::Builder::new()
        .name("oreslang-lsp-watch-bridge".to_owned())
        .spawn(move || {
            while let Ok(path) = changed_rx.recv() {
                if watcher_events.send(Event::FileChanged(path)).is_err() {
                    break;
                }
            }
        })
        .expect("spawn Oreslang LSP watch bridge");

    let supervisor = CompilerSupervisor::start(command);
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let mut documents = HashMap::<String, Document>::new();
    let mut shutdown_requested = false;
    let mut exit_code = 0_i32;

    while let Ok(event) = event_rx.recv() {
        match event {
            Event::Rpc(message) => {
                let method = message.get("method").and_then(Value::as_str);
                let id = message.get("id").cloned();

                match method {
                    Some("initialize") => {
                        if let Some(id) = id {
                            write_response(
                                &mut writer,
                                id,
                                json!({
                                    "capabilities": {
                                        "positionEncoding": "utf-16",
                                        "textDocumentSync": {
                                            "openClose": true,
                                            "change": 1,
                                            "save": { "includeText": true }
                                        },
                                        "workspace": {
                                            "workspaceFolders": {
                                                "supported": true,
                                                "changeNotifications": false
                                            }
                                        }
                                    },
                                    "serverInfo": {
                                        "name": SERVER_NAME,
                                        "version": env!("CARGO_PKG_VERSION")
                                    }
                                }),
                            )?;
                        }
                    }
                    Some("initialized") => {}
                    Some("shutdown") => {
                        shutdown_requested = true;
                        if let Some(id) = id {
                            write_response(&mut writer, id, Value::Null)?;
                        }
                    }
                    Some("exit") => {
                        exit_code = if shutdown_requested { 0 } else { 1 };
                        break;
                    }
                    Some("$/cancelRequest") => {}
                    Some("textDocument/didOpen") => {
                        if let Some((uri, text, version)) = parse_did_open(&message) {
                            let path = uri_to_path(&uri);
                            if let Some(path) = &path {
                                watcher.add(path.clone());
                            }
                            documents.insert(
                                uri.clone(),
                                Document {
                                    path,
                                    text,
                                    version,
                                    dirty: false,
                                    generation: 0,
                                },
                            );
                            schedule_check(&uri, &mut documents, &supervisor, &events);
                        }
                    }
                    Some("textDocument/didChange") => {
                        if let Some((uri, text, version)) = parse_did_change(&message) {
                            if let Some(document) = documents.get_mut(&uri) {
                                document.replace_text(text, version);
                            }
                        }
                    }
                    Some("textDocument/didSave") => {
                        if let Some((uri, text)) = parse_did_save(&message) {
                            if let Some(document) = documents.get_mut(&uri) {
                                if let Some(text) = text {
                                    document.text = text;
                                }
                                document.dirty = false;
                            }
                            schedule_check(&uri, &mut documents, &supervisor, &events);
                        }
                    }
                    Some("textDocument/didClose") => {
                        if let Some(uri) = text_document_uri(&message) {
                            if let Some(document) = documents.remove(&uri) {
                                if let Some(path) = document.path {
                                    watcher.remove(path);
                                }
                            }
                            publish_diagnostics(&mut writer, &uri, Vec::new())?;
                        }
                    }
                    Some("workspace/didChangeWatchedFiles") => {
                        let uris = message
                            .pointer("/params/changes")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(|change| change.get("uri").and_then(Value::as_str))
                            .map(str::to_owned)
                            .collect::<Vec<_>>();
                        for uri in uris {
                            let should_check = documents
                                .get(&uri)
                                .map(|document| !document.dirty)
                                .unwrap_or(false);
                            if should_check {
                                schedule_check(
                                    &uri,
                                    &mut documents,
                                    &supervisor,
                                    &events,
                                );
                            }
                        }
                    }
                    Some(_) if id.is_some() => {
                        write_error(
                            &mut writer,
                            id.expect("checked"),
                            -32601,
                            "method not found",
                        )?;
                    }
                    _ => {}
                }
            }
            Event::CheckCompleted {
                uri,
                generation,
                result,
            } => {
                let current = documents
                    .get(&uri)
                    .map(|document| document.generation == generation)
                    .unwrap_or(false);
                if current {
                    publish_check_result(&mut writer, &uri, result)?;
                }
            }
            Event::FileChanged(path) => {
                let uris = documents
                    .iter()
                    .filter(|(_, document)| {
                        document.path.as_ref() == Some(&path) && !document.dirty
                    })
                    .map(|(uri, _)| uri.clone())
                    .collect::<Vec<_>>();
                for uri in uris {
                    schedule_check(&uri, &mut documents, &supervisor, &events);
                }
            }
            Event::ReaderClosed => {
                exit_code = if shutdown_requested { 0 } else { 1 };
                break;
            }
            Event::ReaderError(message) => {
                let message = truncate(&message, MAX_LOG_MESSAGE);
                write_notification(
                    &mut writer,
                    "window/logMessage",
                    json!({"type": 1, "message": format!("Oreslang LSP input error: {message}")}),
                )?;
                return Err(io::Error::new(io::ErrorKind::InvalidData, message));
            }
        }
    }

    drop(watcher);
    drop(supervisor);
    Ok(exit_code)
}

fn schedule_check(
    uri: &str,
    documents: &mut HashMap<String, Document>,
    supervisor: &CompilerSupervisor,
    events: &Sender<Event>,
) {
    let Some(document) = documents.get_mut(uri) else {
        return;
    };
    let Some(path) = document.path.clone() else {
        return;
    };

    document.generation = document.generation.saturating_add(1);
    let generation = document.generation;
    let uri = uri.to_owned();

    match supervisor.check_file_async(path) {
        Ok(receiver) => {
            let events = events.clone();
            let _ = thread::Builder::new()
                .name("oreslang-lsp-check-result".to_owned())
                .spawn(move || {
                    let result = receiver
                        .recv()
                        .unwrap_or(Err(CompilerClientError::SupervisorClosed));
                    let _ = events.send(Event::CheckCompleted {
                        uri,
                        generation,
                        result,
                    });
                });
        }
        Err(error) => {
            let _ = events.send(Event::CheckCompleted {
                uri,
                generation,
                result: Err(error),
            });
        }
    }
}

fn parse_did_open(message: &Value) -> Option<(String, String, Option<i64>)> {
    let document = message.pointer("/params/textDocument")?;
    Some((
        document.get("uri")?.as_str()?.to_owned(),
        document.get("text")?.as_str()?.to_owned(),
        document.get("version").and_then(Value::as_i64),
    ))
}

fn parse_did_change(message: &Value) -> Option<(String, String, Option<i64>)> {
    let document = message.pointer("/params/textDocument")?;
    let uri = document.get("uri")?.as_str()?.to_owned();
    let version = document.get("version").and_then(Value::as_i64);
    let text = message
        .pointer("/params/contentChanges")
        .and_then(Value::as_array)?
        .last()?
        .get("text")?
        .as_str()?
        .to_owned();
    Some((uri, text, version))
}

fn parse_did_save(message: &Value) -> Option<(String, Option<String>)> {
    let uri = message
        .pointer("/params/textDocument/uri")?
        .as_str()?
        .to_owned();
    let text = message
        .pointer("/params/text")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some((uri, text))
}

fn text_document_uri(message: &Value) -> Option<String> {
    message
        .pointer("/params/textDocument/uri")?
        .as_str()
        .map(str::to_owned)
}

fn publish_check_result<W: Write>(
    writer: &mut W,
    triggering_uri: &str,
    result: Result<CheckResult, CompilerClientError>,
) -> io::Result<()> {
    let mut grouped = BTreeMap::<String, Vec<Value>>::new();

    match result {
        Ok(result) => {
            for diagnostic in result.diagnostics {
                let uri = path_to_file_uri(&diagnostic.path);
                grouped
                    .entry(uri)
                    .or_default()
                    .push(diagnostic_to_lsp(&diagnostic));
            }
        }
        Err(error) => {
            grouped
                .entry(triggering_uri.to_owned())
                .or_default()
                .push(json!({
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 1}
                    },
                    "severity": 1,
                    "source": "oreslang",
                    "message": error.to_string()
                }));
        }
    }

    grouped.entry(triggering_uri.to_owned()).or_default();

    for (uri, diagnostics) in grouped {
        publish_diagnostics(writer, &uri, diagnostics)?;
    }
    Ok(())
}

fn diagnostic_to_lsp(diagnostic: &Diagnostic) -> Value {
    let start_line = diagnostic.range.start.line.saturating_sub(1);
    let start_character = diagnostic.range.start.column.saturating_sub(1);
    let end_line = diagnostic.range.end.line.saturating_sub(1).max(start_line);
    let end_character = diagnostic
        .range
        .end
        .column
        .saturating_sub(1)
        .max(start_character.saturating_add(1));

    let severity = match diagnostic.severity {
        DiagnosticSeverity::Error => 1,
        DiagnosticSeverity::Warning => 2,
        DiagnosticSeverity::Info => 3,
        DiagnosticSeverity::Hint => 4,
    };

    let mut value = json!({
        "range": {
            "start": {"line": start_line, "character": start_character},
            "end": {"line": end_line, "character": end_character}
        },
        "severity": severity,
        "source": diagnostic.source,
        "message": diagnostic.message
    });

    if let Some(code) = &diagnostic.code {
        value["code"] = Value::String(code.clone());
    }
    value
}

fn publish_diagnostics<W: Write>(
    writer: &mut W,
    uri: &str,
    diagnostics: Vec<Value>,
) -> io::Result<()> {
    write_notification(
        writer,
        "textDocument/publishDiagnostics",
        json!({"uri": uri, "diagnostics": diagnostics}),
    )
}

fn write_response<W: Write>(writer: &mut W, id: Value, result: Value) -> io::Result<()> {
    write_message(
        writer,
        &json!({"jsonrpc": "2.0", "id": id, "result": result}),
    )
}

fn write_error<W: Write>(
    writer: &mut W,
    id: Value,
    code: i32,
    message: &str,
) -> io::Result<()> {
    write_message(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": message}
        }),
    )
}

fn write_notification<W: Write>(
    writer: &mut W,
    method: &str,
    params: Value,
) -> io::Result<()> {
    write_message(
        writer,
        &json!({"jsonrpc": "2.0", "method": method, "params": params}),
    )
}

fn uri_to_path(uri: &str) -> Option<PathBuf> {
    let raw = uri.strip_prefix("file://")?;
    let raw = raw.strip_prefix("localhost").unwrap_or(raw);
    let decoded = percent_decode(raw)?;

    #[cfg(windows)]
    let decoded = if decoded.starts_with('/')
        && decoded.as_bytes().get(2).copied() == Some(b':')
    {
        decoded[1..].to_owned()
    } else {
        decoded
    };

    Some(PathBuf::from(decoded))
}

fn path_to_file_uri(path: &Path) -> String {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut text = absolute.to_string_lossy().replace('\\', "/");

    #[cfg(windows)]
    if text.as_bytes().get(1).copied() == Some(b':') {
        text.insert(0, '/');
    }

    format!("file://{}", percent_encode(&text))
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push((hex_value(high)? << 4) | hex_value(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).ok()
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(*byte, b'/' | b':' | b'-' | b'.' | b'_' | b'~')
        {
            encoded.push(*byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{:02X}", byte));
        }
    }
    encoded
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oreslang_protocol::{DiagnosticRange, Position};

    #[test]
    fn file_uri_round_trip_handles_spaces() {
        let path = PathBuf::from("/tmp/ores lang/demo.ores");
        let uri = path_to_file_uri(&path);
        assert_eq!(uri, "file:///tmp/ores%20lang/demo.ores");
        assert_eq!(uri_to_path(&uri), Some(path));
    }

    #[test]
    fn maps_one_based_compiler_positions_to_zero_based_lsp_positions() {
        let diagnostic = Diagnostic {
            path: PathBuf::from("/tmp/demo.ores"),
            range: DiagnosticRange {
                start: Position::new(7, 13),
                end: Position::new(7, 14),
            },
            severity: DiagnosticSeverity::Error,
            code: Some("ORES-TYPE-1".to_owned()),
            source: "oreslang".to_owned(),
            message: "bad type".to_owned(),
        };

        let value = diagnostic_to_lsp(&diagnostic);
        assert_eq!(value["range"]["start"]["line"], 6);
        assert_eq!(value["range"]["start"]["character"], 12);
        assert_eq!(value["range"]["end"]["character"], 13);
        assert_eq!(value["severity"], 1);
        assert_eq!(value["code"], "ORES-TYPE-1");
    }

    #[test]
    fn parses_full_sync_change() {
        let message = json!({
            "params": {
                "textDocument": {"uri": "file:///tmp/a.ores", "version": 3},
                "contentChanges": [{"text": "pub fnc main() {}"}]
            }
        });
        let (uri, text, version) = parse_did_change(&message).expect("change");
        assert_eq!(uri, "file:///tmp/a.ores");
        assert_eq!(text, "pub fnc main() {}");
        assert_eq!(version, Some(3));
    }
}
