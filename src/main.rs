use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const PROTOCOL_VERSION: u32 = 1;
const DEFAULT_COMPILER_BACKEND: &str = "oreslang-compiler";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Diagnostic {
    path: String,
    line: u32,
    column: u32,
    end_line: u32,
    end_column: u32,
    severity: String,
    message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Json,
    Jsonl,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("oreslang: {message}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<u8, String> {
    if args.is_empty() {
        print_usage();
        return Ok(0);
    }

    match args[0].as_str() {
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(0)
        }
        "--version" | "-V" | "version" => {
            println!("oreslang {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "doctor" => doctor(&args[1..]),
        "check" => check(&args[1..]),
        other => Err(format!("unknown command '{other}'")),
    }
}

fn print_usage() {
    println!(
        "Oreslang developer tooling\n\n\
         Usage:\n  oreslang check [--format=human|json|jsonl] [--compiler <path>] <file.ores>...\n  \
         oreslang doctor [--compiler <path>]\n  \
         oreslang version\n\n\
         The public Oreslang CLI is 'oreslang'. It never falls back to a command named 'ores'."
    );
}

fn parse_backend_arg(args: &[String]) -> Result<(Option<String>, Vec<String>), String> {
    let mut backend = None;
    let mut remaining = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--compiler" {
            let value = args.get(i + 1).ok_or("--compiler requires a path")?;
            backend = Some(value.clone());
            i += 2;
        } else if let Some(value) = args[i].strip_prefix("--compiler=") {
            if value.is_empty() {
                return Err("--compiler requires a path".into());
            }
            backend = Some(value.to_owned());
            i += 1;
        } else {
            remaining.push(args[i].clone());
            i += 1;
        }
    }
    Ok((backend, remaining))
}

fn resolve_backend(explicit: Option<String>) -> (String, &'static str) {
    if let Some(command) = explicit {
        return (command, "--compiler");
    }
    if let Ok(command) = env::var("ORESLANG_COMPILER") {
        if !command.trim().is_empty() {
            return (command, "ORESLANG_COMPILER");
        }
    }
    (DEFAULT_COMPILER_BACKEND.to_owned(), "default")
}

fn doctor(args: &[String]) -> Result<u8, String> {
    let (explicit, remaining) = parse_backend_arg(args)?;
    if !remaining.is_empty() {
        return Err(format!("unexpected argument '{}'", remaining[0]));
    }
    let (backend, source) = resolve_backend(explicit);

    println!("oreslang {}", env!("CARGO_PKG_VERSION"));
    println!("public-cli: oreslang");
    println!("compiler-backend: {backend}");
    println!("compiler-backend-source: {source}");
    println!("forbidden-fallback: ores");
    println!("check-mode: non-executing compiler validation only");
    Ok(0)
}

fn check(args: &[String]) -> Result<u8, String> {
    let (explicit_backend, args) = parse_backend_arg(args)?;
    let (backend, _) = resolve_backend(explicit_backend);

    let mut format = OutputFormat::Human;
    let mut files = Vec::<PathBuf>::new();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];
        if arg == "--format" {
            let value = args.get(i + 1).ok_or("--format requires a value")?;
            format = parse_format(value)?;
            i += 2;
        } else if let Some(value) = arg.strip_prefix("--format=") {
            format = parse_format(value)?;
            i += 1;
        } else if arg == "--" {
            files.extend(args[i + 1..].iter().map(PathBuf::from));
            break;
        } else if arg.starts_with('-') {
            return Err(format!("unknown check option '{arg}'"));
        } else {
            files.push(PathBuf::from(arg));
            i += 1;
        }
    }

    if files.is_empty() {
        return Err("check requires at least one .ores file".into());
    }

    let mut diagnostics = Vec::new();
    let mut backend_failed = false;

    for file in &files {
        let outcome = check_file(&backend, file);
        diagnostics.extend(outcome.diagnostics);
        backend_failed |= outcome.backend_failed;
    }

    emit_diagnostics(format, &diagnostics, !backend_failed && diagnostics.is_empty());

    if backend_failed || !diagnostics.is_empty() {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn parse_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "human" => Ok(OutputFormat::Human),
        "json" => Ok(OutputFormat::Json),
        "jsonl" => Ok(OutputFormat::Jsonl),
        _ => Err(format!("unsupported output format '{value}'")),
    }
}

struct CheckOutcome {
    diagnostics: Vec<Diagnostic>,
    backend_failed: bool,
}

fn check_file(backend: &str, file: &Path) -> CheckOutcome {
    let default_path = absoluteish(file);
    let output = Command::new(backend).arg("--check").arg(file).output();

    let output = match output {
        Ok(output) => output,
        Err(error) => {
            return CheckOutcome {
                diagnostics: vec![Diagnostic {
                    path: default_path,
                    line: 1,
                    column: 1,
                    end_line: 1,
                    end_column: 2,
                    severity: "error".into(),
                    message: format!(
                        "Oreslang compiler backend '{backend}' could not be started: {error}. \
                         Install oreslang-compiler or set ORESLANG_COMPILER."
                    ),
                }],
                backend_failed: true,
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = if stdout.is_empty() {
        stderr.to_string()
    } else if stderr.is_empty() {
        stdout.to_string()
    } else {
        format!("{stdout}\n{stderr}")
    };

    let mut diagnostics = parse_backend_output(&combined, &default_path);

    if !output.status.success() && diagnostics.is_empty() {
        diagnostics.push(Diagnostic {
            path: default_path,
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 2,
            severity: "error".into(),
            message: if combined.trim().is_empty() {
                format!("compiler backend exited with {}", output.status)
            } else {
                combined.trim().to_owned()
            },
        });
    }

    CheckOutcome {
        diagnostics,
        backend_failed: !output.status.success(),
    }
}

fn absoluteish(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

fn parse_backend_output(output: &str, default_file: &str) -> Vec<Diagnostic> {
    output
        .lines()
        .filter_map(|line| {
            parse_standard_diagnostic(line)
                .or_else(|| parse_oreslang_positioned_diagnostic(line, default_file))
        })
        .collect()
}

fn parse_standard_diagnostic(line: &str) -> Option<Diagnostic> {
    for severity in ["error", "warning", "info", "hint"] {
        let marker = format!(": {severity}:");
        let marker_index = line.rfind(&marker)?;
        let location = &line[..marker_index];
        let message = line[marker_index + marker.len()..].trim();

        let mut location_parts = location.rsplitn(3, ':');
        let column = location_parts.next()?.trim().parse::<u32>().ok()?;
        let row = location_parts.next()?.trim().parse::<u32>().ok()?;
        let path = location_parts.next()?.trim();
        if path.is_empty() || message.is_empty() {
            continue;
        }

        return Some(Diagnostic {
            path: path.replace('\\', "/"),
            line: row.max(1),
            column: column.max(1),
            end_line: row.max(1),
            end_column: column.max(1).saturating_add(1),
            severity: severity.to_owned(),
            message: message.to_owned(),
        });
    }
    None
}

fn parse_oreslang_positioned_diagnostic(line: &str, default_file: &str) -> Option<Diagnostic> {
    let marker = " error at ";
    let marker_index = line.find(marker)?;
    let prefix = &line[..marker_index];
    if !prefix.contains("Oreslang") {
        return None;
    }

    let rest = &line[marker_index + marker.len()..];
    let mut parts = rest.splitn(3, ':');
    let row = parts.next()?.trim().parse::<u32>().ok()?;
    let column = parts.next()?.trim().parse::<u32>().ok()?;
    let message = parts.next()?.trim();
    if message.is_empty() {
        return None;
    }

    Some(Diagnostic {
        path: default_file.to_owned(),
        line: row.max(1),
        column: column.max(1),
        end_line: row.max(1),
        end_column: column.max(1).saturating_add(1),
        severity: "error".into(),
        message: message.to_owned(),
    })
}

fn emit_diagnostics(format: OutputFormat, diagnostics: &[Diagnostic], ok: bool) {
    match format {
        OutputFormat::Human => {
            for diagnostic in diagnostics {
                println!(
                    "{}:{}:{}: {}: {}",
                    diagnostic.path,
                    diagnostic.line,
                    diagnostic.column,
                    diagnostic.severity,
                    diagnostic.message
                );
            }
        }
        OutputFormat::Json => {
            print!(
                "{{\"version\":{},\"ok\":{},\"diagnostics\":[",
                PROTOCOL_VERSION,
                if ok { "true" } else { "false" }
            );
            for (index, diagnostic) in diagnostics.iter().enumerate() {
                if index > 0 {
                    print!(",");
                }
                print!("{}", diagnostic_json(diagnostic));
            }
            println!("]}}");
        }
        OutputFormat::Jsonl => {
            for diagnostic in diagnostics {
                println!("{}", diagnostic_json(diagnostic));
            }
        }
    }
}

fn diagnostic_json(diagnostic: &Diagnostic) -> String {
    format!(
        "{{\"version\":{},\"path\":\"{}\",\"range\":{{\"start\":{{\"line\":{},\"column\":{}}},\"end\":{{\"line\":{},\"column\":{}}}}},\"severity\":\"{}\",\"message\":\"{}\"}}",
        PROTOCOL_VERSION,
        escape_json(&diagnostic.path),
        diagnostic.line,
        diagnostic.column,
        diagnostic.end_line,
        diagnostic.end_column,
        escape_json(&diagnostic.severity),
        escape_json(&diagnostic.message)
    )
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_compiler_diagnostic() {
        let got = parse_backend_output(
            "/tmp/demo.ores:7:13: error: expected expression",
            "/tmp/demo.ores",
        );
        assert_eq!(
            got,
            vec![Diagnostic {
                path: "/tmp/demo.ores".into(),
                line: 7,
                column: 13,
                end_line: 7,
                end_column: 14,
                severity: "error".into(),
                message: "expected expression".into(),
            }]
        );
    }

    #[test]
    fn parses_windows_drive_paths_from_the_right() {
        let got = parse_backend_output(
            r"C:\src\demo.ores:2:9: warning: suspicious value",
            "unused",
        );
        assert_eq!(got[0].path, "C:/src/demo.ores");
        assert_eq!(got[0].line, 2);
        assert_eq!(got[0].column, 9);
        assert_eq!(got[0].severity, "warning");
    }

    #[test]
    fn parses_native_oreslang_positioned_error() {
        let got = parse_backend_output(
            "Oreslang parse error at 3:5: expected module",
            "/src/demo.ores",
        );
        assert_eq!(got[0].path, "/src/demo.ores");
        assert_eq!(got[0].line, 3);
        assert_eq!(got[0].column, 5);
        assert_eq!(got[0].message, "expected module");
    }

    #[test]
    fn json_escaping_is_machine_safe() {
        assert_eq!(escape_json("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    fn public_default_never_uses_ores() {
        assert_eq!(DEFAULT_COMPILER_BACKEND, "oreslang-compiler");
        assert_ne!(DEFAULT_COMPILER_BACKEND, "ores");
    }
}
