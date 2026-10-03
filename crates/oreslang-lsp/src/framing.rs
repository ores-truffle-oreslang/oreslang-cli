use serde_json::Value;
use std::io::{self, BufRead, Write};

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

pub fn read_message<R: BufRead>(reader: &mut R) -> io::Result<Option<Value>> {
    let mut content_length = None;
    let mut saw_header = false;

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            if saw_header {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF while reading LSP headers",
                ));
            }
            return Ok(None);
        }

        saw_header = true;
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }

        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("Content-Length") {
                let parsed = value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length")
                })?;
                if parsed > MAX_MESSAGE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LSP message exceeds 16 MiB limit",
                    ));
                }
                content_length = Some(parsed);
            }
        }
    }

    let content_length = content_length.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length header")
    })?;

    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn write_message<W: Write>(writer: &mut W, value: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufReader, Cursor};

    #[test]
    fn reads_lsp_frame() {
        let body = br#"{"jsonrpc":"2.0","method":"initialized"}"#;
        let wire = format!(
            "Content-Length: {}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let mut reader = BufReader::new(Cursor::new(wire.into_bytes()));
        let value = read_message(&mut reader).expect("read").expect("message");
        assert_eq!(value["method"], "initialized");
    }

    #[test]
    fn writes_lsp_frame() {
        let mut out = Vec::new();
        write_message(&mut out, &json!({"jsonrpc":"2.0","id":1,"result":null})).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.starts_with("Content-Length: "));
        assert!(text.contains("\r\n\r\n{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":null}"));
    }
}
