use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

pub const DIAGNOSTIC_PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
    Hint,
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Hint => "hint",
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Position {
    /// One-based line number for CLI/editor interoperability.
    pub line: u32,
    /// One-based column number for CLI/editor interoperability.
    pub column: u32,
}

impl Position {
    pub const fn new(line: u32, column: u32) -> Self {
        Self {
            line: if line == 0 { 1 } else { line },
            column: if column == 0 { 1 } else { column },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiagnosticRange {
    pub start: Position,
    pub end: Position,
}

impl DiagnosticRange {
    pub fn point(line: u32, column: u32) -> Self {
        let start = Position::new(line, column);
        let end = Position::new(start.line, start.column.saturating_add(1));
        Self { start, end }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Diagnostic {
    pub path: PathBuf,
    pub range: DiagnosticRange,
    pub severity: DiagnosticSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub source: String,
    pub message: String,
}

impl Diagnostic {
    pub fn error(path: PathBuf, line: u32, column: u32, message: impl Into<String>) -> Self {
        Self {
            path,
            range: DiagnosticRange::point(line, column),
            severity: DiagnosticSeverity::Error,
            code: None,
            source: "oreslang".to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckReport {
    pub version: u32,
    pub diagnostics: Vec<Diagnostic>,
}

impl CheckReport {
    pub fn new(diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            version: DIAGNOSTIC_PROTOCOL_VERSION,
            diagnostics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_round_trip_is_stable() {
        let report = CheckReport::new(vec![Diagnostic::error(
            PathBuf::from("demo.ores"),
            7,
            13,
            "expected expression",
        )]);

        let json = serde_json::to_string(&report).expect("serialize");
        let decoded: CheckReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, decoded);
    }
}
