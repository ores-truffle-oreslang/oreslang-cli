use oreslang_protocol::{Diagnostic, DiagnosticRange, DiagnosticSeverity};
use regex::Regex;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const DEFAULT_COMPILER_PROGRAM: &str = "oreslang-compiler";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilerCommand {
    pub program: OsString,
    pub prefix_args: Vec<OsString>,
}

impl CompilerCommand {
    pub fn discover() -> Self {
        if let Some(jar) = env::var_os("ORESLANG_COMPILER_JAR") {
            return Self {
                program: OsString::from("java"),
                prefix_args: vec![OsString::from("-jar"), jar],
            };
        }

        Self {
            program: env::var_os("ORESLANG_COMPILER")
                .unwrap_or_else(|| OsString::from(DEFAULT_COMPILER_PROGRAM)),
            prefix_args: Vec::new(),
        }
    }

    pub fn from_program(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            prefix_args: Vec::new(),
        }
    }

    pub fn with_prefix_args(mut self, args: impl IntoIterator<Item = OsString>) -> Self {
        self.prefix_args.extend(args);
        self
    }

    pub fn display(&self) -> String {
        let mut parts = vec![self.program.to_string_lossy().into_owned()];
        parts.extend(
            self.prefix_args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned()),
        );
        parts.join(" ")
    }
}

#[derive(Debug)]
pub enum CompilerClientError {
    Spawn { command: String, source: io::Error },
    InvalidPath(PathBuf),
}

impl fmt::Display for CompilerClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn { command, source } => {
                write!(
                    formatter,
                    "failed to start Oreslang compiler backend '{command}': {source}"
                )
            }
            Self::InvalidPath(path) => write!(
                formatter,
                "Oreslang check target has no usable parent directory: {}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for CompilerClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn { source, .. } => Some(source),
            Self::InvalidPath(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub diagnostics: Vec<Diagnostic>,
    pub raw_output: String,
}

#[derive(Clone, Debug)]
pub struct CompilerClient {
    command: CompilerCommand,
}

impl CompilerClient {
    pub fn new(command: CompilerCommand) -> Self {
        Self { command }
    }

    pub fn command(&self) -> &CompilerCommand {
        &self.command
    }

    pub fn check_file(&self, path: &Path) -> Result<CheckResult, CompilerClientError> {
        let absolute = absolute_path(path)?;
        let cwd = absolute
            .parent()
            .ok_or_else(|| CompilerClientError::InvalidPath(absolute.clone()))?;

        let mut command = Command::new(&self.command.program);
        command
            .args(&self.command.prefix_args)
            .arg("--check")
            .arg(&absolute)
            .current_dir(cwd);

        let output = command
            .output()
            .map_err(|source| CompilerClientError::Spawn {
                command: self.command.display(),
                source,
            })?;

        let raw_output = join_output(&output.stdout, &output.stderr);
        let mut diagnostics = parse_compiler_output(&raw_output, &absolute);

        if !output.status.success() && diagnostics.is_empty() {
            let message = raw_output
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("compiler backend failed without a diagnostic")
                .trim();
            diagnostics.push(Diagnostic::error(absolute.clone(), 1, 1, message));
        }

        Ok(CheckResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            diagnostics,
            raw_output,
        })
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, CompilerClientError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    env::current_dir()
        .map(|cwd| cwd.join(path))
        .map_err(|source| CompilerClientError::Spawn {
            command: "resolve current directory".to_owned(),
            source,
        })
}

fn join_output(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
        (false, false) => format!("{stdout}\n{stderr}"),
        (false, true) => stdout.into_owned(),
        (true, false) => stderr.into_owned(),
        (true, true) => String::new(),
    }
}

fn standard_diagnostic_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"^(?P<path>.+):(?P<line>\d+):(?P<column>\d+):\s*(?P<severity>error|warning|info|hint):\s*(?P<message>.+)$",
        )
        .expect("valid standard diagnostic regex")
    })
}

fn native_diagnostic_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"Oreslang\s+(?:lexer|parse)\s+error\s+at\s+(?P<line>\d+):(?P<column>\d+):\s*(?P<message>.+)$",
        )
        .expect("valid native diagnostic regex")
    })
}

pub fn parse_compiler_output(output: &str, default_path: &Path) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if let Some(captures) = standard_diagnostic_pattern().captures(line) {
            let severity = match &captures["severity"] {
                "warning" => DiagnosticSeverity::Warning,
                "info" => DiagnosticSeverity::Info,
                "hint" => DiagnosticSeverity::Hint,
                _ => DiagnosticSeverity::Error,
            };
            let line_number = captures["line"].parse::<u32>().unwrap_or(1).max(1);
            let column = captures["column"].parse::<u32>().unwrap_or(1).max(1);

            diagnostics.push(Diagnostic {
                path: PathBuf::from(&captures["path"]),
                range: DiagnosticRange::point(line_number, column),
                severity,
                code: None,
                source: "oreslang".to_owned(),
                message: captures["message"].trim().to_owned(),
            });
            continue;
        }

        if let Some(captures) = native_diagnostic_pattern().captures(line) {
            let line_number = captures["line"].parse::<u32>().unwrap_or(1).max(1);
            let column = captures["column"].parse::<u32>().unwrap_or(1).max(1);
            diagnostics.push(Diagnostic::error(
                default_path.to_path_buf(),
                line_number,
                column,
                captures["message"].trim(),
            ));
        }
    }

    diagnostics
}

pub fn os_string(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_os_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_diagnostic_with_colons_in_path() {
        let diagnostics = parse_compiler_output(
            r"C:\src\demo.ores:7:13: error: expected expression",
            Path::new("demo.ores"),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].path, PathBuf::from(r"C:\src\demo.ores"));
        assert_eq!(diagnostics[0].range.start.line, 7);
        assert_eq!(diagnostics[0].range.start.column, 13);
        assert_eq!(diagnostics[0].message, "expected expression");
    }

    #[test]
    fn parses_native_positioned_diagnostic() {
        let diagnostics = parse_compiler_output(
            "java.lang.IllegalArgumentException: Oreslang parse error at 2:9: expected expression",
            Path::new("/tmp/demo.ores"),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].path, PathBuf::from("/tmp/demo.ores"));
        assert_eq!(diagnostics[0].range.start.line, 2);
        assert_eq!(diagnostics[0].range.start.column, 9);
    }

    #[test]
    fn ignores_unrelated_output() {
        assert!(parse_compiler_output("compiler cache warm", Path::new("x.ores")).is_empty());
    }

    #[test]
    fn default_backend_never_names_unrelated_ores_cli() {
        assert_eq!(DEFAULT_COMPILER_PROGRAM, "oreslang-compiler");
        assert_ne!(DEFAULT_COMPILER_PROGRAM, "ores");
    }
}
