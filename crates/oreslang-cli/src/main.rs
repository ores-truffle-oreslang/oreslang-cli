use clap::{Args, Parser, Subcommand, ValueEnum};
use oreslang_compiler_client::{CompilerClient, CompilerCommand};
use oreslang_protocol::{CheckReport, Diagnostic, DiagnosticSeverity, DIAGNOSTIC_PROTOCOL_VERSION};
use serde::Serialize;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "oreslang",
    version,
    about = "Oreslang developer tooling and editor frontend"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse, resolve, and type-check Oreslang without executing guest code.
    Check(CheckArgs),
    /// Run the Oreslang language server.
    Lsp(LspArgs),
    /// Show the compiler backend that the CLI will use.
    Doctor(DoctorArgs),
    /// Print the Oreslang CLI version.
    Version,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Jsonl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PermissionCheck {
    /// Compile/type-check normally and enforce external I/O permissions when an operation executes.
    Runtime,
    /// Reject statically identifiable external-I/O calls whose coarse permission is absent.
    Compile,
}

impl PermissionCheck {
    fn backend_value(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Compile => "compile",
        }
    }
}

/// Deno-style scoped permissions forwarded to the Oreslang compiler/runtime.
///
/// Scope-taking flags require '=' so a bare permission flag can mean "all"
/// without consuming the following Oreslang source path.
#[derive(Clone, Debug, Args)]
struct PermissionArgs {
    /// Choose runtime-only or compile-time-plus-runtime permission admission.
    #[arg(
        long,
        env = "ORESLANG_PERMISSION_CHECK",
        value_enum,
        default_value_t = PermissionCheck::Runtime
    )]
    permission_check: PermissionCheck,

    /// Allow every Ores-owned privileged I/O category.
    #[arg(long, env = "ORESLANG_ALLOW_ALL")]
    allow_all: bool,

    /// Allow filesystem reads; bare means all, =PATHS narrows to comma-separated roots.
    #[arg(
        long,
        env = "ORESLANG_ALLOW_READ",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "PATHS"
    )]
    allow_read: Option<String>,

    /// Deny filesystem reads; explicit denies override allows.
    #[arg(
        long,
        env = "ORESLANG_DENY_READ",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "PATHS"
    )]
    deny_read: Option<String>,

    /// Allow filesystem writes.
    #[arg(
        long,
        env = "ORESLANG_ALLOW_WRITE",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "PATHS"
    )]
    allow_write: Option<String>,

    /// Deny filesystem writes.
    #[arg(
        long,
        env = "ORESLANG_DENY_WRITE",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "PATHS"
    )]
    deny_write: Option<String>,

    /// Allow network endpoints; bare means all, =HOST[:PORT],... narrows the scope.
    #[arg(
        long,
        env = "ORESLANG_ALLOW_NET",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "HOSTS"
    )]
    allow_net: Option<String>,

    /// Deny network endpoints.
    #[arg(
        long,
        env = "ORESLANG_DENY_NET",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "HOSTS"
    )]
    deny_net: Option<String>,

    /// Allow environment-variable names.
    #[arg(
        long,
        env = "ORESLANG_ALLOW_ENV",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "NAMES"
    )]
    allow_env: Option<String>,

    /// Deny environment-variable names.
    #[arg(
        long,
        env = "ORESLANG_DENY_ENV",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "NAMES"
    )]
    deny_env: Option<String>,

    /// Allow child-process commands.
    #[arg(
        long,
        env = "ORESLANG_ALLOW_RUN",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "COMMANDS"
    )]
    allow_run: Option<String>,

    /// Deny child-process commands.
    #[arg(
        long,
        env = "ORESLANG_DENY_RUN",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "COMMANDS"
    )]
    deny_run: Option<String>,

    /// Allow system/process information keys.
    #[arg(
        long,
        env = "ORESLANG_ALLOW_SYS",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "KEYS"
    )]
    allow_sys: Option<String>,

    /// Deny system/process information keys.
    #[arg(
        long,
        env = "ORESLANG_DENY_SYS",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "KEYS"
    )]
    deny_sys: Option<String>,

    /// Allow native FFI library roots.
    #[arg(
        long,
        env = "ORESLANG_ALLOW_FFI",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "PATHS"
    )]
    allow_ffi: Option<String>,

    /// Deny native FFI library roots.
    #[arg(
        long,
        env = "ORESLANG_DENY_FFI",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "PATHS"
    )]
    deny_ffi: Option<String>,

    /// Allow runtime/hot-code import roots.
    #[arg(
        long,
        env = "ORESLANG_ALLOW_IMPORT",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "PATHS"
    )]
    allow_import: Option<String>,

    /// Deny runtime/hot-code import roots.
    #[arg(
        long,
        env = "ORESLANG_DENY_IMPORT",
        num_args = 0..=1,
        default_missing_value = "*",
        require_equals = true,
        value_name = "PATHS"
    )]
    deny_import: Option<String>,

    /// State explicitly that permission failures must never prompt.
    #[arg(long, env = "ORESLANG_NO_PROMPT")]
    no_prompt: bool,
}

impl PermissionArgs {
    fn backend_args(&self) -> Vec<OsString> {
        let mut args = vec![OsString::from(format!(
            "--permission-check={}",
            self.permission_check.backend_value()
        ))];

        if self.allow_all {
            args.push(OsString::from("--allow-all"));
        }
        push_scope(&mut args, "allow-read", self.allow_read.as_deref());
        push_scope(&mut args, "deny-read", self.deny_read.as_deref());
        push_scope(&mut args, "allow-write", self.allow_write.as_deref());
        push_scope(&mut args, "deny-write", self.deny_write.as_deref());
        push_scope(&mut args, "allow-net", self.allow_net.as_deref());
        push_scope(&mut args, "deny-net", self.deny_net.as_deref());
        push_scope(&mut args, "allow-env", self.allow_env.as_deref());
        push_scope(&mut args, "deny-env", self.deny_env.as_deref());
        push_scope(&mut args, "allow-run", self.allow_run.as_deref());
        push_scope(&mut args, "deny-run", self.deny_run.as_deref());
        push_scope(&mut args, "allow-sys", self.allow_sys.as_deref());
        push_scope(&mut args, "deny-sys", self.deny_sys.as_deref());
        push_scope(&mut args, "allow-ffi", self.allow_ffi.as_deref());
        push_scope(&mut args, "deny-ffi", self.deny_ffi.as_deref());
        push_scope(&mut args, "allow-import", self.allow_import.as_deref());
        push_scope(&mut args, "deny-import", self.deny_import.as_deref());

        if self.no_prompt {
            args.push(OsString::from("--no-prompt"));
        }
        args
    }
}

fn push_scope(args: &mut Vec<OsString>, flag: &str, value: Option<&str>) {
    let Some(value) = value else { return };
    if value == "*" {
        args.push(OsString::from(format!("--{flag}")));
    } else {
        args.push(OsString::from(format!("--{flag}={value}")));
    }
}

#[derive(Debug, Args)]
struct BackendArgs {
    /// Override the internal compiler backend executable.
    #[arg(long, value_name = "PROGRAM")]
    compiler: Option<OsString>,

    /// Prefix argument passed to the internal compiler backend before --check.
    #[arg(long = "compiler-arg", value_name = "ARG", action = clap::ArgAction::Append)]
    compiler_args: Vec<OsString>,
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// Oreslang source files to check.
    #[arg(required = true, value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Diagnostic output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    #[command(flatten)]
    permissions: PermissionArgs,

    #[command(flatten)]
    backend: BackendArgs,
}

#[derive(Debug, Args)]
struct LspArgs {
    /// Serve Language Server Protocol messages over stdin/stdout.
    #[arg(long)]
    stdio: bool,

    #[command(flatten)]
    permissions: PermissionArgs,

    #[command(flatten)]
    backend: BackendArgs,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[command(flatten)]
    backend: BackendArgs,
}

#[derive(Serialize)]
struct JsonLineDiagnostic<'a> {
    version: u32,
    diagnostic: &'a Diagnostic,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Check(args) => check(args),
        Command::Lsp(args) => lsp(args),
        Command::Doctor(args) => doctor(args),
        Command::Version => version(),
    }
}

fn compiler_command(args: &BackendArgs) -> CompilerCommand {
    let mut command = args
        .compiler
        .clone()
        .map(CompilerCommand::from_program)
        .unwrap_or_else(CompilerCommand::discover);

    if !args.compiler_args.is_empty() {
        command = command.with_prefix_args(args.compiler_args.clone());
    }
    command
}

fn permissioned_compiler_command(
    backend: &BackendArgs,
    permissions: &PermissionArgs,
) -> CompilerCommand {
    compiler_command(backend).with_prefix_args(permissions.backend_args())
}

fn check(args: CheckArgs) -> ExitCode {
    let client = CompilerClient::new(permissioned_compiler_command(
        &args.backend,
        &args.permissions,
    ));
    let mut diagnostics = Vec::new();
    let mut failed = false;

    for file in &args.files {
        match client.check_file(file) {
            Ok(result) => {
                if !result.success {
                    failed = true;
                }
                if result
                    .diagnostics
                    .iter()
                    .any(|item| item.severity == DiagnosticSeverity::Error)
                {
                    failed = true;
                }
                diagnostics.extend(result.diagnostics);
            }
            Err(error) => {
                failed = true;
                diagnostics.push(Diagnostic::error(file.clone(), 1, 1, error.to_string()));
            }
        }
    }

    emit(&diagnostics, args.format);

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn lsp(args: LspArgs) -> ExitCode {
    if !args.stdio {
        eprintln!("oreslang lsp currently requires --stdio");
        return ExitCode::from(2);
    }

    let command = permissioned_compiler_command(&args.backend, &args.permissions);
    match oreslang_lsp::run_stdio(command) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code.clamp(0, u8::MAX as i32) as u8),
        Err(error) => {
            eprintln!("oreslang lsp: {error}");
            ExitCode::FAILURE
        }
    }
}

fn version() -> ExitCode {
    println!("oreslang {}", env!("CARGO_PKG_VERSION"));
    ExitCode::SUCCESS
}

fn doctor(args: DoctorArgs) -> ExitCode {
    let command = compiler_command(&args.backend);
    println!("oreslang {}", env!("CARGO_PKG_VERSION"));
    println!("diagnostic protocol: v{DIAGNOSTIC_PROTOCOL_VERSION}");
    println!("compiler backend: {}", command.display());
    println!("public editor command: oreslang check <file.ores>");
    println!("language server: oreslang lsp --stdio");
    println!("permissions: Deno-style --allow-*/--deny-*; runtime enforcement is always active");
    ExitCode::SUCCESS
}

fn emit(diagnostics: &[Diagnostic], format: OutputFormat) {
    match format {
        OutputFormat::Human => {
            for item in diagnostics {
                let start = &item.range.start;
                match &item.code {
                    Some(code) => println!(
                        "{}:{}:{}: {}[{}]: {}",
                        item.path.display(),
                        start.line,
                        start.column,
                        item.severity,
                        code,
                        item.message
                    ),
                    None => println!(
                        "{}:{}:{}: {}: {}",
                        item.path.display(),
                        start.line,
                        start.column,
                        item.severity,
                        item.message
                    ),
                }
            }
        }
        OutputFormat::Json => {
            let report = CheckReport::new(diagnostics.to_vec());
            println!(
                "{}",
                serde_json::to_string(&report).expect("diagnostic report must serialize")
            );
        }
        OutputFormat::Jsonl => {
            for diagnostic in diagnostics {
                println!(
                    "{}",
                    serde_json::to_string(&JsonLineDiagnostic {
                        version: DIAGNOSTIC_PROTOCOL_VERSION,
                        diagnostic,
                    })
                    .expect("diagnostic must serialize")
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_compiler_override_wins() {
        let args = BackendArgs {
            compiler: Some(OsString::from("custom-compiler")),
            compiler_args: vec![OsString::from("--internal")],
        };

        let command = compiler_command(&args);
        assert_eq!(command.program, OsString::from("custom-compiler"));
        assert_eq!(command.prefix_args, vec![OsString::from("--internal")]);
    }

    #[test]
    fn bare_scope_does_not_consume_source_file() {
        let cli = Cli::try_parse_from([
            "oreslang",
            "check",
            "--allow-read",
            "demo.ores",
        ])
        .expect("permission CLI should parse");

        let Command::Check(args) = cli.command else {
            panic!("expected check command");
        };
        assert_eq!(args.permissions.allow_read.as_deref(), Some("*"));
        assert_eq!(args.files, vec![PathBuf::from("demo.ores")]);
    }

    #[test]
    fn scoped_permissions_forward_to_compiler_backend() {
        let cli = Cli::try_parse_from([
            "oreslang",
            "check",
            "--permission-check=compile",
            "--allow-read=./data,/tmp/shared",
            "--deny-read=./data/secrets",
            "--allow-net=api.example.com:443",
            "demo.ores",
        ])
        .expect("permission CLI should parse");

        let Command::Check(args) = cli.command else {
            panic!("expected check command");
        };
        let forwarded = args.permissions.backend_args();
        let rendered: Vec<_> = forwarded
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();

        assert!(rendered.contains(&"--permission-check=compile".to_owned()));
        assert!(rendered.contains(&"--allow-read=./data,/tmp/shared".to_owned()));
        assert!(rendered.contains(&"--deny-read=./data/secrets".to_owned()));
        assert!(rendered.contains(&"--allow-net=api.example.com:443".to_owned()));
    }
}
