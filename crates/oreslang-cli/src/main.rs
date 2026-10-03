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

fn check(args: CheckArgs) -> ExitCode {
    let client = CompilerClient::new(compiler_command(&args.backend));
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
}
