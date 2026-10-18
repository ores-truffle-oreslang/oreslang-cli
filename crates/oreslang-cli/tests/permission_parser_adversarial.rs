//! CLI permission grants may be set only through the typed flags-2-env path.
use std::process::Command;

#[test]
fn compiler_arg_cannot_smuggle_permission_authority_or_response_files() {
    for forbidden in [
        "--allow-all", "--allow-read=/", "--allow-net=*", "--deny-env=PATH",
        "--permission-check=runtime", "--no-prompt", "@permission-flags.rsp", "--",
        "--ores-isolate=off",
    ] {
        let result=Command::new(env!("CARGO_BIN_EXE_oreslang"))
            .args(["check", "main.ores", &format!("--compiler-arg={forbidden}")])
            .output().expect("launch CLI parser");
        assert!(!result.status.success(), "bypass accepted: {forbidden}");
        let message=String::from_utf8_lossy(&result.stderr);
        assert!(message.contains("policy flags must use first-class CLI options"),
                "unexpected error for {forbidden}: {message}");
    }
}
