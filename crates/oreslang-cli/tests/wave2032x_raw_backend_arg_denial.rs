//! CLI raw backend argument provenance through both real binary aliases.
//! The Unix positive control uses a fake shell backend; no guest compilation.
use std::process::Command;

#[test]
fn both_aliases_reject_policy_flags_smuggled_through_compiler_arg() {
    for bin in [env!("CARGO_BIN_EXE_atto"), env!("CARGO_BIN_EXE_oreslang")] {
        for forbidden in [
            "--allow-net=*",
            "--deny-read=/private",
            "--permission-check=compile",
            "--no-prompt",
            "--hard-rt",
            "--strict-aot",
            "--freestanding",
            "@response-file",
            "--",
        ] {
            let output = Command::new(bin)
                .args(["check", "not-executed.atto"])
                .arg(format!("--compiler-arg={forbidden}"))
                .output()
                .expect("binary exists");
            assert_eq!(output.status.code(), Some(2),
                "alias {bin}, raw {forbidden}: {output:?}");
            assert!(output.stdout.is_empty(),
                "parser denial must not execute backend: {forbidden}");
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("first-class CLI options"),
                "expected fail-closed provenance message: {forbidden}: {output:?}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn both_aliases_preserve_nonpolicy_literal_args_as_single_argv_values() {
    use std::{fs, os::unix::fs::PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let folder = std::env::temp_dir().join(format!(
        "atto-wave2032x-{}-{}", std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&folder).unwrap();
    let backend = folder.join("compiler.sh");
    fs::write(&backend,
        "#!/bin/sh\nprintf 'RECEIVED:%s\\n' \"$@\"\nexit 0\n").unwrap();
    fs::set_permissions(&backend, fs::Permissions::from_mode(0o700)).unwrap();
    let source = folder.join("quoted name.atto");
    fs::write(&source, "fnc main(): int { return 7; }\n").unwrap();
    for bin in [env!("CARGO_BIN_EXE_atto"), env!("CARGO_BIN_EXE_oreslang")] {
        let output = Command::new(bin)
            .arg("run")
            .arg(&source)
            .arg("--compiler")
            .arg(&backend)
            .arg("--compiler-arg=--X-test-only")
            .arg("--compiler-arg=value with spaces")
            .output()
            .unwrap();
        assert!(output.status.success(), "{bin}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("RECEIVED:--X-test-only\n"), "{stdout}");
        assert!(stdout.contains("RECEIVED:value with spaces\n"), "{stdout}");
        assert!(stdout.contains("RECEIVED:--permission-check=runtime\n"), "{stdout}");
        assert!(!stdout.contains("RECEIVED:--allow-all"), "{stdout}");
    }
    fs::remove_dir_all(folder).unwrap();
}
