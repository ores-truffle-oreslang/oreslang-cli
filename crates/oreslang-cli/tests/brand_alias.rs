use std::process::Command;

#[test]
fn both_binary_names_are_built_from_one_parser_and_expose_matching_subcommands() {
    let atto = Command::new(env!("CARGO_BIN_EXE_atto")).arg("--help").output().unwrap();
    let legacy = Command::new(env!("CARGO_BIN_EXE_oreslang")).arg("--help").output().unwrap();
    assert!(atto.status.success() && legacy.status.success());
    let new_help = String::from_utf8_lossy(&atto.stdout);
    let old_help = String::from_utf8_lossy(&legacy.stdout);
    assert!(new_help.contains("Usage: atto "), "{new_help}");
    assert!(old_help.contains("Usage: oreslang "), "{old_help}");
    for sub in ["check", "run", "test", "lsp", "doctor", "version"] {
        assert!(new_help.contains(sub), "{sub}: {new_help}");
        assert!(old_help.contains(sub), "{sub}: {old_help}");
    }
    let atto_v = Command::new(env!("CARGO_BIN_EXE_atto")).arg("--version").output().unwrap();
    let old_v = Command::new(env!("CARGO_BIN_EXE_oreslang")).arg("--version").output().unwrap();
    assert!(atto_v.status.success() && old_v.status.success());
    assert_eq!(atto_v.stdout, old_v.stdout, "version contract changed by alias");
}

#[cfg(unix)]
#[test]
fn atto_and_oreslang_pass_atto_and_ores_paths_to_one_compiler_without_permission_escalation() {
    use std::{fs, os::unix::fs::PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!("atto-alias-{}-{}", std::process::id(), NONCE.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir(&path).unwrap();
    let compiler = path.join("backend.sh");
    fs::write(&compiler, "#!/bin/sh\nprintf 'ARG:%s\\n' \"$@\"\nexit 0\n").unwrap();
    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o700)).unwrap();
    let mut results = Vec::new();
    for binary in [env!("CARGO_BIN_EXE_atto"), env!("CARGO_BIN_EXE_oreslang")] {
        for name in ["test.atto", "test.ores"] {
            let file = path.join(name);
            fs::write(&file, "fnc main():int{return 42;}").unwrap();
            let output = Command::new(binary)
                .arg("run").arg(&file)
                .arg("--compiler").arg(&compiler)
                .env("ORESLANG_ALLOW_ALL", "true")
                .env("ORESLANG_ALLOW_NET", "*")
                .output().unwrap();
            assert!(output.status.success(), "{:?}", output);
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(text.contains("ARG:--permission-check=runtime"), "{text}");
            assert!(!text.contains("ARG:--allow-all"), "{text}");
            assert!(!text.contains("ARG:--allow-net=*"), "{text}");
            assert!(text.contains(name), "{text}");
            results.push((name.to_owned(), text.to_string(), output.status.code()));
        }
    }
    assert_eq!(results[0], results[2], "atto and oreslang diverged for .atto");
    assert_eq!(results[1], results[3], "atto and oreslang diverged for .ores");
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn both_aliases_reject_unknown_permissions_and_fail_closed() {
    for binary in [env!("CARGO_BIN_EXE_atto"), env!("CARGO_BIN_EXE_oreslang")] {
        let output = Command::new(binary)
            .args(["run", "--allow-everything", "missing.atto"]).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}
