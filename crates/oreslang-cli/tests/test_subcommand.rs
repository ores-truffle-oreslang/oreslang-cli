use std::process::Command;

#[test]
fn test_race_subcommand_dispatches_to_external_runner_without_fake_success() {
    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .args(["test", "--race", "suite.ores"])
        .env(
            "ORESLANG_TEST_CLI",
            "/an-intentionally-nonexistent-oreslang-test",
        )
        .output()
        .expect("oreslang executable exists");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to start oreslang-test"), "{stderr}");
}

#[test]
fn test_fuzz_subcommand_dispatches_to_external_runner_without_fake_success() {
    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .args([
            "test",
            "--fuzz",
            "suite.ores",
            "--runs",
            "2",
            "--seed",
            "42",
        ])
        .env(
            "ORESLANG_TEST_CLI",
            "/an-intentionally-nonexistent-oreslang-test",
        )
        .output()
        .expect("oreslang executable exists");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to start oreslang-test"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn test_subcommand_forwards_all_flags_and_propagates_runner_exit() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let script = std::env::temp_dir().join(format!(
        "oreslang-test-dispatch-{}.sh",
        std::process::id()
    ));
    fs::write(&script, "#!/bin/sh\nprintf 'ARG:%s\\n' \"$@\"\nexit 7\n")
        .expect("create fixture runner");
    let mut permissions = fs::metadata(&script)
        .expect("fixture exists")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).expect("mark runner executable");

    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .args([
            "test", "--race", "fixture.ores", "--runs", "3", "--seed", "42",
        ])
        .env("ORESLANG_TEST_CLI", &script)
        .output()
        .expect("oreslang executable exists");
    let _ = fs::remove_file(&script);

    assert_eq!(output.status.code(), Some(7));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout,
        "ARG:--race\nARG:fixture.ores\nARG:--runs\nARG:3\nARG:--seed\nARG:42\n"
    );
}
