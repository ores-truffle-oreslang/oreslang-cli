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
    assert!(
        stderr.contains("failed to start AttoLang test executable"),
        "{stderr}"
    );
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
    assert!(
        stderr.contains("failed to start AttoLang test executable"),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_subcommand_forwards_all_flags_and_propagates_runner_exit() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile_dir("legacy-forward");
    let script = dir.join("runner.sh");
    fs::write(&script, "#!/bin/sh\nprintf 'ARG:%s\\n' \"$@\"\nexit 7\n")
        .expect("create fixture runner");
    let mut permissions = fs::metadata(&script).expect("fixture exists").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).expect("mark runner executable");

    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .args([
            "test",
            "--race",
            "fixture.ores",
            "--runs",
            "3",
            "--seed",
            "42",
        ])
        .env("ORESLANG_TEST_CLI", &script)
        .output()
        .expect("oreslang executable exists");
    fs::remove_dir_all(&dir).expect("remove private legacy fixture dir");

    assert_eq!(output.status.code(), Some(7));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout,
        "ARG:--race\nARG:fixture.ores\nARG:--runs\nARG:3\nARG:--seed\nARG:42\n"
    );
}

#[test]
fn canonical_atto_dispatch_fails_closed_when_explicit_runner_missing() {
    let output = Command::new(env!("CARGO_BIN_EXE_atto"))
        .args(["test", "--race"])
        .env("ATTO_TEST_CLI", "/deliberately-unavailable-atto-test")
        .env("ORESLANG_TEST_CLI", "/legacy-override-must-not-win")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("AttoLang test executable"));
}

#[cfg(unix)]
#[test]
fn atto_test_forwards_fuzz_args_to_canonical_runner_and_preserves_exit_code() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile_dir("atto-forward");
    let runner = dir.join("test-runner");
    fs::write(&runner, "#!/bin/sh\nprintf 'ARG:%s\\n' \"$@\"\nexit 7\n").unwrap();
    let mut perms = fs::metadata(&runner).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&runner, perms).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_atto"))
        .args(["test", "--fuzz", "--cases", "5", "--seed", "42"])
        .env("ATTO_TEST_CLI", &runner)
        .env("ORESLANG_TEST_CLI", "/legacy-must-not-win")
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(dir);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "ARG:--fuzz\nARG:--cases\nARG:5\nARG:--seed\nARG:42\n"
    );
}

#[cfg(unix)]
#[test]
fn test_runner_killed_by_signal_is_inconclusive_not_a_finding() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile_dir("signal");
    let script = dir.join("runner.sh");
    fs::write(&script, "#!/bin/sh\nkill -KILL $$\n").expect("create fixture runner");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("chmod runner");
    let output = Command::new(env!("CARGO_BIN_EXE_atto"))
        .args(["test", "--fuzz"])
        .env("ATTO_TEST_CLI", &script)
        .output()
        .expect("atto executable exists");
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[cfg(unix)]
#[test]
fn test_runner_exit_1_is_a_finding_but_term_and_exit_2_are_inconclusive() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile_dir("exit-classes");
    let script = dir.join("runner.sh");
    for (source, expected) in [
        ("#!/bin/sh\nexit 1\n", 1),
        ("#!/bin/sh\nexit 2\n", 2),
        ("#!/bin/sh\nkill -TERM $$\n", 2),
        ("#!/bin/sh\nexit 7\n", 7),
    ] {
        fs::write(&script, source).expect("write test runner");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("chmod test runner");
        let output = Command::new(env!("CARGO_BIN_EXE_atto"))
            .args(["test", "--fuzz"])
            .env("ATTO_TEST_CLI", &script)
            .output()
            .expect("atto executable exists");
        assert_eq!(output.status.code(), Some(expected), "{output:?}");
    }
    fs::remove_dir_all(&dir).expect("clean isolated test fixtures");
}

#[cfg(unix)]
fn tempfile_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("atto-test-dispatch-{tag}-{}", std::process::id()));
    // Never follow or reuse a predictable pre-existing path: the old
    // create_dir_all accepted an attacker-created symlink under /tmp.
    std::fs::create_dir(&dir).expect("exclusive fixture dir creation");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .expect("keep runner fixture directory private");
    dir
}
