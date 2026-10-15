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
