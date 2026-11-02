#[test]
fn release_archives_contain_both_cli_executables_and_pinned_actions() {
    let yaml = include_str!("../../../.github/workflows/release.yml");
    assert!(yaml.contains("cargo build --release --locked --bins"));
    assert!(yaml.contains("release/atto\" dist/"));
    assert!(yaml.contains("release/atto.exe\" \"dist/atto.exe\""));
    assert!(yaml.contains("tar -C dist -czf") && yaml.contains(" atto"));
    assert!(yaml.contains("Compress-Archive -Path \"dist/*.exe\""));
    assert!(!yaml.contains("actions/checkout@v4"));
    assert!(!yaml.contains("dtolnay/rust-toolchain@stable"));
    assert!(!yaml.contains("actions/upload-artifact@v4"));
    assert!(yaml.contains("oreslang-linux-x86_64.tar.gz"));
    assert!(yaml.contains("oreslang-windows-x86_64.zip"));
}

#[test]
fn ci_smokes_both_real_cargo_binaries() {
    let yaml = include_str!("../../../.github/workflows/ci.yml");
    for cmd in [
        "cargo run --locked --bin atto -- version",
        "cargo run --locked --bin atto -- doctor",
        "cargo run --locked --bin oreslang -- version",
        "cargo run --locked --bin oreslang -- doctor",
    ] {
        assert!(yaml.contains(cmd), "missing CI command: {cmd}");
    }
}
