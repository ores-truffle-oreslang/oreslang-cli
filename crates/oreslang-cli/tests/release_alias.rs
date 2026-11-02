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

#[test]
fn release_contract_distinguishes_cli_only_from_native_bundles_and_forbids_overwrite() {
    let docs = include_str!("../../../docs/DESKTOP_RELEASE.md");
    let release = include_str!("../../../.github/workflows/release.yml");
    let formula = include_str!("../../../packaging/homebrew/generate-formula.sh");
    assert!(docs.contains("three executables"));
    assert!(docs.contains("CLI-only archives"));
    assert!(docs.contains("not a native compiler release"));
    assert!(docs.contains("MOCK backend"));
    for archive in [
        "oreslang-compiler-macos-arm64.tar.gz",
        "oreslang-compiler-macos-x86_64.tar.gz",
    ] {
        assert!(
            formula.contains(archive),
            "missing compiler bundle: {archive}"
        );
        assert!(
            !release.contains(archive),
            "public CLI-only workflow must not masquerade as compiler bundle: {archive}"
        );
    }
    assert!(formula.contains(r#"bin.install "atto", "oreslang", "oreslang-compiler""#));
    assert!(release.contains("gh release upload"));
    assert!(
        !release.contains("--clobber"),
        "published release assets must not be overwritten by reruns"
    );
}

#[test]
fn release_upload_treats_tag_and_archive_as_data_not_shell_source() {
    let yaml = include_str!("../../../.github/workflows/release.yml");
    assert!(yaml.contains("RELEASE_TAG: ${{ github.ref_name }}"));
    assert!(yaml.contains("RELEASE_ARCHIVE: ${{ matrix.archive }}"));
    assert!(yaml.contains("run: gh release upload \"$RELEASE_TAG\" \"$RELEASE_ARCHIVE\""));
    assert!(!yaml.contains("run: gh release upload \"${{"));
    assert!(!yaml.contains("--clobber"));
}
