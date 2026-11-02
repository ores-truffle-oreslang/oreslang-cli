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
    assert!(yaml.contains(
        "gh release upload \"$RELEASE_TAG\" \"dist/$archive\" --repo \"$GITHUB_REPOSITORY\""
    ));
    assert!(yaml.contains("gh run download \"$GITHUB_RUN_ID\" --repo \"$GITHUB_REPOSITORY\""));
    assert!(!yaml.contains("run: gh release upload \"${{"));
    assert!(!yaml.contains("--clobber"));
}

#[test]
fn release_compilation_has_no_write_token_and_publication_has_no_checkout() {
    // Windows checkouts may normalize text to CRLF; inspect the same logical YAML.
    let yaml = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let (build, publish) = yaml
        .split_once("\n  publish:\n")
        .expect("release must separate build and publish jobs");
    assert!(build.contains("permissions:\n  contents: read"));
    assert!(!build.contains("contents: write"));
    assert!(!build.contains("GH_TOKEN:"));
    assert!(build.contains("cargo test --workspace --locked"));
    assert!(build.contains("actions/upload-artifact@"));
    assert!(publish.contains("needs: build"));
    assert!(publish.contains("actions: read"));
    assert!(publish.contains("contents: write"));
    assert!(publish.contains("GH_TOKEN: ${{ github.token }}"));
    assert!(!publish.contains("actions/checkout@"));
    assert!(!publish.contains("cargo "));
    assert!(publish.contains("set -euo pipefail"));
    for archive in [
        "oreslang-linux-x86_64.tar.gz",
        "oreslang-macos-x86_64.tar.gz",
        "oreslang-macos-aarch64.tar.gz",
        "oreslang-windows-x86_64.zip",
    ] {
        assert!(publish.contains(archive), "missing artifact: {archive}");
    }
}

#[test]
fn release_macos_runners_match_archive_architectures_and_are_not_retired() {
    let yaml = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    assert!(yaml.contains("os: macos-15-intel\n            target: x86_64-apple-darwin"));
    assert!(yaml.contains("os: macos-15\n            target: aarch64-apple-darwin"));
    for retired in ["macos-13", "macos-13-large", "macos-13-xlarge"] {
        assert!(
            !yaml.contains(&format!("os: {retired}\n")),
            "retired macOS runner: {retired}"
        );
    }
}

#[test]
fn release_requires_protected_main_and_tag_ancestry_before_publication() {
    let yaml = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let (_, publish) = yaml.split_once("\n  publish:\n").expect("publish job");
    for required in [
        "if [ \"$GITHUB_REF_TYPE\" != \"tag\" ]; then",
        "gh api \"repos/$GITHUB_REPOSITORY/branches/main\" --jq '.protected'",
        "if [ \"$protected\" != \"true\" ]; then",
        "gh api \"repos/$GITHUB_REPOSITORY/compare/$GITHUB_SHA...main\" --jq '.status'",
        "ahead|identical)",
    ] {
        assert!(
            publish.contains(required),
            "missing release governance gate: {required}"
        );
    }
    let protection = publish.find("protected=").unwrap();
    let ancestry = publish.find("ancestry=").unwrap();
    let create = publish.find("gh release create").unwrap();
    assert!(protection < ancestry && ancestry < create);
}

#[test]
fn release_downloads_and_validates_every_archive_before_draft_publication() {
    let yaml = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let (_, publish) = yaml.split_once("\n  publish:\n").expect("publish job");
    for required in [
        "gh run download \"$GITHUB_RUN_ID\" --repo \"$GITHUB_REPOSITORY\"",
        "test -s \"dist/$archive\"",
        "tar -tzf \"dist/$archive\"",
        "unzip -Z -1 dist/oreslang-windows-x86_64.zip",
        "gh release view \"$RELEASE_TAG\"",
        "gh release create \"$RELEASE_TAG\"",
        "--verify-tag --draft",
        "gh release upload \"$RELEASE_TAG\" \"dist/$archive\"",
        "gh release edit \"$RELEASE_TAG\"",
        "--draft=false",
    ] {
        assert!(
            publish.contains(required),
            "missing immutable publication gate: {required}"
        );
    }
    let download = publish.find("gh run download").unwrap();
    let validation = publish.find("unzip -Z -1").unwrap();
    let create = publish.find("gh release create").unwrap();
    let upload = publish.find("gh release upload").unwrap();
    let publish_release = publish.find("gh release edit").unwrap();
    assert!(
        download < validation && validation < create && create < upload && upload < publish_release
    );
}

#[test]
fn release_tag_must_still_resolve_to_the_exact_workflow_commit() {
    let yaml = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let (_, publish) = yaml.split_once("\n  publish:\n").expect("publish job");
    assert!(
        publish.contains("gh api \"repos/$GITHUB_REPOSITORY/commits/$RELEASE_TAG\" --jq '.sha'")
    );
    assert!(publish.contains("if [ \"$resolved_commit\" != \"$GITHUB_SHA\" ]; then"));
    assert!(publish.contains("release tag no longer resolves to this workflow commit"));
    assert_eq!(
        publish.matches("          verify_tag_commit\n").count(),
        3,
        "tag identity must be checked after governance, before draft creation, and before publish"
    );
}

#[test]
fn release_tag_identity_checks_bracket_downloads_and_draft_publication() {
    let yaml = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let (_, publish) = yaml.split_once("\n  publish:\n").expect("publish job");
    let checks: Vec<_> = publish
        .match_indices("          verify_tag_commit\n")
        .collect();
    assert_eq!(checks.len(), 3);
    let ancestry = publish.find("ancestry=").expect("main ancestry gate");
    let download = publish.find("gh run download").expect("artifact download");
    let create = publish.find("gh release create").expect("draft creation");
    let upload = publish.find("gh release upload").expect("asset upload");
    let publish_release = publish
        .find("gh release edit")
        .expect("release publication");
    assert!(ancestry < checks[0].0 && checks[0].0 < download);
    assert!(download < checks[1].0 && checks[1].0 < create);
    assert!(create < upload && upload < checks[2].0 && checks[2].0 < publish_release);
}
