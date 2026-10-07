#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("oreslang-cli-test-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn fake_compiler(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("oreslang-compiler");
    fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).expect("write compiler");
    let mut permissions = fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod");
    path
}

#[test]
fn check_converts_backend_diagnostic_to_protocol_json() {
    let dir = temp_dir();
    let source = dir.join("demo.ores");
    fs::write(&source, "pub fnc main() => void { return; }\n").expect("source");

    let compiler = fake_compiler(
        &dir,
        "for source in \"$@\"; do :; done\nprintf '%s:3:5: error: expected expression\\n' \"$source\"\nexit 1",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .arg("check")
        .arg("--format")
        .arg("json")
        .arg("--compiler")
        .arg(&compiler)
        .arg(&source)
        .output()
        .expect("run oreslang");

    assert!(!output.status.success());

    let payload: Value = serde_json::from_slice(&output.stdout).expect("protocol json");
    assert_eq!(payload["version"], 1);
    assert_eq!(
        payload["diagnostics"][0]["path"],
        source.to_string_lossy().as_ref()
    );
    assert_eq!(payload["diagnostics"][0]["range"]["start"]["line"], 3);
    assert_eq!(payload["diagnostics"][0]["range"]["start"]["column"], 5);
    assert_eq!(payload["diagnostics"][0]["message"], "expected expression");

    fs::remove_dir_all(dir).ok();
}

#[test]
fn check_succeeds_when_backend_reports_no_diagnostics() {
    let dir = temp_dir();
    let source = dir.join("demo.ores");
    fs::write(&source, "pub fnc main() => void { return; }\n").expect("source");
    let compiler = fake_compiler(&dir, "exit 0");

    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .arg("check")
        .arg("--format=json")
        .arg("--compiler")
        .arg(&compiler)
        .arg(&source)
        .output()
        .expect("run oreslang");

    assert!(output.status.success());

    let payload: Value = serde_json::from_slice(&output.stdout).expect("protocol json");
    assert_eq!(payload["version"], 1);
    assert_eq!(payload["diagnostics"].as_array().unwrap().len(), 0);

    fs::remove_dir_all(dir).ok();
}

#[test]
fn check_preserves_nonfatal_select_return_warning_in_json() {
    let dir = temp_dir();
    let source = dir.join("select.ores");
    fs::write(&source, "pub routine main() -> void { return; }\n").expect("source");

    // The unmerged compiler #408 emits a nonfatal W-SELECT-RETURN warning.
    // Mock the backend wire format without assuming the new syntax is on main.
    let compiler = fake_compiler(
        &dir,
        "for source in \"$@\"; do :; done\nprintf '%s:4:7: warning: W-SELECT-RETURN discarded do-select return\\n' \"$source\"\nexit 0",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .arg("check")
        .arg("--format=json")
        .arg("--compiler")
        .arg(&compiler)
        .arg(&source)
        .output()
        .expect("run oreslang");

    assert!(
        output.status.success(),
        "warning-only compiler output must not fail: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("protocol json");
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["diagnostics"][0]["severity"], "warning");
    assert_eq!(
        payload["diagnostics"][0]["path"],
        source.to_string_lossy().as_ref()
    );
    assert_eq!(
        payload["diagnostics"][0]["message"],
        "W-SELECT-RETURN discarded do-select return"
    );
    fs::remove_dir_all(dir).ok();
}
