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

#[test]
fn ambient_permission_variables_cannot_grant_run_authority() {
    let dir = temp_dir();
    let source = dir.join("ambient-deny.ores");
    fs::write(&source, "pub fnc main() => void { return; }\n").expect("source");
    let compiler = fake_compiler(&dir, "printf 'ARG:%s\\n' \"$@\"");

    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .arg("run")
        .arg("--compiler")
        .arg(&compiler)
        .arg(&source)
        .env("ORESLANG_ALLOW_ALL", "true")
        .env("ORESLANG_ALLOW_NET", "*")
        .env("ORESLANG_ALLOW_READ", "/")
        .env("ORESLANG_ALLOW_ENV", "PATH")
        .env("ORESLANG_PERMISSION_CHECK", "compile")
        .output()
        .expect("run oreslang");
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ARG:--permission-check=runtime"),
        "{stdout}"
    );
    assert!(!stdout.contains("ARG:--allow-"), "{stdout}");
    assert!(!stdout.contains("ARG:--allow-all"), "{stdout}");
    assert!(
        !stdout.contains("ARG:--permission-check=compile"),
        "{stdout}"
    );
    fs::remove_dir_all(dir).ok();
}

#[test]
fn explicit_permission_arguments_survive_ambient_grant_attempts() {
    let dir = temp_dir();
    let source = dir.join("explicit-grant.ores");
    fs::write(&source, "pub fnc main() => void { return; }\n").expect("source");
    let compiler = fake_compiler(&dir, "printf 'ARG:%s\\n' \"$@\"");

    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .arg("run")
        .arg("--allow-net=api.example.com:443")
        .arg("--deny-net=blocked.example.com:443")
        .arg("--compiler")
        .arg(&compiler)
        .arg(&source)
        .env("ORESLANG_ALLOW_ALL", "true")
        .env("ORESLANG_ALLOW_NET", "*")
        .env("ORESLANG_DENY_NET", "")
        .output()
        .expect("run oreslang");
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ARG:--allow-net=api.example.com:443"),
        "{stdout}"
    );
    assert!(
        stdout.contains("ARG:--deny-net=blocked.example.com:443"),
        "{stdout}"
    );
    assert!(!stdout.contains("ARG:--allow-net=*"), "{stdout}");
    assert!(!stdout.contains("ARG:--allow-all"), "{stdout}");
    fs::remove_dir_all(dir).ok();
}

#[test]
fn compiler_arg_cannot_smuggle_permission_or_isolate_authority() {
    let dir = temp_dir();
    let source = dir.join("compiler-arg-policy.ores");
    fs::write(&source, "pub fnc main() => void { return; }\n").expect("source");
    let compiler = fake_compiler(&dir, "printf 'unexpected backend launch\\n'");

    for unsafe_option in [
        "--allow-all",
        "--allow-net=*",
        "--deny-env=PATH",
        "--permission-check=compile",
        "--no-prompt",
        "--ores-permission-explicit=true",
        "--ores-capabilities=NETWORK",
        "--release",
        "--strict-aot",
        "--hard-rt",
        "--freestanding",
        "--",
        "@/tmp/backend-argfile",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
            .arg("run")
            .arg(&source)
            .arg("--compiler")
            .arg(&compiler)
            .arg(format!("--compiler-arg={unsafe_option}"))
            .output()
            .expect("run oreslang");
        assert_eq!(
            output.status.code(),
            Some(2),
            "compiler option unexpectedly admitted: {unsafe_option}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("permission, isolate, and build-profile policy flags"),
            "rejection message missing for {unsafe_option}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "backend unexpectedly executed for {unsafe_option}"
        );
    }

    // The same parser applies to check and lsp, not only the run path.
    for subcommand in ["check", "lsp"] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oreslang"));
        cmd.arg(subcommand);
        if subcommand == "lsp" {
            cmd.arg("--stdio");
        } else {
            cmd.arg(&source);
        }
        let output = cmd
            .arg("--compiler")
            .arg(&compiler)
            .arg("--compiler-arg=--allow-all")
            .output()
            .expect("run oreslang");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    fs::remove_dir_all(dir).ok();
}

#[test]
fn ordinary_compiler_args_still_reach_backend_without_new_permissions() {
    let dir = temp_dir();
    let source = dir.join("compiler-arg-safe.ores");
    fs::write(&source, "pub fnc main() => void { return; }\n").expect("source");
    let compiler = fake_compiler(&dir, "printf 'ARG:%s\\n' \"$@\"");

    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .arg("run")
        .arg(&source)
        .arg("--compiler")
        .arg(&compiler)
        .arg("--compiler-arg=--diagnostics=json")
        .output()
        .expect("run oreslang");
    assert!(
        output.status.success(),
        "backend invocation rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ARG:--diagnostics=json"), "{stdout}");
    assert!(
        stdout.contains("ARG:--permission-check=runtime"),
        "{stdout}"
    );
    assert!(!stdout.contains("ARG:--allow-all"), "{stdout}");
    fs::remove_dir_all(dir).ok();
}


#[test]
fn build_profile_flags_are_first_class_and_forwarded() {
    let dir = temp_dir();
    let source = dir.join("profile.ores");
    fs::write(&source, "pub fnc main() => void { return; }\n").expect("source");
    let compiler = fake_compiler(&dir, "printf 'ARG:%s\\n' \"$@\"");

    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .arg("run")
        .arg("--strict-aot")
        .arg("--freestanding")
        .arg("--compiler")
        .arg(&compiler)
        .arg(&source)
        .output()
        .expect("run oreslang");

    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ARG:--strict-aot"), "{stdout}");
    assert!(stdout.contains("ARG:--freestanding"), "{stdout}");
    assert!(stdout.contains("ARG:--permission-check=runtime"), "{stdout}");
    fs::remove_dir_all(dir).ok();
}

#[test]
fn build_profile_selectors_are_mutually_exclusive() {
    let dir = temp_dir();
    let source = dir.join("profile-conflict.ores");
    fs::write(&source, "pub fnc main() => void { return; }\n").expect("source");
    let compiler = fake_compiler(&dir, "printf 'unexpected backend launch\\n'");

    let output = Command::new(env!("CARGO_BIN_EXE_oreslang"))
        .arg("check")
        .arg("--release")
        .arg("--strict-aot")
        .arg("--compiler")
        .arg(&compiler)
        .arg(&source)
        .output()
        .expect("run oreslang");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(dir).ok();
}
