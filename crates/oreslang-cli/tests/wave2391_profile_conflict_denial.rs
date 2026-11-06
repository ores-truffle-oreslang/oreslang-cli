//! Real CLI argument-provenance checks for AOT/realtime profile conflicts.
//! The compiler never executes on rejected arguments; no guest parity claim.
use std::process::Command;

#[test]
fn mutually_exclusive_build_profiles_are_rejected_before_backend_dispatch() {
    let aliases = [env!("CARGO_BIN_EXE_atto"), env!("CARGO_BIN_EXE_oreslang")];
    let conflicting = [
        ("--release", "--strict-aot"),
        ("--release", "--hard-rt"),
        ("--strict-aot", "--hard-rt"),
    ];
    for binary in aliases {
        for subcommand in ["check", "run"] {
            for (first, second) in conflicting {
                for (left, right) in [(first, second), (second, first)] {
                    let result = Command::new(binary)
                        .args([subcommand, "never-executed.atto", left, right])
                        .arg("--compiler=not-a-real-backend-wave2391")
                        .output()
                        .expect("CLI executable");
                    assert_eq!(
                        result.status.code(),
                        Some(2),
                        "{binary} {subcommand} {left} {right}: {result:?}"
                    );
                    assert!(
                        result.stdout.is_empty(),
                        "denied profiles must not dispatch backend"
                    );
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    assert!(
                        stderr.contains("cannot be used with"),
                        "expected CLI conflict before backend: {stderr}"
                    );
                    assert!(
                        stderr.contains(left) || stderr.contains(right),
                        "expected named conflicting profile: {stderr}"
                    );
                }
            }
        }
    }
}

#[test]
fn each_individual_profile_is_advertised_by_both_frontends() {
    for binary in [env!("CARGO_BIN_EXE_atto"), env!("CARGO_BIN_EXE_oreslang")] {
        for subcommand in ["check", "run"] {
            let output = Command::new(binary)
                .args([subcommand, "--help"])
                .output()
                .expect("CLI executable");
            assert!(output.status.success(), "{binary} {subcommand}: {output:?}");
            let help = String::from_utf8(output.stdout).expect("UTF-8 help");
            for profile in ["--release", "--strict-aot", "--hard-rt", "--freestanding"] {
                assert!(
                    help.contains(profile),
                    "{binary} {subcommand} missing {profile}"
                );
            }
        }
    }
}
