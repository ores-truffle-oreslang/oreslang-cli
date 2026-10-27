# oreslang-cli: rollout receipt inspection v1

This opt-in Rust tool checks the consistency of a declared acceptance receipt.
It does not run Oreslang, authenticate GitHub jobs, prove artifact contents,
authorize source export, or certify a compiler/backend. No release workflow or
required status context is activated by this change.

## Repository acceptance targets

The table is a proposed acceptance checklist based on this repository's
[README at the inspected base](https://github.com/ores-truffle-oreslang/oreslang-cli/blob/2c601d72752312fbad12c7c5e3d7fbda45bb57e3/README.md).
These are acceptance targets, not claims of implemented adapters or executed tests.
Bind each case to an actual command/oracle before producing a receipt; otherwise
it remains NOT_EXECUTED. A missing implementation must not be replaced with a stub.

| Case | Backend | Evidence phase | Required observation |
| --- | --- | --- | --- |
| compiler-discovery | host | host | Resolve and pin the actual compiler used by the CLI |
| diagnostic-contract | host | host | Preserve machine diagnostics and nonzero compiler exits |
| no-fake-artifact | host | host | Never publish success/output when compiler admission fails |

The compiler profiles deliberately require executable coverage for async I/O,
ownership, indexing, exports, generators and supervision. Unsupported features
remain gaps. Passing negative fixtures does not satisfy the execution rows.
Host-only checks and model results stay in their own evidence phases.

## Build and inspect

Use Rust 1.75+ with rustfmt and Clippy. The crate has no dependencies and a
separate workspace, so it does not alter this repository's application build.

```sh
cargo fmt --manifest-path tools/rollout-evidence/Cargo.toml -- --check
cargo clippy --manifest-path tools/rollout-evidence/Cargo.toml --offline --locked --all-targets -- -D warnings
cargo test --manifest-path tools/rollout-evidence/Cargo.toml --offline --locked
cargo run --manifest-path tools/rollout-evidence/Cargo.toml --offline --locked -- --cases
cargo run --manifest-path tools/rollout-evidence/Cargo.toml --offline --locked -- receipt.tsv EXPECTED_COMMIT EXPECTED_TREE EXPECTED_CORPUS_SHA256
```

The receipt is canonical ASCII/LF TSV, at most 1 MiB, with this exact header:

```text
repository	suite	backend	phase	outcome	commit	tree	corpus_sha256	run_id	job_id	steps	tests	exit_code	artifact_sha256
```

Repository must equal `ores-truffle-oreslang/oreslang-cli`. The expected commit/tree are
full nonzero lowercase 40-hex Git object IDs supplied independently of the
receipt. The corpus pin is a nonzero lowercase 64-hex SHA-256 for the reviewed
fixture/oracle set. Bind all dependency compiler commits, trees, binaries, command
lines, toolchain versions and individual fixture digests in the referenced
artifact; this compact envelope does not validate those dependencies itself.

Every tuple from `cases.tsv` must occur exactly once, with no extra tuple.
Only outcome `pass`, exit code `0`, positive canonical u64 run/job/step/test
counts and a nonzero 64-hex artifact digest are consistent. For a rejection row,
exit 0 is the **negative-test harness** exit; the artifact must record the
expected failing compiler exit/diagnostic and absent output artifact.
Skipped, queued, cancelled, unexecuted and intentional capability rejection
statuses fail a required execution row. Whitespace ambiguity, unknown columns,
duplicate cases, missing cases and stale pins are rejected.

Success prints `CONSISTENT_UNAUTHENTICATED_RECEIPT`, never VERIFIED.
Unit tests use synthetic receipts solely to test this parser. They establish
neither repository acceptance nor native/AOT execution. The added workflow runs
only checker self-tests and profile listing.

## Integration boundaries

- Core remains host-I/O-free; guest stdlib I/O must use admitted async capability
  providers with bounded backpressure, cancellation and physical retirement.
  Await suspends logical work without blocking scheduler carriers.
- Respect actor ownership, generation fences, cleanup, pointerless borrow rules
  and fail-closed unsupported syntax. Source export aliases do not automatically
  expose host/ABI exports. Pure callback/numeric libraries acquire no new I/O.
- Keep Java/GraalVM, LLVM, Wasm, .NET and JS execution observations distinct.
  Host mocks, linker stubs, symbolic models, accepted syntax and rejected syntax
  cannot establish executable parity. Finite model checks must record scope,
  bounds and tool version and cannot replace real compiler/runtime tests.
- New first-party tooling uses Rust. This crate does not migrate or approve
  retained legacy scripts, alter compiler pins, or widen existing capability gates.
- Before trusting any receipt, independently verify exact run/job identity,
  check issuer, actual commands, step conclusions, test counts, raw artifact
  hashes, fixture coverage, dependencies and expected outputs. This checker
  makes **no** GitHub API calls and performs **no** cryptographic authentication.
- Private-source transfer and branch-protection policies stay in force.
  Run locally or on source-authorized runners. No destination allowlist,
  source mirror, credentials, automatic merge or release promotion is added.

The profile is additive to existing tests and security gates. Review and wire a
real receipt producer in a later repository-specific change; never infer a green
acceptance result from checker unit tests.
