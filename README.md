# AttoLang CLI (`oreslang-cli`)

Canonical developer-tooling and IDE frontend for **AttoLang**.

The repository and legacy `oreslang` executable remain unchanged for compatibility.
A new `atto` executable is built from **the same source file**. This is not
a second parser, compiler, privilege boundary or diagnostic protocol.


The public executables are:

```text
atto        # preferred AttoLang command
oreslang    # retained compatibility command
```

Both share subcommands, permission gates, backend selection, diagnostic JSON,
and exit codes. Only the executable name shown in help/usage differs.

```sh
atto --help
atto --version
atto check app.atto
atto run app.atto
oreslang check app.ores  # historical command and extension still forwarded
```

The CLI forwards source paths unchanged; `.atto` admission and compilation
remain the chosen backend's responsibility, not proof of feature parity.

This repository is **not** `ORESoftware/ores-cli` and editor integrations must
not depend on that unrelated tool.

## Ownership boundary

- `oreslang-source.java` owns the AttoLang lexer, parser, type checker,
  ownership checker, import graph, compiler APIs, runtime, and authoritative
  diagnostic production.
- `oreslang-cli` owns the developer-facing process/transport boundary:
  command-line UX, machine-readable diagnostic formats, compiler discovery,
  and eventually LSP/session management.
- `vscode-plugins` and `sublime-text-plugins` are thin editor clients. They
  invoke `oreslang`; they do not implement a second AttoLang compiler.

The Rust CLI deliberately does **not** parse or type-check AttoLang source.

## Commands

The commands below preserve existing `.ores` examples and the current `oreslang` executable. New AttoLang source should use `.atto` when a specific compiler/CLI release accepts that extension; support is not established by this README.


### Check

```bash
oreslang check app.ores
oreslang check app.ores lib.ores
oreslang check --format json app.ores
oreslang check --format jsonl app.ores
```

`oreslang check` is non-executing. The compiler backend may parse, resolve,
link symbolically, type-check, ownership-check, and perform static capability
validation, but it must not run guest `init`, `main`, actors, GPU kernels, or
other user code.

Human diagnostics use the editor-friendly form:

```text
/path/to/app.ores:12:7: error: expected expression
```

JSON uses diagnostic protocol version 1:

```json
{
  "version": 1,
  "ok": false,
  "diagnostics": [
    {
      "path": "/path/to/app.ores",
      "range": {
        "start": {"line": 12, "column": 7},
        "end": {"line": 12, "column": 8}
      },
      "severity": "error",
      "source": "oreslang",
      "message": "expected expression"
    }
  ]
}
```

Positions are one-based at the CLI protocol boundary. See
[`docs/IDE_PROTOCOL.md`](docs/IDE_PROTOCOL.md) for the editor contract.

### Doctor

```bash
oreslang doctor
```

Shows the diagnostic protocol version and the compiler backend that will be
used.

### Version

```bash
oreslang version
oreslang --version
```

## Permission grant boundary

Permission grants are **explicit command-line authorization**. The Rust CLI
does not infer `--allow-all`, `--allow-*`, `--deny-*` or
`--permission-check` from inherited `ORESLANG_*` environment variables.
In particular, an ambient `ORESLANG_ALLOW_ALL=true` must never turn a
`oreslang run app.ores` into a privileged execution. Explicit denies still
override explicit grants at the backend runtime policy boundary.

The checked-in `.cli-flags.toml` is a **future canonical flags-2-env
schema**. Its environment-field names must not be interpreted by this
legacy Clap launcher as an alternate authorization channel. The eventual
single-parser migration must preserve explicit source-of-authority tracking,
non-escalation across compiler/runtime layers, and denial when permission
provenance is absent. Do not load ambient or `.env` permission values as
an implicit substitute for command-line flags.

## Compiler backend discovery

The current compiler authority lives in `oreslang-source.java`. Until a
persistent compiler service/native distribution is available, the Rust CLI
delegates to that compiler's non-executing check entrypoint.

Backend resolution is:

1. explicit `--compiler /path/to/backend`;
2. `ORESLANG_COMPILER_JAR=/path/to/oreslang-source.jar` → `java -jar ...`;
3. `ORESLANG_COMPILER=/path/to/compiler-launcher`;
4. fallback internal launcher name `oreslang-compiler`.

The CLI intentionally never falls back to a command named `ores`, so it cannot
accidentally resolve to the unrelated `ORESoftware/ores-cli` on PATH. The
compiler distribution should provide `oreslang-compiler` or set one of the
explicit backend environment variables.

The public/editor command remains `oreslang check ...` in every case.

For unusual local layouts, the CLI also supports prefix arguments:

```bash
oreslang check --compiler /path/to/backend --compiler-arg ARG app.ores
```

## Language server

The Rust CLI now exposes a long-lived editor process:

```bash
oreslang lsp --stdio
```

The LSP runtime owns:

- JSON-RPC `Content-Length` framing over stdin/stdout;
- full-document synchronization and an in-memory unsaved-buffer cache;
- asynchronous compiler checks through a restartable compiler supervisor;
- file-result caching for unchanged source files;
- portable external-file watching;
- stale-result suppression using per-document generations;
- compiler-worker panic isolation/recovery;
- LSP diagnostic conversion from the canonical one-based compiler protocol.

Unsaved editor text is cached but is not written to disk. Until
`oreslang-source.java` exposes an explicit source-overlay API, authoritative
compiler checks are run for the saved file representation. This keeps editor
tooling from mutating source merely to obtain diagnostics.

The compiler supervisor is deliberately a stable Rust lifecycle boundary.
Today it adapts the compiler's one-shot non-executing `--check` entrypoint.
When the compiler grows a persistent RPC/native service, that process can be
owned and restarted behind the same supervisor API.

## Native distribution

Tags matching `v*` build and attach native `oreslang` binaries for:

- Linux x86-64;
- macOS x86-64;
- macOS Apple Silicon;
- Windows x86-64.

## Direction

Next layers include source-overlay checking, `oreslang check --watch`, and
compiler-backed formatting, symbols, semantic tokens, references, rename,
completion, and code actions.

Those features belong here as transport/tooling. AttoLang language semantics
remain in `oreslang-source.java`.

## Compiler PR checkpoint (2026-10-06)

A [repository-specific compiler compatibility matrix](docs/compiler-pr-sync.md) tracks the 10 newest `oreslang-source.java` PRs. They remain unmerged upstream; existing demos, build flags, and stable compiler references stay unchanged pending exact-SHA conformance testing.


## Test CLI: `atto test` (race, fuzz and sanitizers)

The public `atto test` subcommand delegates directly to the Rust
`atto-test` runner in `ores-truffle-oreslang/oreslang-test.cli`.
The legacy `oreslang test` / `oreslang-test` names remain compatible.
Both executable names forward the exact test arguments and exit code without
inventing compiler or sanitizer results.

```sh
atto test --fuzz --cases 1000 --seed 123
atto test --race --trace tests/traces/ordered.jsonl  # offline trace analysis
atto test --race                                      # inconclusive until trusted runtime trace support
```

The dispatcher selects `ATTO_TEST_CLI=/absolute/path/to/atto-test` first,
then the legacy `ORESLANG_TEST_CLI` override. With neither configured it
tries `atto-test` and then `oreslang-test` on PATH. **A failed explicit
override never silently falls back.** Native test compiler selection is still
controlled by the test runner's `ORESLANG_BIN` (compatibility variable).

`--fuzz` mutates stdin for an explicitly configured executable in
`atto-test.toml`, not automatically compiled AttoLang source. Sanitizer
reports in child output are observable findings, but cannot establish whether
ASan/UBSan/TSan instrumentation actually covered guest code.
`--race --trace` is an offline happens-before analysis, not live TSan/guest
scheduler validation. Uninstrumented `--race` exits 2, never a fake pass.

## Build profiles

`oreslang check` and `oreslang run` accept the backend-neutral build-profile selectors
`--release`, `--strict-aot`, and `--hard-rt`. They are mutually exclusive selectors;
`--hard-rt` semantically includes the requirements of `strict-aot`, which includes
`release`. `--freestanding` is orthogonal and may be combined with any profile.

Runtime reflection is forbidden by the v1 profile contract. Backends must use compile-time
introspection/code generation and explicit reachability roots instead. A backend that cannot
prove a requested profile must reject it rather than silently weakening it.

The canonical profile semantics live in `oreslang-target-profiles/docs/BUILD_PROFILES.md`.
