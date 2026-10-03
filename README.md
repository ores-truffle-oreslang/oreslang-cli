# oreslang-cli

Canonical developer-tooling and IDE frontend for Oreslang.

The public executable is:

```text
oreslang
```

This repository is **not** `ORESoftware/ores-cli` and editor integrations must
not depend on that unrelated tool.

## Ownership boundary

- `oreslang-source.java` owns the Oreslang lexer, parser, type checker,
  ownership checker, import graph, compiler APIs, runtime, and authoritative
  diagnostic production.
- `oreslang-cli` owns the developer-facing process/transport boundary:
  command-line UX, machine-readable diagnostic formats, compiler discovery,
  and eventually LSP/session management.
- `vscode-plugins` and `sublime-text-plugins` are thin editor clients. They
  invoke `oreslang`; they do not implement a second Oreslang compiler.

The Rust CLI deliberately does **not** parse or type-check Oreslang source.

## Commands

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

Those features belong here as transport/tooling. Oreslang language semantics
remain in `oreslang-source.java`.
