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

Positions are one-based at the CLI protocol boundary.

### Doctor

```bash
oreslang doctor
```

Shows the diagnostic protocol version and the compiler backend that will be
used.

## Compiler backend discovery

The current compiler authority lives in `oreslang-source.java`. Until a
persistent compiler service/native distribution is available, the Rust CLI
delegates to that compiler's non-executing check entrypoint.

Backend resolution is:

1. `ORESLANG_COMPILER_JAR=/path/to/oreslang-source.jar` → `java -jar ...`;
2. `ORESLANG_COMPILER=/path/to/compiler-launcher`;
3. fallback internal launcher name `oreslang-compiler`.

The CLI intentionally never falls back to a command named `ores`, so it cannot accidentally resolve to the unrelated `ORESoftware/ores-cli` on PATH. The compiler distribution should provide `oreslang-compiler` or set one of the explicit backend environment variables.

The public/editor command remains `oreslang check ...` in every case.

For unusual local layouts, the CLI also supports:

```bash
oreslang check --compiler /path/to/backend --compiler-arg ARG app.ores
```

## Direction

The intended next layers are:

- persistent incremental compiler sessions;
- source overlays/stdin for unsaved editor buffers;
- `oreslang check --watch`;
- `oreslang lsp --stdio`;
- formatting, symbols, semantic tokens, references, rename, completion, and
  code actions backed by compiler APIs.

Those features belong here as transport/tooling. Oreslang language semantics
remain in `oreslang-source.java`.
