# oreslang-cli

Canonical developer tooling and IDE CLI for Oreslang.

The installed executable is **`oreslang`**.

```sh
oreslang check app.ores
oreslang check --format=json app.ores
oreslang doctor
oreslang version
```

## Repository boundary

- `oreslang-source.java` owns the lexer, parser, type checker, ownership checker, import graph, and compiler semantics.
- `oreslang-cli` owns the public developer-tooling executable, machine diagnostics, IDE-facing process contracts, and eventually the Oreslang language server.
- `vscode-plugins`, `sublime-text-plugins`, and other editor integrations invoke `oreslang`.
- `ORESoftware/ores-cli` is unrelated and must not be used by Oreslang tooling.

## Compiler backend

`oreslang check` delegates to the authoritative compiler backend using a mandatory non-executing `--check` call.

Backend discovery:

1. `--compiler <path>`
2. `ORESLANG_COMPILER`
3. `oreslang-compiler` on `PATH`

There is intentionally **no fallback to a command named `ores`**.

See [docs/IDE_PROTOCOL.md](docs/IDE_PROTOCOL.md) for the versioned editor contract.
