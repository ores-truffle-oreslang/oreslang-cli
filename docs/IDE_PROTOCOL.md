# Oreslang IDE protocol

The public executable for Oreslang developer tooling is:

```text
oreslang
```

Editor integrations must never call `ORESoftware/ores-cli`, must never call the
Java compiler directly, and must never fall back to a command named `ores`.

## Compiler checks

Human-readable:

```sh
oreslang check app.ores
```

Machine-readable:

```sh
oreslang check --format=json app.ores
```

Protocol version 1 uses one-based line and column coordinates:

```json
{
  "version": 1,
  "ok": false,
  "diagnostics": [
    {
      "path": "/src/app.ores",
      "range": {
        "start": {"line": 7, "column": 13},
        "end": {"line": 7, "column": 14}
      },
      "severity": "error",
      "source": "oreslang",
      "message": "expected expression"
    }
  ]
}
```

A diagnostic may also contain a stable `code` when the compiler supplies one.

For streaming consumers:

```sh
oreslang check --format=jsonl app.ores
```

Each JSONL record contains the protocol version plus one diagnostic.

## Safety invariant

`oreslang check` performs validation only. It must not run guest `main`,
file/module `init`, actors, GPU kernels, user static initialization, or other
Oreslang guest code.

The authoritative lexer/parser/typechecker remains in `oreslang-source.java`.
This repository is the developer-tooling/process boundary, not a second compiler.

## Compiler backend discovery

The CLI invokes an internal compiler backend with `--check`.

Discovery order:

1. `ORESLANG_COMPILER_JAR` → `java -jar <jar>`;
2. explicit `--compiler <program>` or `ORESLANG_COMPILER`;
3. `oreslang-compiler` on `PATH`.

There is deliberately no `ores` fallback.
