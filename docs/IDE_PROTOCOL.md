# Oreslang IDE protocol

The public executable for Oreslang developer tooling is:

```text
oreslang
```

Editor integrations must never call `ORESoftware/ores-cli` and must never fall back to a command named `ores`.

## Compiler checks

Human-readable:

```sh
oreslang check app.ores
```

Machine-readable:

```sh
oreslang check --format=json app.ores
```

The JSON envelope is versioned:

```json
{
  "version": 1,
  "ok": false,
  "diagnostics": [
    {
      "version": 1,
      "path": "/src/app.ores",
      "range": {
        "start": {"line": 7, "column": 13},
        "end": {"line": 7, "column": 14}
      },
      "severity": "error",
      "message": "expected expression"
    }
  ]
}
```

Line and column values are **1-based** in protocol version 1.

## Safety invariant

`oreslang check` is validation only. It must not run guest `main`, file/module `init`, actors, GPU kernels, static user initialization, or other Oreslang guest code.

The authoritative parser/type checker remains in `oreslang-source.java`. This repository is the developer-tooling/process boundary, not a second compiler implementation.

## Compiler backend discovery

The CLI invokes an internal compiler backend with `--check`. Discovery order:

1. explicit `--compiler <path>`;
2. `ORESLANG_COMPILER`;
3. `oreslang-compiler` on `PATH`.

There is deliberately no `ores` fallback.
