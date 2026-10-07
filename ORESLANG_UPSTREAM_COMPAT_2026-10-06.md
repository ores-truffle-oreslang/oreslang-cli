# Oreslang upstream compatibility — 2026-10-06

This repository is audited against the latest 10 PRs in `ores-truffle-oreslang/oreslang-source.java` (#405, #406, #408, #409, #410, #411, #412, #414, #415, #416).

## Upstream contract

- #405 `do select` / `do nb select` no-result syntax; legacy select remains compatible.
- #406 arm-local `return` inside `do select`, with `W-SELECT-RETURN` diagnostics.
- #408 surfaces those warnings through the CLI.
- #409 additive runtime `SelectPlan`; no source rewrite required and traditional select stays on `SelectSet`.
- #410 permits task-local data-only `Channel<T>` at async boundaries and makes explicit `rt take` consuming.
- #411 defines binding capabilities: `const` fixed/read-only, `val` = `const mut`, `let` rebindable/read-only, `let mut` rebindable/mutable; adds select-case bindings.
- #412 expands do-select control-flow/actor-domain/atomic-dispatch coverage.
- #414 hardens source continuations so selected arms/cleanup run once.
- #415 adds `define actor` parsing/isolation groundwork and host `ready`/`done`; source `spawn Worker()` lifecycle is still deferred.
- #416 shares immutable checked code images across same-process actor contexts; not cross-process or machine-code sharing.

## Repository impact

Preserve and display compiler warnings from #408; future syntax-aware tooling must recognize `do select`, `do nb select`, and #411 binding qualifiers without rewriting legacy select.

## Integration policy

These PRs are not one linear compiler head: several are stacked on different bases and #415/#416 are a separate actor stack. Do **not** repin this repository to an arbitrary draft head and call it “latest.” Source migrations should be compatible with the intended contract, while compiler pins move only when the required upstream stack is integrated and exact-head CI is green.

If the source organization cannot allocate GitHub Actions runners, validate by mirroring the exact source Git tree/blob SHAs into a temporary branch in a funded test organization and run Actions there. Do not use private cross-org checkout tokens or secrets.

## Guardrails

- `do select` / `do nb select` are side-effecting/no-result forms; arm returns are local and discarded.
- Traditional `select` behavior remains available; #409 must not replace it.
- `cb select` / `nb cb select` are not canonical select syntax.
- Keep source pointer-free; ownership remains expressed with `rt copy/share/borrow/take/ref/unref/deref` as supported.
- Actor-mailbox data must remain serializable; task-local channels are not actor-mailbox capabilities.
- #416 shares immutable code data only inside the same OS process; it does not establish cross-process page/JIT sharing.
