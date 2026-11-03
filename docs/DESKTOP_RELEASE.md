# Releasing an installable AttoLang desktop compiler

## Release unit: **three executables, not a CLI-only archive**

An installable AttoLang toolchain requires `atto`, the compatible `oreslang`
launcher, and the authoritative Java/GraalVM native `oreslang-compiler`,
all built for the **same host OS and architecture**. On Windows all three
names end with `.exe`. Both launcher names use the same Rust implementation.

The public `.github/workflows/release.yml` produces **CLI-only archives**
containing `atto` and `oreslang`. Those archives do not contain
`oreslang-compiler`, are **not a native compiler release**, and must never be
substituted for the approved combined compiler bundles required by Homebrew
or a desktop installer. A source-free MOCK backend is not a native compiler.

Both launchers resolve a sibling compiler before searching `PATH`. A
successful `atto version` or `oreslang version` is **not** a compiler test:
acceptance must include `atto check path/to/valid.atto`, the compatible
`oreslang check` (including legacy `.ores`), invalid-file diagnostic/exit checks,
and `atto run` of a
known-safe fixture using the real compiler.

## Private build candidates

The private `oreslang-source.java` repository's
`.github/workflows/desktop-compiler-candidates.yml` builds native compiler
candidates for macOS ARM64, macOS x86_64 and Windows x86_64; its bundles include
all three executables and a `provenance.json` with full source/frontend commit IDs and
SHA-256 values. The candidate workflow also performs the combined CLI check.
Windows builds a **per-user installer** and performs install/check/uninstall
smoke tests. These are **private artifacts**, not user-installable public
releases.

The Java source is private and its source-mirroring security rules are
deny-by-default. Do not mirror the private tree into this public repository or
another organization, or publish a public binary/release without an
independently reviewed binary-distribution approval and integrity evidence.
No ordinary user should be told the compiler is available until all relevant
assets are actually published and verified.

## Publication gate

Before promoting a release:

1. Confirm CI executed steps at the **exact** source and CLI commits. A job
   failed with **zero executed steps** is a runner problem, not test evidence.
2. Build and run native compiler and public CLI on all three target systems;
   fail on missing compiler, unsupported host, or runtime libraries.
3. Run installer tests on a clean macOS ARM64, macOS x86_64, and Windows x64
   system, including checks and user-PATH behavior; inspect uninstall output.
4. Security-review binary publication, license/dependency redistribution,
   SBOM, artifacts, signing/notarization (macOS), signing/SmartScreen
   (Windows), SHA-256 and attestations, and the release provenance.
5. Publish **approved** combined platform archives and Windows installer to a public
   GitHub Release in this repository. Artifacts must match the source commit
   and the SHA-256 values in the release manifest. Never upload private source.
6. Generate the Homebrew formula with the checksums of the **published** macOS
   archives. Update a public tap, then execute `brew install`,
   `brew test`, and `brew uninstall` on both macOS architectures.

## Homebrew formula generation

Only **after** a public `vX.Y.Z` release contains these two archives:

- `oreslang-compiler-macos-arm64.tar.gz`
- `oreslang-compiler-macos-x86_64.tar.gz`

Run:

```bash
bash packaging/homebrew/generate-formula.sh vX.Y.Z \
  REAL_ARM64_ARCHIVE_SHA256 REAL_INTEL_ARCHIVE_SHA256 \
  Formula/oreslang.rb
```

The generated formula installs all three executables and contains a real AttoLang
source-level check. Its release URL and checksums must be verified; do not
publish the formula with placeholder digests. These compiler-bundle archive
names are **different** from the CLI-only archives produced by the public
release workflow. Never silently replace an already published release asset;
rebuilds require a new reviewed release identity and provenance.

Until a dedicated `homebrew-oreslang` repository is available, an approved
formula placed in `Formula/` of this public repository can be installed
through an **explicit-URL** Homebrew tap:

```bash
brew tap ores-truffle-oreslang/cli https://github.com/ores-truffle-oreslang/oreslang-cli
brew install ores-truffle-oreslang/cli/oreslang
oreslang doctor
atto check hello.atto
# Legacy compatibility: oreslang check hello.ores
```

This is a *future command*, not a currently available install: the formula and
public release assets must first be published. A conventional
`homebrew-oreslang` tap can later replace this explicit URL tap.

## Windows

After review, publish the verified installer
`oreslang-windows-x86_64-setup.exe`. It must contain all three executables, preserve
user PATH entries, avoid administrator privileges, and cleanly uninstall. Do
not substitute the limited experimental `.NET` backend for the reference
compiler without explicitly changing the advertised feature support.
