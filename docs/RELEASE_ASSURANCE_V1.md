# AttoLang source-free release manifest verifier v1

This is an **opt-in public prototype** of proof-carrying release *candidate*
validation. It is intentionally not a merge or release permission gate. It
verifies that an external, independently trusted **Ed25519 public key** signed
one canonical DSSE envelope and that a local release artifact's **actual bytes**
match the signed length and SHA-256.

It cannot establish that a signed assertion came from GitHub, that code
owners approved, that an artifact was produced by a trusted runner, that
branch rules are enforced, or that an AttoLang backend actually compiled and
executed `.atto`. Those claims require independent authenticated retrieval
from source-owned GitHub, relevant signing identity policy, compiler guest
traces, and read-back after the final merge or release race check.

## Usage and safe exit codes

```bash
node tools/release-assurance-v1/verify.mjs \
  --envelope ./envelope.json \
  --trusted-key ./independently-approved-ed25519-public-key.pem \
  --artifact ./atto-release.tar.gz
```

The caller must obtain and pin the trusted public key **out of band**. A
public key embedded in the envelope does not establish trust. Never use a
self-generated test key as a production trust anchor. Signing/release
operations are deliberately absent from this verifier.

- Exit `3`: `LOCAL_CRYPTOGRAPHIC_CANDIDATE`; signature and artifact bytes
  match, but **release_authorized=false** and guest parity unproven.
- Exit `1`: `DENIED`; malformed signature, invalid receipt, mismatch, or unsafe
  admission claim.
- Exit `2`: input file admission or usage error.

**There is no success/authorized exit zero.** A wrapper treating this as a
release authorization is unsafe. Only a separately authenticated, privileged,
independent release service may promote evidence after GitHub/live source
identity and code-owner policy are verified.

## Signed envelope format

Canonical compact UTF-8 JSON (not pretty-printed). Duplicate JSON keys,
non-canonical encodings, extra fields, malformed base64, multiple signatures,
wrong payload types and keys not matching the separately trusted public key
are rejected. The DSSE PAE signature covers exact payload type and payload
bytes. Signature `keyid` is SHA-256 of the Ed25519 SPKI DER public key.

```json
{"payloadType":"application/vnd.atto.release-assurance.v1+json","payload":"BASE64_OF_CANONICAL_JSON","signatures":[{"keyid":"SHA256_OF_TRUSTED_PUBLIC_KEY_DER","sig":"BASE64_ED25519_SIGNATURE"}]}
```

The signed payload has exactly the fields `schema`, `subject`, `governance`,
`reviews`, `workflow`, and `backends`:

- `schema`: `atto.release-assurance.v1`.
- `subject`: release repository, immutable Git commit and tree SHA, release
  artifact filename/basename, actual SHA-256 and positive byte length.
- `governance`: **asserted** protected-main, no bypass, required code-owner
  approval, stale-review dismissal, PR author, code-owner identities, required
  check contexts.
- `reviews`: ordered or unordered historical approvals/changes requested,
  dismissed or commented. The validator chooses the latest event for every
  case-insensitive reviewer identity. It rejects changed heads, unknown review
  states, invalid UTC calendar dates, ambiguous timestamp ties and outstanding
  change requests.
- `workflow`: asserted exact source commit/tree, positive run/attempt/job/
  runner identities, completed successful status, numbered **nonempty**
  executed-step receipts and required immutable-checkout/test steps.
- `backends`: exactly five unique `java`, `llvm`, `net`, `wasm`, `forge`
  candidate guest receipts, each with its **own** backend repo head, tree,
  run/attempt/job/runner/step identity and toolchain/fixture/output digests.
  Each named backend must identify its canonical
  `ores-truffle-oreslang/oreslang-source.<backend>` repository; a copied job
  from another repository is denied even when the signed shape is otherwise valid.
  `HOST_ONLY`, `NOT_EXECUTED`, `steps=[]`, mismatching fixture/output hashes,
  or missing backend results cannot pass the schema.

Even a signed, schema-compliant source-free **synthetic fixture** can claim all
five backends were executed. Thus a positive local result must **never** be
presented as real guest evidence. The runner's production proof must come from
independent authenticated source-side execution and matching blobs.

## Security and CI properties

- Private keys never appear in this repository. Tests generate **ephemeral**
  Ed25519 pairs only in process for synthetic local fixtures.
- Input paths use descriptor-pinned `O_NOFOLLOW` and `O_NONBLOCK`; deny symlink,
  multi-linked, nonregular, empty, and oversized files, and inode/size/mtime/
  ctime changes during read. Stable symlinked ancestor directories and lexical
  `..` path segments are denied; the leaf pathname and ancestors are checked
  again after reading. These pathname checks are **not** race-free against a
  hostile same-UID process able to replace directories between checks; use
  private, trusted input directories when preparing candidate evidence.
  Envelope max 256 KiB, public key max 16 KiB, release artifact max 64 MiB.
- Real Node 22 tests cover 40 individual mutation cases, 1,024 compound
  boolean-security combinations, key substitution, artifact tampering,
  malformed canonical JSON/UTF-8/base64, unsafe paths, and the CLI nonzero
  exit-code contract.
- The public Actions workflow uses pinned `checkout` and `setup-node` commits,
  checks out the original PR HEAD, verifies the commit/tree plus the actual raw
  source file blobs, and executes all negative tests. It is **source-free**;
  no private AttoLang compiler or conformance source is mirrored.

## Integration prerequisites for production

1. Authenticate full GitHub REST/GraphQL review, status, branch-policy and
   job-steps pagination through an installation-limited, read-only collector.
2. Bind each live receipt to exact repository, commit+tree, workflow run ID,
   run attempt, job ID, successful required step and artifact digest.
3. Ensure the reviewer has independent authority and approval still applies
   after all newer review events and pushes.
4. Require verified compiler-backed guest execution for each backend, plus
   matching negative fixtures; host-only smoke never qualifies.
5. Re-read head, policy, review and run identity immediately before publishing;
   any changed value invalidates the candidate. Require independent signing
   identity governance and a signed release artifact before promotion.
6. Configure GitHub branch protection and code-owner review externally; this
   connection cannot enforce administration settings.

This verifier deliberately does **not** connect to a production release
publisher and never issues a publish, approval or merge request.
