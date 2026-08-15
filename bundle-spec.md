# BitExact bundle format, version 1

A bundle is a single UTF-8 JSON document exported from a recorded run.
It is verifiable independently of BitExact: the open-source verifier
(`verifier/`) implements exactly this document, and the fixtures in
`verifier/testdata/` are the conformance corpus for any other
implementation.

## Canonicalization

All hashes and signatures are computed over RFC 8785 (JCS) canonical
JSON: object keys sorted by UTF-16 code units, ECMAScript
shortest-round-trip number formatting, minimal string escaping with
lone surrogates emitted as `\uXXXX` escapes, UTF-8 encoding, NaN and
Infinity rejected. Integers outside the I-JSON safe range
(|n| > 2^53 − 1) are rejected — other languages would parse them as
doubles and canonicalize different bytes. The vector corpus
`testdata/jcs-vectors.json` is normative for implementations.

## Hash algorithms

Each entry names its algorithm in `alg`: `"blake2b-256"` (default) or
`"sha256"` (for FIPS-constrained deployments; field commitments then use
HMAC-SHA256). Verifiers follow each entry's own `alg`; mixed stores
verify.

## Top-level object

| Field | Type | Meaning |
|---|---|---|
| `format` | string | Exactly `"bitexact-bundle/1"`. |
| `run_id` | string | The recorded run's identifier. |
| `entries` | array | The run's manifest entries, in step order (see below). |
| `chain` | object | `{"head_hash": <hex>}` — the `hash` of the final entry, or `null` for an empty run. |
| `checkpoints` | array, optional | Signed head attestations (see below). |
| `anchors` | array, optional | External head anchors (see below). |
| `signature` | object, optional | Detached ed25519 signature (see below). |

## Entries

Each entry is one recorded step:

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | Entry format version; currently `2`. |
| `alg` | string | Hash algorithm identifier. |
| `run_id` | string | Same as the bundle `run_id`; verification fails on mismatch. |
| `step` | integer | 0-based position; must equal the entry's index. |
| `kind` | string | `http_call`, `tool_call`, `nondet`, `fork`, `injected`, `run_meta`, `run_end`, `redaction`, or `repair`. `injected` marks a synthetic response written by a response-mutation fork — explicitly not recorded upstream traffic; its data carries `source_step`, the replacement `response`, and `replaced_response` (the recorded response it displaced), and the kind is preserved through every descendant fork. |
| `ts` | string | ISO-8601 UTC timestamp at recording time. |
| `prev` | string | The previous entry's `hash`; 64 zeros for step 0 (genesis). |
| `data` | object | Kind-specific payload; individual fields may be redacted. |
| `salts` | object | Per-path 16-byte hex salts; a redacted path's salt is destroyed. Absent when every path is redacted. |
| `commitments` | object | Per-path salted commitments — keyed BLAKE2b-256 (or HMAC-SHA256) over the canonical value. Always complete. |
| `redacted` | array | Paths whose value and salt were removed. |
| `ctx` | string, optional | Name of the tool inside whose live execution this entry was recorded; replay absorbs such entries when it serves that tool from the record. Part of the chain body. |
| `hash` | string | Hash (per `alg`) of the canonical JSON of the entry's chain body. |

**Committed paths**: every top-level key of `data`; when a value is a
non-empty object, its second-level keys instead (path `parent.child`).
Path segments escape `~` as `~0` and `.` as `~1`, so dotted keys cannot
collide with nested paths. A dict emptied by redacting all its committed
sub-paths remains as an empty object.

The **chain body** is the entry without `hash`, `data`, `salts`, and
`redacted` — the chain commits to payloads only through `commitments`.

`run_meta` (environment fingerprint) opens SDK runs; `run_end` seals
them (its `steps` equals its own position + 1, and only `redaction`
and `repair` audit entries may follow it); `redaction` entries record
what was redacted, by whom, and when; `repair` entries record an
operator's explicit acceptance of truncated history.

## Chain verification

Starting from `prev = "0" * 64`, for each entry at index `i`:

1. `entry["v"]` is `2` and `entry["alg"]` is supported
2. `entry["run_id"]` equals the bundle `run_id`
3. `entry["step"] == i` and `entry["prev"] == prev`
4. `hash(alg, canonical(chain body)) == entry["hash"]`
5. For every path in `commitments`: if listed in `redacted`, the value
   must be absent; otherwise the value must be present and its salted
   commitment must match. Every present data path must be committed.
6. `prev = entry["hash"]`

Finally `chain.head_hash` must equal the last entry's `hash`. Any
failure identifies the exact broken step and path.

## Redaction

Removing a path's value and salt and listing the path in `redacted`
preserves chain verification: the commitment remains, attesting the
content existed, while the destroyed salt prevents dictionary attacks.
Redaction is per-field and survives signing (see below). `bitexact
redact` redacts the stored manifest itself, write-ahead: a chained
`redaction` audit entry naming the fields and the operator lands on
the chain before any value is destroyed, so a crash mid-redaction
leaves a recorded intent that verification flags until the redaction
is re-run to completion. Export-time redaction (`--redact-steps`)
instead produces a redacted copy for a recipient and leaves the store
— and its audit trail — untouched. Audit entries themselves cannot be
redacted.

## Checkpoints

Signed, sequence-numbered, hash-linked head attestations:

```json
{"run_id": "...", "seq": K, "steps": N, "head_hash": "<hex>",
 "prev_checkpoint": "<hex>", "alg": "...", "key_id": "<16 hex>",
 "ts": "...", "public_key": "<64 hex>", "signature": "<128 hex>"}
```

`signature` is ed25519 over the canonical JSON of `{"run_id", "seq",
"steps", "head_hash", "prev_checkpoint", "alg", "key_id"}`;
`prev_checkpoint` is the hash of the previous attested body under the
*previous checkpoint's own* `alg` (64 zeros for seq 0). Verifiers must
check that each checkpoint's `run_id` equals the bundle `run_id`,
contiguous `seq` from 0, chain links, every signature, `steps` within
the entry count, and the entry at `steps - 1` carrying `head_hash`.
Relying parties pin recorder identity with `--expect-recorder-key` or
a trust file; a verifier asked to require a recorder key **must fail**
a bundle that presents no checkpoints, or the requirement is
unenforced. Checkpoints presented together
cannot be forged, reordered, or thinned; that the newest were not
removed with the manifest tail is guaranteed by the bundle signature
below or an externally anchored head — never by local files alone.

## Anchors

External anchors pin a run's head *outside* its mutable store, so a
rollback the local store cannot detect fails against evidence a relying
party holds independently. The optional `anchors` array carries one record
per anchor. Each binds `{run_id, steps, head_hash}`: a verifier checks
that the anchor names the bundle's run and that the bundle still carries
that head at the anchored step; `steps` beyond the bundle's entry count is
a truncation failure. The bundle signature covers the anchor set (see
below), so anchors cannot be added or dropped after signing.

A **WORM anchor** is a recorder-signed head attestation, written to a
customer WORM / object-lock store:

| Field | Meaning |
|---|---|
| `type` | `"worm"`. |
| `run_id`, `steps`, `head_hash` | the attested run, its step count, and head. |
| `alg` | the head's hash algorithm. |
| `key_id`, `public_key` | recorder key identity (`key_id` is BLAKE2b-64 of the raw key). |
| `anchored_at` | ISO-8601 UTC time the anchor was written. |
| `signature` | ed25519 over the canonical JSON of `{type, run_id, steps, head_hash, alg, key_id, anchored_at}`. |

A relying party pins a WORM anchor to a recorder key with
`--expect-recorder-key` (the same key that signs checkpoints); an unpinned
WORM anchor still binds the head but is not attributed to a specific
recorder. Its `anchored_at` is recorder-asserted — the external, immutable
store, not this field, is what makes the head un-rewindable.

An **RFC 3161 anchor** carries an independent timestamp authority's token
over the head:

| Field | Meaning |
|---|---|
| `type` | `"rfc3161"`. |
| `run_id`, `steps`, `head_hash` | the attested run, its step count, and head. |
| `hash_alg` | the imprint algorithm, always `"sha256"`. |
| `token` | base64 DER RFC 3161 TimeStampToken (a CMS SignedData wrapping a TSTInfo). |

The token's message imprint is `SHA-256(bytes.fromhex(head_hash))` —
SHA-256 regardless of the head's own algorithm, so any TSA can anchor any
run. Verification checks the imprint against the bundle head, the TSA's
CMS signature over the signed attributes (whose message-digest and
content-type must match the TSTInfo), and that the signer certificate
carries the `timeStamping` extended key usage; a relying party pins the
authority with `--expect-tsa` (the signer must equal, or be directly
issued by, the pinned certificate). A timestamp is meant to outlive its
signing certificate, so certificate validity dates are not enforced —
revocation and PKI freshness are the relying party's concern.

An anchor proves a head existed and was not rolled back below it. Like the
rest of a bundle, it never asserts the captured trajectory is the complete
set of calls the agent made.

## Signature

```json
{"algorithm": "ed25519", "key_id": "<16 hex>", "public_key": "<64 hex>",
 "signed_at": "<ISO-8601>", "signature": "<128 hex>"}
```

The signature is ed25519 over the canonical JSON of `{"format",
"run_id", "chain", "signed_at", "key_id"}` plus `"checkpoints"` and
`"anchors"` when present. The chain head commits to every entry — redaction after
signing preserves the signature — and the checkpoint set, signing time,
and key identity are all pinned. `key_id` is BLAKE2b-64 of the raw
public key. A verifier given a trusted key (or trust file) must reject
an unsigned bundle. Trust files list `bundle_keys` and `recorder_keys`
as `{key_id, public_key}` entries, supporting rotation. A trust file
that is empty, misspells a key list, or omits `public_key` from an
entry must be rejected outright — a malformed trust file must never
silently constrain nothing.

## DSSE envelope

`bitexact export --format dsse` wraps the bundle as the predicate of an
in-toto Statement (`predicateType` `https://bitexact.dev/run/v1`,
subject digest pinning the chain head) inside a DSSE envelope
(`payloadType` `application/vnd.in-toto+json`, signatures over the DSSE
PAE with ed25519, `public_key` carried alongside each `keyid`). The
verifier consumes envelopes directly and applies every bundle check to
the embedded predicate.
