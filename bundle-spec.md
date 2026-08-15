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

### v1 entries (compatibility)

Entries written by pre-1.2 releases carry `v: 1` and commit to the
whole payload at once: `data_hash` is BLAKE2b-256 over
`salt || canonical(data)` with a single 16-byte hex `salt`, the chain
body excludes `hash`, `data`, `salt`, and `redacted` (so it includes
`data_hash`), and canonical bytes are Python `json.dumps` with sorted
keys and `,`/`:` separators — not RFC 8785. A redacted v1 entry has
`data` and `salt` removed and `redacted: true`. Verifiers must verify
each entry under its own version's scheme; evidence outlives releases.
v1 bundle signatures cover only `{"format", "run_id", "chain"}` (plus
`"checkpoints"` when present) — a signature without `signed_at`/
`key_id` fields is verified against that legacy body. v1 checkpoints
omit `alg`/`key_id` from the attested body.

## Chain verification

Starting from `prev = "0" * 64`, for each entry at index `i`:

1. `entry["v"]` is `2` (or `1`, verified under the v1 scheme above)
   and `entry["alg"]` is supported
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

## Signature

```json
{"algorithm": "ed25519", "key_id": "<16 hex>", "public_key": "<64 hex>",
 "signed_at": "<ISO-8601>", "signature": "<128 hex>"}
```

The signature is ed25519 over the canonical JSON of `{"format",
"run_id", "chain", "signed_at", "key_id"}` plus `"checkpoints"` when
present. The chain head commits to every entry — redaction after
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
