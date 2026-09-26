# BitExact bundle format, version 1

A bundle is a single UTF-8 JSON document exported from a recorded run.
It is verifiable independently of BitExact: the open-source verifier
(`verifier/`) implements exactly this document, and the fixtures in
`verifier/testdata/` are the conformance corpus for any other
implementation.

## Canonicalization — `bitexact-jcs/1`

All hashes and signatures are computed over RFC 8785 (JCS) canonical
JSON: object keys sorted by UTF-16 code units, ECMAScript
shortest-round-trip number formatting, minimal string escaping with
lone surrogates emitted as `\uXXXX` escapes, UTF-8 encoding, NaN and
Infinity rejected.

RFC 8785 alone is not sufficient for evidence, so this format is a named
**dialect** of it rather than plain conformance. Every value both
`bitexact-jcs/1` and RFC 8785 accept canonicalizes to exactly the bytes
RFC 8785 prescribes; values that a conformant implementation elsewhere
would canonicalize differently, or that would let two distinct values
share one commitment, are **refused at record time** instead of being
committed to. A refusal is a recording failure, which is visible; a
silent disagreement between two implementations is an untampered run
reported as tampered, which is not.

Each restriction in the table below refuses a value that a conformant
RFC 8785 implementation *would* canonicalize, because two such
implementations could disagree about it or it could let two values
share one commitment. In two places the dialect instead diverges from
RFC 8785 where RFC 8785's own behavior is unambiguous. Negative zero,
which RFC 8785 canonicalizes to `0` (errata 7920), is refused rather
than emitted, because `-0.0` and `0.0` would otherwise share one
commitment. Strings containing lone surrogates, which RFC 8785 §3.2.2.2
requires a compliant implementation to reject with an error, are instead
accepted and emitted as `\uXXXX` escapes — recorded model output can
contain them, and a value that cannot be recorded is a lost run. A
third-party implementation built on a strictly compliant JCS library
must relax that one rule to verify bundles whose data carries lone
surrogates.

The restrictions, and what each one prevents:

| Refused | Why |
|---|---|
| Duplicate object keys | Parsers disagree on which wins (RFC 8785 §3.1 forbids them but no canonicalizer can enforce it — the parser has already collapsed the repeat). The line would read differently to a different tool. |
| Nesting deeper than 128 | Otherwise the limit is wherever the reader's stack ends, so two installs reach different verdicts on the same bytes. A reader bounds a whole document at 128; a recorder therefore refuses entry `data` nested deeper than 125, the three wrapper levels (bundle, entries, entry) being what a JSON bundle adds around it, so anything recorded verifies in every reader. |
| Negative zero | RFC 8785 errata 7920: the spec's own rules emit `0` for both zeros, so `-0.0` and `0.0` would share one commitment. |
| Non-string object keys | JSON has none; coercing them lets `{1: "a"}` and `{"1": "a"}` collide, and `str(True)` is `True` where JSON writes `true`. |
| Keys colliding under surrogate folding | Two distinct Python keys that JSON cannot tell apart would emit a duplicate that re-parses lossily. |
| Integers a double does not reproduce | JSON numbers are doubles. An integer is accepted when the double it parses to reproduces its digits, and refused otherwise — so `10^18` is accepted (every parser reads it back identically) while `2^53 + 1` is refused (a parser elsewhere reads `9007199254740992`). \|n\| ≤ 2^53 − 1 is the range where this is guaranteed, but it is not the test: a flat threshold would refuse values every implementation agrees on, and would refuse the integer digits this format's own float rule emits at and above 2^53. Encode genuinely large integers as strings (RFC 8785 Appendix D). |

Two consequences worth stating plainly for anyone relying on this:

- RFC 8785 is an **Informational, Independent Stream** RFC. Its own
  Status of This Memo says the RFC Editor "makes no statement about its
  value for implementation or deployment." Citing it is a statement
  about byte format, not about endorsement.
- Cross-implementation byte-identity does **not** hold across every JCS
  implementation in the wild. The reference Java and C# ES6 number
  serializers are known to misformat subnormals
  (`cyberphone/json-canonicalization#34`, unfixed), and RFC 7638 sorts
  keys by code point where RFC 8785 sorts by UTF-16 code unit. This is
  why the vector corpus below, not the RFC alone, is the conformance
  target.

The vector corpus `testdata/jcs-vectors.json` is normative for
implementations: `cases` fixes the bytes for accepted values, and
`refused` fixes what must be rejected.

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
| `license_cert` | object, optional | The vendor-signed `bitexact-license/1` the recorder ran under (see *License provenance*). **Informational only** — it is not part of the bundle signature and is never consulted by integrity verification; a bundle with no cert verifies identically. |

## Entries

Each entry is one recorded step:

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | Entry format version; currently `2`. |
| `alg` | string | Hash algorithm identifier. |
| `run_id` | string | Same as the bundle `run_id`; verification fails on mismatch. |
| `step` | integer | 0-based position; must equal the entry's index. |
| `kind` | string | `http_call`, `tool_call`, `nondet`, `fork`, `injected`, `identity`, `context`, `human_decision`, `decision_record`, `marker`, `model`, `run_meta`, `run_end`, `redaction`, `repair`, `hold`, or `hold_release` — **enforced**: verifiers must refuse any other kind. `model` is a second-hand model call ingested from an observability feed (always `prov: asserted`). A `tool_call` may be `prov: observed` (captured through a wrapped client) or `prov: asserted` (an out-of-band `record_tool_call`); `human_decision` (a human approval/rejection/edit of an output, with an optional `binds_step`) and `marker` (an honest record of a known-uncaptured path) are always `prov: asserted`. `decision_record` (always `prov: asserted`) commits the run's governance policy about its output — an optional `retention_deadline` (ISO-8601 default purge date, distinct from an operational legal hold) with an optional `retention_basis` naming the schedule rule, `output_flags` (a dict of scalar flags such as `is_adverse_action`, `is_automated_decision`, `contains_pii`; each flag is its own committed, redactable path), and `reason_codes` (the principal reasons behind an adverse action). `identity` (always `prov: asserted`) records the run's asserted principal, agent, delegation, scope, and policy/model versions — plus, for the workflow model, the `workflow` name, `workflow_version` label, `environment`, `code` identity, and optional `workflow_instance` (business-case id), and a BitExact-computed `workflow_digest` (a fingerprint of the declared composition constituents — workflow/policy/prompt/model/code, deliberately excluding the version label and environment — so two runs claiming one `workflow_version` but carrying different digests are provably different compositions under one label). All are asserted evidence of who acted and under what workflow and authority, never an authentication of it; the digest fingerprints the declared identifier strings, not the underlying policy/prompt/code bytes. `context` (always `prov: asserted`) commits what the agent knew — its `data` carries a stable `name`, an always-present `content_hash` (hash of the canonical context, so hash-only survives redaction), and optional redactable `content` and a `source` label. `injected` (always `prov: synthetic`) marks a counterfactual response written by a response-mutation fork — explicitly not recorded upstream traffic; its data carries `source_step`, the replacement `response`, and `replaced_response` (the recorded response it displaced), and both the kind and the synthetic class are preserved through every descendant fork. |
| `prov` | string | Provenance class: `observed` (captured at a wrapped boundary — the proxy, a wrapped client, patched nondeterminism), `asserted` (committed by an explicit hook), or `synthetic` (a counterfactual response written by a response-mutation fork, never captured upstream). Part of the chain body, so relabeling or dropping it breaks the entry hash; verification rejects any other value. |
| `ts` | string | ISO-8601 instant with a UTC offset (`2026-09-02T00:00:00+00:00`) at recording time — **enforced**: verifiers must refuse a `ts` that is not an ISO-8601 instant carrying an offset. |
| `prev` | string | The previous entry's `hash`; 64 zeros for step 0 (genesis). |
| `data` | object | Kind-specific payload; individual fields may be redacted. |
| `salts` | object | Per-path 16-byte hex salts — **enforced**: a salt of any other length is refused, named as the salt; a redacted path's salt is destroyed. Absent when every path is redacted. |
| `commitments` | object | Per-path salted commitments — keyed BLAKE2b-256 (or HMAC-SHA256) over the canonical value. Always complete. |
| `redacted` | array | Paths whose value and salt were removed — **enforced**: every listed path must be one this entry committed, and its salt must be gone; a marker naming an uncommitted path, or one whose salt survives, is refused. |
| `ctx` | string, optional | Name of the tool inside whose live execution this entry was recorded - a nondeterminism read, a nested tool, or a model call the tool made through a wrapped client, which forwards the active tool frame to the recorder in the `X-BitExact-Ctx` request header. Replay absorbs such entries when it serves that tool from the record, so a tool that talks to the model replays without re-executing. Part of the chain body. |
| `hash` | string | Hash (per `alg`) of the canonical JSON of the entry's chain body. |

**Committed paths**: every top-level key of `data`; when a value is a
non-empty object, its second-level keys instead (path `parent.child`).
Path segments escape `~` as `~0` and `.` as `~1`, so dotted keys cannot
collide with nested paths. A dict emptied by redacting all its committed
sub-paths remains as an empty object.

The **chain body** is the entry without `hash`, `data`, `salts`, and
`redacted` — the chain commits to payloads only through `commitments`.

**Provenance per kind (enforced).** The class an entry carries is fixed by
its kind, and a verifier must refuse any other pairing — a `prov` label is
inside the entry hash, so on a keyless bundle relabelling is free, and this
rule is what stops an `injected` counterfactual being re-chained as an
observed `http_call`, or an operator's assertion being presented as
something the recorder saw:

| Kinds | `prov` |
|---|---|
| `run_meta`, `run_end`, `fork`, `http_call`, `nondet` | `observed` |
| `tool_call` | `observed` (a wrapped tool) or `asserted` (`record_tool_call`) |
| `identity`, `context`, `human_decision`, `decision_record`, `marker`, `model`, `redaction`, `repair`, `hold`, `hold_release` | `asserted` |
| `injected` | `synthetic` |

The recorder applies the same table when it writes: an entry of a kind
that cannot carry the requested class is refused at write time, so the
product never produces evidence every verifier refuses.

`run_meta` (environment fingerprint) opens SDK runs (informative: its
position is not verified — a run that opens otherwise verifies
identically) — its data also carries a non-authoritative `watermark`
(`license_id`, `image_digest`, and an opaque deployment `fingerprint`)
committed for attribution: it is part of the hash chain (so altering it
is detectable) but is never consulted in verification, and a run without
it verifies identically;
`run_end` seals
them (its `steps` equals its own position + 1, and only the audit kinds
`redaction`, `repair`, `hold` and `hold_release` may follow it);
`redaction` entries record what was redacted, by whom (`by`, and under
dual control `requested_by`), and when; `repair` entries record an
operator's explicit acceptance of truncated history; `hold` places a
legal hold (`reason`, `by`, `placed_at`) and `hold_release` lifts it
(`by`, `released_at`) - the hold in force is the last `hold` with no
`hold_release` after it, so it lives in the chain and nothing outside
the chain can lift it. Every audit entry a signing recorder appends
past the seal is covered by a fresh checkpoint. The *content* of the
audit entries (`fields`, `by`, `reason`, timestamps) is informative:
verifiers consult only a `redaction` entry's `fields`; the rest is
committed, hash-covered evidence the reader interprets.

## Chain verification

Starting from `prev = "0" * 64`, for each entry at index `i`:

1. `entry["v"]` is `2` and `entry["alg"]` is supported
2. `entry["run_id"]` equals the bundle `run_id`
3. `entry["step"] == i` and `entry["prev"] == prev`
4. `hash(alg, canonical(chain body)) == entry["hash"]`
5. `entry["prov"]` is `observed`, `asserted`, or `synthetic`
6. For every path in `commitments`: if listed in `redacted`, the value
   must be absent; otherwise the value must be present and its salted
   commitment must match. Every present data path must be committed.
7. `prev = entry["hash"]`

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
redacted — **enforced**: a `redaction`, `repair`, `hold` or
`hold_release` entry carrying a `redacted` marker is refused.

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
the entry count, and the entry at `steps - 1` carrying `head_hash`;
they must refuse a checkpoint whose `alg` is not a supported algorithm
(a null `alg` signed as null is not hashable unambiguously) and one whose
`key_id` is not BLAKE2b-64 of its own `public_key` (**enforced**). The
checkpoint `ts` is outside the attested body: informative, never
verified.
Relying parties pin recorder identity with `--expect-recorder-key` or
a trust file. A verifier asked to require a recorder key **must fail**
a bundle that presents no checkpoints or WORM anchors, and **must fail**
a bundle whose head is not covered by a checkpoint or WORM anchor signed
with that key — whether or not the bundle carries a signature, and
whatever key that signature is under. The bundle signature is the
exporter's attestation; it never stands in for the recorder's, because
the exporter holds store access and is the party the recorder tier
exists to distrust. Checkpoints presented together cannot be forged,
reordered, or thinned; that the newest were not removed with the
manifest tail is guaranteed by a head-covering checkpoint or an
externally anchored head — never by local files alone.

Every tier, pinned or not, **must fail** a *sealed* bundle that carries
checkpoints but none covering its head. A recorder that signs mints a
head-covering checkpoint at the seal and after every audit entry it
appends past it (a redaction claim, a repair record, a legal hold), so a
sealed run whose head no checkpoint covers has a tail written without
the key. An unsealed run legitimately has entries past its last periodic
checkpoint; the verdict says `unsealed - end not attested` for it, and
`--require-sealed` turns that into a failure.

When a recorder key is pinned, redaction must be **accountable**:
every `redacted` marker must be backed by an on-chain `redaction` claim
entry naming `step:path`, signed bundle or not. `bitexact redact` writes
that claim and mints a fresh head-covering checkpoint over the new head,
so an authorized redaction re-verifies; a keyless strip — a marker with
no claim, which leaves the entry hash, the head, and its checkpoint
unchanged — is refused as an unaccountable withholding. A forged claim
cannot rescue the strip: appending it advances the head past the last
checkpoint, which the head-coverage rule then rejects. Export-time
redaction (`--redact-steps`) carries no claim, so a recipient who needs
recorder authentication of a redacted run must redact the store first.
The plain (no-key) verdict asserts no authenticity and keeps the
export-redaction exemption; the bundle signature (below) binds the
marker set for the exporter's tier only.

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
| `key_id`, `public_key` | recorder key identity (`key_id` is BLAKE2b-64 of the raw key — **enforced**: a `key_id` that does not derive from `public_key` is refused). |
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
| `hash_alg` | the imprint algorithm, always `"sha256"` — **enforced**: any other declared value is refused; the token's own imprint algorithm is checked independently. |
| `nonce` | optional; the request nonce the anchor was obtained with — **enforced** when present: the token's `nonce` must equal it, so a replayed token for an earlier request is refused. |
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
"run_id", "chain", "signed_at", "key_id"}` plus `"checkpoints"`,
`"anchors"`, and `"redactions"` when present. The chain head commits to
every entry's committed values; the signature additionally binds the
redaction markers as `"redactions"` — a map of `str(entry index)` to the
sorted `redacted` path list, present only when some entry is redacted — so
a committed field cannot be suppressed after signing. `redacted` is
excluded from the entry hash, so without this a party holding no key could
add a marker and strip a value while the signature stayed valid; a
legitimate redaction is applied before signing (or the bundle is re-signed)
and is covered. The checkpoint set, signing time, and key identity are all
pinned. `key_id` is BLAKE2b-64 of the raw public key (**enforced** when
present: a `key_id` that does not derive from `public_key` is refused).
Each `redactions` path list is sorted by Unicode code point (Python's
`sorted`; a JavaScript implementation must not rely on the default
`Array.prototype.sort`, which compares UTF-16 code units and differs for
astral characters). Hex keys compare case-insensitively wherever a
verifier pins one. A verifier given a
trusted key (or trust file) must reject an unsigned bundle. Trust files list `bundle_keys` and `recorder_keys`
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
the embedded predicate. **Enforced**: a run envelope whose statement
`predicateType` is not `https://bitexact.dev/run/v1` is refused, and a
signature entry whose `keyid` is present but is not BLAKE2b-64 of its
`public_key` is refused.

## Provenance bundle (BagIt)

`bitexact provenance-bundle <run>` packages a run and every fork that
branches from it (transitively), plus any fork-matrix reports, as a
single independently-verifiable **BagIt 1.0** bag (RFC 8493):

```
<bag>/
  bagit.txt                    BagIt-Version: 1.0
  bag-info.txt                 External-Identifier: <root run_id>, Payload-Oxum
  manifest-sha256.txt          sha256 of every file under data/
  tagmanifest-sha256.txt       sha256 of the tag files above
  data/
    runs/<run_id>.bundle.json  one bitexact-bundle/1 (optionally signed) per run
    fork-matrix/<...>.json      fork-matrix reports, verbatim
    provenance-graph.json       the cross-run graph (below)
    attestations/provenance.dsse.json   signed graph attestation (with --sign)
```

`provenance-graph.json` (`format` `bitexact-provenance-graph/1`) lists
the `root`, the `nodes` (each `run_id`, its `bundle` path, `head_hash`,
and `role` — `original` for a run with no in-bag source, `fork` for one
whose committed fork entry names an in-bag source),
the `edges` (`child`, `source_run`, `at_step`, `source_prev_hash`),
`fork_matrices`, and `excluded` — descendants the producer left out, each
with a `reason` (`unsealed`: a fork that never sealed tested nothing and
is not evidence; a bag carrying one would not verify). `excluded` is
informative: the verifier proves the runs that are present, and an
auditor who wants a left-out run asks for it by id.

The graph is verified from **authority the bag cannot forge**: each
fork's committed `fork` entry (signed inside its own run bundle) carries
`source_run`, `at_step`, and `source_prev_hash` — the source's committed
entry hash at `at_step - 1` (a *prefix commitment*, `GENESIS` at step 0).
The verifier re-derives that hash from the source's own verified entries
in the bag and requires it to match, so a rewritten or truncated source
is caught; it then requires the whole set to be one tree rooted at
`root`, with no cycles and no run left unconnected. The
`attestations/provenance.dsse.json` envelope signs an in-toto Statement
whose `predicateType` is `https://bitexact.dev/provenance-graph/v1`,
predicate is the graph, and subject list pins every run's head — binding
the *set* of runs under one signature, so hiding a fork is detectable.
**Enforced listing rules**: `bag-info.txt`'s `External-Identifier` must
equal the graph `root`; each node's `role` must be what its own fork
entry makes it; and `edges` must be exactly the fork relationships the
bundles commit to (each `child`, `source_run`, `at_step`,
`source_prev_hash` re-derived from the committed entries) — no edge
missing, none invented. What the bag says about itself must be what its
runs prove. Informative, not verified: the `runs/<run_id>.bundle.json`
naming convention (the graph's `bundle` path is authoritative), and the
content of `fork-matrix/` reports, which are copied verbatim and are
covered by the payload manifest only.

The standalone verifier checks a bag directly:
`python bitexact_verifier.py <bag-dir> [--expect-key HEX | --trust-file f]`.

## Streamed form — `bitexact-bundle-jsonl/1`

`bitexact export --format jsonl` writes the same evidence as one JSON
object per line so a GB-scale run verifies without being held in memory:

```
{"format": "bitexact-bundle-jsonl/1", "run_id": ..., "chain": {...},
 "checkpoints": [...], "anchors": [...], "signature": {...}, "license_cert": {...}}
<entry 0>
<entry 1>
...
```

The first non-blank line is the header — the top-level object without
`entries` — and every following non-blank line is one entry, in step
order. Blank lines are skipped and CRLF line endings are tolerated. A
line that is not JSON is refused naming its line number. Every rule of
the object form applies unchanged: the same chain, seal, redaction,
checkpoint, anchor and signature checks, the same signed body (a JSONL
signature is over `"format": "bitexact-bundle-jsonl/1"`), and the same
verdict.

## License provenance

`license_cert` is the vendor-signed `bitexact-license/1` document the
recorder ran under: `{"license_id", "licensee", "expires", "tier",
"entitlements", "recorder_keys": [<hex>...], "scope"?, "signature"}`,
signed by the BitExact vendor key over the canonical JSON of every field
but `signature`. It is informational: outside the bundle signature,
never consulted by integrity verification, and advisory only.
`bitexact_verifier.py --vendor-key HEX` prints a report after the
verdict and never changes it: whether the vendor signature verifies,
whether the licence has expired (evaluated against the verifier's clock,
so it is a hint, not an attestation), and whether the run's recorder
key (from its checkpoints or WORM anchors) is one the licence names —
a run signed by a key the licence does not cover reads as a possible
licence replay.
