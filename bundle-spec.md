# BitExact bundle format

A bundle is a single UTF-8 JSON document exported from a recorded run.
It is verifiable independently of BitExact: the open-source verifier
(`verifier/`) implements exactly this document, and the fixtures in
`verifier/testdata/` are the conformance corpus for any other
implementation.

## Canonicalization — `aer-jcs`

All hashes and signatures are computed over RFC 8785 (JCS) canonical
JSON: object keys sorted by UTF-16 code units, ECMAScript
shortest-round-trip number formatting, minimal string escaping with
lone surrogates emitted as `\uXXXX` escapes, UTF-8 encoding, NaN and
Infinity rejected.

RFC 8785 alone is not sufficient for evidence, so this format is a named
**dialect** of it rather than plain conformance. Every value both
`aer-jcs` and RFC 8785 accept canonicalizes to exactly the bytes
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
| `format` | string | Exactly `"aer-bundle"`. |
| `run_id` | string | The recorded run's identifier — **enforced**: a `run_id` that is not a string is refused. The recorder mints only ids matching `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` (a letter or digit, then up to 63 letters, digits, `.`, `_` or `-`); verifiers do not check that syntax. |
| `entries` | array | The run's manifest entries, in step order (see below). |
| `chain` | object | `{"head_hash": <hex>}` — the `hash` of the final entry. |
| `checkpoints` | array, optional | Signed head attestations (see below). |
| `anchors` | array, optional | External head anchors (see below). |
| `tlog` | object, optional | Proof that the head checkpoint is in the deployment's transparency log (see below). |
| `signature` | object, optional | Detached ed25519 signature (see below). |
| `license_cert` | object, optional | The vendor-signed `bitexact-license` the recorder ran under (see *License provenance*). **Informational only** — it is not part of the bundle signature and is never consulted by integrity verification; a bundle with no cert verifies identically. |
| `causal_order` | object, optional | Present when the run was recorded from more than one host: `{"steps": [...], "cycle": [...]}`, the step numbers in the order they happened — each source's own `seq`, the `caused_by` links in each entry's `aer_source` block, then its `hlc`, ties by chain position — and the steps caught in a cycle, listed last in chain order. The streamed format carries it in its header line. **Informational only** — derived from fields inside each entry's hash, so a reader derives it again rather than trusting it; it is not part of the bundle signature, what it rests on is asserted by the hosts, and `entries` stay in chain order. |

## Entries

Each entry is one recorded step:

| Field | Type | Meaning |
|---|---|---|
| `alg` | string | Hash algorithm identifier. |
| `run_id` | string | Same as the bundle `run_id`; verification fails on mismatch. |
| `step` | integer | 0-based position; must equal the entry's index (**enforced**; `true` and `false` are not integers - see Integers). |
| `kind` | string | `http_call`, `tool_call`, `policy_check`, `nondet`, `fork`, `injected`, `identity`, `context`, `human_decision`, `decision_record`, `marker`, `model`, `run_meta`, `run_end`, `redaction`, `repair`, `hold`, or `hold_release` — **enforced**: verifiers must refuse any other kind. `policy_check` records that a named safety or policy check ran: `check` (its name), `outcome` (`pass`, `fail`, `warn`, `error` or `unknown`), and optional `version`, `subject_step` (the step it judged) and `detail`; `prov: observed` when the check ran in a wrapped function (`record_check`), `prov: asserted` when it was reported by a hook (`record_policy_check`). Replay re-runs a check and never serves it from the record. `model` is a second-hand model call ingested from an observability feed (always `prov: asserted`). A `tool_call` may be `prov: observed` (captured through a wrapped client) or `prov: asserted` (an out-of-band `record_tool_call`); `human_decision` (a human approval/rejection/edit of an output, with an optional `binds_step`) and `marker` (an honest record of a known-uncaptured path) are always `prov: asserted`. A `marker` whose `data.gap` is an object is a **declared capture gap**: the recorder's own record that it did not capture something it should have, with `cause` (one of `license_lapsed`, `signing_key_missing` (a valid license bound to a recorder key that is not configured), `recorder_key_unlicensed` (a configured recorder key the license does not name), `build_modified` (the installed build's files are not the ones its release signed), `payload_oversize`, `storage_unavailable`, `adapter_unavailable` (a framework adapter that failed to load or attach, so what it would have captured was not recorded), `serialization`, `invalid_argument`, `recorder_unavailable`, `run_id_rejected`, `run_not_owned` (a call through the proxy named a run another writer opened; it is forwarded and recorded nowhere, so this cause appears only in the proxy's log and counters, never on a chain), `journal_failed`, `run_ended`, `run_context_lost`, `spool_overflow`, `queue_overflow`, `intake_rejected`, `source_gap`, `source_conflict`, `late_after_gap`, `causal_inconsistency`, `token_rejected` (a write the run token it carried did not authorize and no fresh token could: the token did not grant the kind, or was delegated and had expired or been revoked; the gap takes the event's place and carries its `aer_source`), `checkpoint_failed` (the recorder key could not sign the checkpoint after an entry was stored - an HSM gone, a post-quantum half that failed), `scrub_failed` and `capture_key_unavailable` (declared per field in an entry's `capture` block, never as a marker - see Capture controls), `capture_policy_invalid` (the capture policy in force cannot be used, so no run opens: noted on the refusal ledger, never on a chain), `unclassified`), `where`, `policy`, and `withheld` (`bytes` or `length` of content it did not store, or null; never an unkeyed digest of it, from any source - the digest is keyed with the capture key, as `keyed`, `nonce` and `key_id`, or dropped as `"digest": "dropped: no capture key"` when no capture key or no capture policy is in force, or, when the key is held in a PKCS#11 token that did not answer, taken out and declared in the entry's `capture` block as the field `gap.withheld` with mode `withheld` and cause `capture_key_unavailable`, a declared gap; a capture policy that cannot be read at all leaves `"digest": "dropped: capture key unavailable"`). A gap a remote source declared, a source's attempt to rewrite a seq it already sent (`source_conflict`), or content a source sent for a seq it had declared lost (`late_after_gap`: the loss stands, the content is not stored, its hash is in `withheld`) also names `seqs` (`[first, last]`). A verifier reports declared gaps beside its verdict: the chain is intact, the capture is not complete. `decision_record` (always `prov: asserted`) commits the run's governance policy about its output — an optional `retention_deadline` (ISO-8601 default purge date, distinct from an operational legal hold) with an optional `retention_basis` naming the schedule rule, `output_flags` (a dict of scalar flags such as `is_adverse_action`, `is_automated_decision`, `contains_pii`; each flag is its own committed, redactable path), and `reason_codes` (the principal reasons behind an adverse action). `identity` (always `prov: asserted`) records the run's asserted principal, agent, delegation, scope, and policy/model versions — plus, for the workflow model, the `workflow` name, `workflow_version` label, `environment`, `code` identity, and optional `workflow_instance` (business-case id), and a BitExact-computed `workflow_digest` (a fingerprint of the declared composition constituents — workflow/policy/prompt/model/code, deliberately excluding the version label and environment — so two runs claiming one `workflow_version` but carrying different digests are provably different compositions under one label). All are asserted evidence of who acted and under what workflow and authority, never an authentication of it; the digest fingerprints the declared identifier strings, not the underlying policy/prompt/code bytes. `context` (always `prov: asserted`) commits what the agent knew — its `data` carries a stable `name`, either redactable `content`, committed like any field (no plain hash of it is stored beside it, so a redacted value cannot be guessed back), or a caller-supplied `content_hash`, which is the caller's own claim, and an optional `source` label. `injected` (always `prov: synthetic`) marks a counterfactual response written by a response-mutation fork — explicitly not recorded upstream traffic; its data carries `source_step`, the replacement `response`, and `replaced_response` (the recorded response it displaced), and both the kind and the synthetic class are preserved through every descendant fork. |
| `prov` | string | Provenance class: `observed` (captured at a wrapped boundary — the proxy, a wrapped client, patched nondeterminism), `asserted` (committed by an explicit hook), or `synthetic` (a counterfactual response written by a response-mutation fork, never captured upstream). Part of the chain body, so relabeling or dropping it breaks the entry hash; verification rejects any other value. |
| `ts` | string | The recording time, written by the recorder as `2026-09-02T00:00:00.123456+00:00` — **enforced**: an RFC 3339 `date-time` in exactly this grammar, and nothing else: `YYYY-MM-DD`, an upper-case `T`, `HH:MM:SS`, an optional `.` and one or more digits, then an upper-case `Z` or a `+HH:MM` / `-HH:MM` offset, all digits ASCII; the date a real calendar date, the hour `00`-`23`, minute and second `00`-`59` (no leap second), the offset hour `00`-`23` and minute `00`-`59`. Lower-case `t` or `z`, a space for `T`, the basic format (`20260902T000000Z`), week or ordinal dates, a missing seconds field, an offset without its colon, `24:00` and a missing offset are refused. |
| `prev` | string | The previous entry's `hash`; 64 zeros for step 0 (genesis). |
| `data` | object | Kind-specific payload; individual fields may be redacted — **enforced**: always present, `{}` when the step recorded nothing; an entry without `data`, or with a `data` that is not an object, is refused. |
| `salts` | object, optional | Per-path 16-byte hex salts — **enforced**: a salt of any other length is refused, named as the salt; a redacted path's salt is destroyed. May be absent when no path holds a stored value that needs one (every path redacted, hash-only or withheld). |
| `commitments` | object | Per-path salted commitments — keyed BLAKE2b-256 (or HMAC-SHA256) over the canonical value — **enforced**: always present, `{}` when `data` is empty; an entry without `commitments`, or with one that is not an object, is refused. Complete: every present data path is committed, and every committed path's value is present, redacted, or declared never stored (see Chain verification). |
| `redacted` | array, optional | Paths whose value and salt were removed; absent until a path is redacted — **enforced**: an empty list is refused; every listed path must be one this entry committed, and its salt must be gone; a marker naming an uncommitted path, or one whose salt survives, is refused. |
| `capture` | object, optional | What the capture policy kept of the entry's fields: exactly `policy` (the policy's digest), `applied_by` (`recorder`, or the collector's source id) and `fields`, a non-empty object of each declared path's outcome. Part of the chain body. Absent when every field was kept as captured and none was claimed cleaned upstream. See Capture controls for its exact shape. |
| `ctx` | string, optional | Name of the tool inside whose live execution this entry was recorded - a nondeterminism read, a nested tool, or a model call the tool made through a wrapped client, which tells the recorder the tool frame active when it made the call. Replay absorbs such entries when it serves that tool from the record, so a tool that talks to the model replays without re-executing. Part of the chain body. |
| `via` | string, optional | The capture path the entry came through: `proxy`, `sdk-python`, `sdk-ts`, `sdk-go`, `sdk-java`, `otel`, `langchain`, `openai-agents`, `claude-agent-sdk`, `adk`, `auditant`, `llamaindex`, `vapi`, `mcp-proxy` or `governance` (an adapter's entries and gap markers name the adapter, the MCP proxy's its own path, and every SDK's governance-decision API's `governance`, whichever engine `data.reported_by` names) for a writer that wrote it into the store in process, or `relay:` and one of those (`relay:sdk-ts`) for an event the recorder took from a collector. Absent when the writer named no path: an operator's act, or a relayed event that named no `sdk` label. Part of the chain body, so altering it breaks the entry hash, but the writer asserts it: it is attribution, never proof. Informative: a verifier never refuses an entry for its `via`, and prints the per-path mix of a verified chain's entries after its verdict, the `run_end` seal excepted: it closes the chain rather than capturing anything, and its `sealed_by` names who wrote it (`captured via proxy 12, relay:sdk-ts 4 (attribution, not proof)`). |
| `hash` | string | Hash (per `alg`) of the canonical JSON of the entry's chain body. |

**Committed paths**: every top-level key of `data`; when a value is a
non-empty object, its second-level keys instead (path `parent.child`).
Path segments escape `~` as `~0` and `.` as `~1`, so dotted keys cannot
collide with nested paths. A dict emptied by redacting all its committed
sub-paths remains as an empty object.

The **chain body** is the entry without `hash`, `data`, `salts`, and
`redacted` — the chain commits to payloads only through `commitments`.

**Integers (enforced).** Every member this document calls an integer - an
entry's `step`, a checkpoint's `seq` and `steps`, an anchor's `steps`, a
`run_end`'s `data.steps`, a `fork`'s `data.at_step`, a log proof's `index`
and `size` - is a JSON number; `true` and `false` are never integers, and
a verifier refuses one wherever an integer is required, whatever its
language makes of `true == 1`. Where a verifier compares a value it read
with one it computed (the signed ledger heads, the graph's edge listing,
an attestation's predicate), two values are equal exactly when their
canonical JSON is equal, so `true` is never `1`.

**Provenance per kind (enforced).** The class an entry carries is fixed by
its kind, and a verifier must refuse any other pairing — a `prov` label is
inside the entry hash, so on a keyless bundle relabeling is free, and this
rule is what stops an `injected` counterfactual being re-chained as an
observed `http_call`, or an operator's assertion being presented as
something the recorder saw:

| Kinds | `prov` |
|---|---|
| `run_meta`, `run_end`, `fork`, `http_call`, `nondet` | `observed` |
| `tool_call` | `observed` (a wrapped tool) or `asserted` (`record_tool_call`) |
| `policy_check` | `observed` (a wrapped check) or `asserted` (`record_policy_check`) |
| `identity`, `context`, `human_decision`, `decision_record`, `marker`, `model`, `redaction`, `repair`, `hold`, `hold_release` | `asserted` |
| `injected` | `synthetic` |

The recorder applies the same table when it writes: an entry of a kind
that cannot carry the requested class is refused at write time, so the
product never produces evidence every verifier refuses.

`run_meta` opens every run the product writes — an SDK run, and a run the
recording proxy or the recorder is the first to write — and its position is
not verified: a run that opens otherwise verifies identically. Its data
always carries `capture_policy` and `standing` (see Capture controls),
which the product adds to every `run_meta` whatever its writer supplied. A
verifier reads each `run_meta` in a chain as the opening of one run: each
counts one run in the capture clause and states one standing. An SDK run's
`run_meta` also carries its environment fingerprint (`python`, `platform`,
`recorder_version`) and a non-authoritative `watermark`
(`license_id`, `image_digest`, and an opaque deployment `fingerprint`)
committed for attribution: it is part of the hash chain (so altering it
is detectable) but is never consulted in verification, and a run without
it verifies identically;
`run_end` seals
them (**enforced**: its `data.steps` is an integer equal to its own
position + 1, only the audit kinds `redaction`, `repair`, `hold` and
`hold_release` may follow it, and a `run_end` carrying a `redacted` marker
is refused - the seal commits the step count the run is verified against,
and the recorder refuses to redact it; its informative `sealed_by` names
who wrote it: `sdk`, `recorder` or `operator`); a `fork` entry records
that the run continues another (see Provenance bundle) - **enforced**: a
run carries at most one, and a second is refused, so no reader has to
choose which one counts (the recorder writes it after the run's
`run_meta` and any `identity` entry);
`redaction` entries record what was redacted, by whom (`by`, and under
dual control `requested_by`), and when; `repair` entries record an
operator's explicit acceptance of truncated history; `hold` places a
legal hold (`reason`, `by`, `placed_at`) and `hold_release` lifts it
(`reason`, `by`, `released_at`) - the hold in force is the last `hold` with no
`hold_release` after it, so it lives in the chain and nothing outside
the chain can lift it. Every audit entry a signing recorder appends
past the seal is covered by a fresh checkpoint. A `run_end`, `redaction`,
`hold` or `hold_release` the recorder wrote because a peer asked for it
also carries `submitted_by` in its data: the identity in the client
certificate of the mTLS connection the request arrived on, which the
recorder writes and the peer cannot state. `by` and `requested_by` are
what that peer asserts; `submitted_by` is who asserted it, so two halves
of a two-person act that one certificate submitted are seen to be one
submitter's. An entry written in the recorder's own process carries none.
Where the recorder verified the person behind the act (Verified identity,
below), a `hold`, `hold_release` or `redaction` also carries
`verified_identity` for its `by`, and a `redaction` approved under
two-person control carries `requested_identity` for its `requested_by`.
**Enforced**: each is a verified identity of the principal it stands
beside; `requested_identity` appears only on a `redaction`, and only with
`verified_identity`; and the two are not one person - the same `issuer`
and `subject` - so a two-person approval one person made fails, whatever
names its `by` and `requested_by` give. The rest of the *content* of the
audit entries (`fields`, `by`, `reason`, `submitted_by`, timestamps) is
informative: verifiers consult only a `redaction` entry's `fields`; the
rest is committed, hash-covered evidence the reader interprets, and the
reading view shows `submitted_by`, and the subject and issuer of each
verified identity, beside the step it is on.

### Verified identity

A recorder configured to verify who acts checks the OpenID Connect ID token
the person's sign-in produced - its signature against the issuer's keys, its
issuer, audience and validity window - and records what it verified, never
the token, as an object of exactly four non-empty strings:

| Field | Value |
|---|---|
| `issuer` | the token's `iss` |
| `subject` | the token's `sub` |
| `claim` | the claim the principal was taken from: `sub` or `email` |
| `principal` | that claim's value: the principal the record names |

**Enforced** wherever one lands on a chain (an audit entry's data, above;
a ledger event, under Ledgers): exactly these fields, each a non-empty
string; `claim` is `sub` or `email`; with `sub`, `principal` equals
`subject`; and `principal` equals the principal of the record it stands
beside (`by`, or for `requested_identity` the `requested_by`). Two verified
identities are one person when their `issuer` and `subject` are equal,
whatever their principals. A record with none names a principal its
submitter asserted.

## Chain verification

Starting from `prev = "0" * 64`, for each entry at index `i`, in this
order (the first that fails is the verdict, named `step i: ...`):

1. The entry is a JSON object.
2. Its chain body canonicalizes (`step i: entry cannot be canonicalized`).
3. `entry["alg"]` is supported.
4. `entry["run_id"]` equals the bundle `run_id`.
5. `entry["step"]` is the integer `i`.
6. `entry["prev"] == prev`.
7. `hash(alg, canonical(chain body)) == entry["hash"]`.
8. `entry["prov"]` is `observed`, `asserted`, or `synthetic`.
9. `kind` is in the vocabulary and `prov` is a class that kind may carry
   (Provenance per kind).
10. `ts` is an RFC 3339 date-time as the `ts` row states.
11. An audit entry or a `run_end` carries no `redacted` marker.
12. `data` and `commitments` are objects, `salts` (when present) an
    object, and `redacted` (when present) an array of strings.
13. The `capture` block, if present, holds (Capture controls).
14. Every `redacted` path is one `commitments` names.
15. For every path in `commitments`: if listed in `redacted`, the value
    and its salt must be absent; if the `capture` block declares it
    `hash-only` or `withheld`, it is skipped (step 13 checked that it holds
    no value, salt or marker); otherwise the value must be present, its
    salt a 16-byte hex string, and its salted commitment must match.
16. Every present data path is committed (a top-level object emptied by
    redacting every committed child excepted).
17. The run rules: no entry but an audit kind after a `run_end`; a
    `run_end`'s `data.steps` is the integer `i + 1`; no second `fork`
    entry.
18. `prev = entry["hash"]`

A bundle carries at least one entry — **enforced**: a bundle with no
entries is refused, since an empty chain is not evidence of a run, and the
exporter refuses to export a run with none, in every format. Then, in
order: `chain.head_hash` must equal the last entry's `hash`; the run's
stated standing is checked (Capture controls); every redaction claim is
applied (Redaction); at the recorder tier every marker has its claim; and
the checkpoints, anchors, bundle signature and transparency-log proof are
checked as their sections state. Any failure in the entries identifies
the exact broken step and path.

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

**Claims (enforced).** A `redaction` entry's `data.fields` is its claim:
an array whose string members are `<step>:<path>` tokens, `<step>` the
claimed entry's index in ASCII decimal with no leading zero (`0`, `7`,
`12`, never `07`) and `<path>` everything after the first `:`. A member
that is not a string, or a token whose step is not written that way or
names no entry of the run, is not a claim and is ignored. Every claim
must be applied - its step's `redacted` lists its path - or the bundle
fails (`redaction of <token> recorded but not applied`). At the recorder
tier every marker must be backed by the claim token written exactly as
`<step>:<path>`. No other member of a `redaction` entry is consulted.

## Capture controls

A capture policy decides what of each field is kept before anything is
written, at the one place every entry is built and where every remote
event enters a host's collector. Every outcome other than keeping the
value is declared in the entry's `capture` block, inside the chain body:

```json
"capture": {
  "policy": "b2:<BLAKE2b-256 of the policy's canonical JSON>",
  "applied_by": "recorder",
  "fields": {
    "response.text": {"mode": "scrub", "found": {"pan": 1}},
    "request.body":  {"mode": "hash-only", "nonce": "<32 hex>",
                      "key_id": "<32 hex>", "alg": "blake2b-256"},
    "body.b64":      {"mode": "unscanned"},
    "result.note":   {"mode": "scrubbed-upstream", "by": "presidio"},
    "args":          {"mode": "withheld", "cause": "scrub_failed",
                      "reason": "time budget exceeded", "detector": "pan"}
  }
}
```

The block has exactly these three members — **enforced**: a block with
any other member or a missing one, a `policy` or `applied_by` that is not
a string, or a `fields` that is not a non-empty object is refused. The
producer writes `policy` as `b2:` and the lowercase hex BLAKE2b-256 of the
policy's canonical JSON; a verifier checks only that it is text. Each key
of `fields` is a committed path (see Committed paths) and each value an
object naming its `mode` and that mode's members (below); a field may also
carry its own `applied_by` and `policy` (a later applier's, see below) and
an upstream claim kept beside BitExact's own outcome (`upstream: true`,
and `by`).

| Mode | The entry holds | The commitment is over |
|---|---|---|
| `scrub` | the value with each detector match replaced by a token (`[PAN ••••1111]`, `[IBAN]`, `[CREDENTIAL]`); `found` counts the matches by detector | the scrubbed value, under a random salt, as any kept value |
| `hash-only` | no value and no salt | the value, under a salt derived as HMAC-SHA256(capture key, `aer-hash-only` ‖ nonce ‖ path)[:16]; `key_id` names the key, or is null when there was none (the salt was discarded, `cause: capture_key_unavailable`, and the field can never be opened) |
| `hash-only` with `linkable: true` | no value, no salt and no nonce | the value, under the one salt of its key, HMAC-SHA256(capture key, `aer-hash-only-linkable`)[:16]: an equal value commits equal wherever it is committed under that key, so records can be joined on it - and anyone can see which fields hold the same value. `key_id` names the key; a linkable field always has one |
| `unscanned` | the value as captured (base64 bytes the detectors cannot read) | the value, as any kept value |
| `withheld` | no value and no salt | 32 random bytes: the field's presence is committed, its content is gone (`cause: scrub_failed`; or `cause: capture_key_unavailable` for a digest - a gap's `withheld`, a relayed event's `aer_source.sent` - dropped because the capture key could not be used, with `reason: capture key unavailable`); `reason` says what stopped the scrub, and `detector` names the detector that raised or ran out of time on it, the category it could not be scrubbed for (absent when the failure was no detector's) |
| `scrubbed-upstream` | the value as captured | the value; the agent claimed it was cleaned before BitExact saw it, naming the tool that cleaned it in `by` when it said which (`"by": "presidio"`) - recorded as its claim, never counted as a scrub |

A claim of upstream cleaning on a field BitExact itself scrubbed or kept
hash-only never displaces BitExact's outcome: the field keeps its own mode
and adds `upstream: true`, with `by` when the claim named a tool. A writer
makes the claim with the custody hint `scrubbed-upstream`, or
`scrubbed-upstream:<tool>` (the tool a letter or digit, then up to 63
letters, digits, `.`, `_` or `-`). A verdict counts every claimed field as
`claimed cleaned upstream (asserted, not checked)`, a field carrying both
an outcome and a claim under both.

**Enforced**: every declared path is in `commitments`; a `hash-only` or
`withheld` path holds no value, no salt and no redaction marker; a
`hash-only` path carries a supported `alg` and either a 32-hex `nonce`
with a 32-hex `key_id` and no `cause`, a 32-hex `nonce` with a null
`key_id` and `cause: capture_key_unavailable`, or `linkable: true` with no
`nonce`, a 32-hex `key_id` and no `cause`; `linkable` on any other field,
or with any other value, is refused; a `withheld` path names its `cause`; a `scrub` names a
non-empty `found` of positive integer counts; the modes are `scrub`,
`hash-only`, `withheld`, `unscanned` and `scrubbed-upstream`, and any
other mode is refused; a field's own `applied_by` and `policy`, and an
upstream claim's `by`, when present, are text.
A field declared with a `cause` is a declared capture gap and is counted
with the gap markers. On an entry a collector applied the policy to, the
block's `policy` and `applied_by` are the collector's; a field the
recorder changed after it carries its own `applied_by` (`recorder`) and
`policy`. A collector's own declaration never names a field's applier.

The capture key never appears in evidence. A holder of it tests a
candidate value against a hash-only field by recomputing the salt and the
commitment (`bitexact verify RUN --open STEP:PATH --candidate-file F`, or
`--open-withheld STEP --candidate-file F` for a gap's keyed digest;
recorded on the run's custody chain: testing a candidate is the same act
as guessing it). A capture key known to be in other hands is revoked from
a date; a verdict names the fields committed under it as guessable by
whoever holds it since then - the product from its policy's
`revoked_keys`, the standalone verifier from each
`--revoked-capture-key ID=YYYY-MM-DD`. A hash-only field is
a keyed hash of its value: pseudonymous, not de-identified (HIPAA
45 CFR 164.514(c) names a code derived from an identifier as not
de-identified; GDPR Art. 4(5) names keeping the additional information
apart as what makes data pseudonymous). Verifiers state the outcome
counts in their verdict and say so.

A run's `run_meta` records `capture_policy`, the digest of the policy in
force when it opened, or `off`. Under a policy, the product's own digests
of content it does not hold are keyed or dropped: a gap's `withheld`
digest (above), and the recorder's `aer_source.sent` digest of a relayed
event, which is dropped when the recorder's own policy changed the event.
A verdict on a run whose `run_meta` says `off` adds `, no capture policy
was in force` first in its capture clause and prints the scope sentence; a
verdict on a bag or pack of more than one run counts them instead: `, N runs recorded with no
capture policy in force`.

A run's `run_meta` also records `standing`: where the producing deployment
stood when the run opened - `state` (`ok`, `amber` or `red`), `reasons`
(plain-English strings, empty when `ok`) and `records` (whether the
deployment was allowed to record). It is the producer's statement, not
something the bundle proves. Every verifier - the open one and the
product's `bitexact verify` alike - prints, on its own line after the OK
line, `standing when recorded: <state>` - for more than one run, the count in
each state - followed by the reasons, and `(stated by the producer, not
proof)`. A standing of any other shape is counted `malformed` on that line
and fails nothing. A run whose `standing` says `records: false` recorded
what its own producer declared it must not: verification fails it —
**enforced** by every reader alike, each with the same reason: the
command line on every form; the `verify_bundle`, `verify_jsonl`,
`verify_envelope` and `verify_provenance_bundle` APIs (a bag or pack fails
on the run whose standing says so); and the product's `bitexact verify`,
export, packs and Verify view.

## Checkpoints

Signed, sequence-numbered, hash-linked head attestations:

```json
{"run_id": "...", "seq": K, "steps": N, "head_hash": "<hex>",
 "prev_checkpoint": "<hex>", "alg": "...", "key_id": "<16 hex>",
 "ts": "...", "public_key": "<64 hex>", "signature": "<128 hex>",
 "pq_alg": "ML-DSA-65", "pq_public_key": "<hex>", "pq_key_id": "<16 hex>",
 "pq_signature": "<hex>"}
```

`signature` is ed25519 over the canonical JSON of `{"run_id", "seq",
"steps", "head_hash", "prev_checkpoint", "alg", "key_id"}`;
`prev_checkpoint` is the hash of the previous attested body under the
*previous checkpoint's own* `alg` (64 zeros for seq 0). Verifiers must
check that each checkpoint's `run_id` equals the bundle `run_id`,
contiguous integer `seq` from 0, chain links, every signature, `steps` a
non-negative integer within the entry count (**enforced**: a non-integer
or negative `steps` is refused - a negative count binds no entry), and
the entry at `steps - 1` carrying `head_hash`;
they must refuse a checkpoint whose `alg` is not a supported algorithm
(a null `alg` signed as null is not hashable unambiguously) and one whose
`key_id` is not BLAKE2b-64 of its own `public_key` (**enforced**). The
checkpoint `ts` is outside the attested body: informative, never
verified. The optional `pq_alg`, `pq_public_key`, `pq_key_id` and
`pq_signature` carry the checkpoint's ML-DSA half, also outside the
attested body (see Post-quantum signatures).
Relying parties pin recorder identity with `--expect-recorder-key` or
a trust file. Without a pin, each checkpoint is checked against the key
it carries and nothing requires successive checkpoints to share one
Ed25519 key: an unpinned verdict asserts no recorder identity, so a
change of key is not refused (post-quantum continuity, below, is per
Ed25519 key). With a pin, every checkpoint must be by a pinned key. A
verifier asked to require a recorder key **must fail**
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
that the anchor names the bundle's run, that `steps` is a non-negative
integer (**enforced**), and that the bundle still carries that head at the
anchored step; `steps` beyond the bundle's entry count is a truncation
failure. The bundle signature covers the anchor set (see
below), so anchors cannot be added or dropped after signing.

A **WORM anchor** is a recorder-signed head attestation, written to a
customer WORM / object-lock store:

| Field | Meaning |
|---|---|
| `type` | `"worm"`. |
| `run_id`, `steps`, `head_hash` | the attested run, its step count, and head. |
| `alg` | the head's hash algorithm — **enforced**: `blake2b-256` or `sha256`; any other value, or none, is refused, whatever the signature says. |
| `key_id`, `public_key` | recorder key identity (`key_id` is BLAKE2b-64 of the raw key — **enforced**: a `key_id` that does not derive from `public_key` is refused). |
| `anchored_at` | ISO-8601 UTC time the anchor was written. |
| `submitted_by` | present when a peer asked the recorder for the anchor: the identity in the client certificate of the mTLS connection the request arrived on. |
| `signature` | ed25519 over the canonical JSON of `{type, run_id, steps, head_hash, alg, key_id, anchored_at}`, with `submitted_by` added when the anchor carries it - so it cannot be added, removed or changed without failing the signature. |
| `pq_alg`, `pq_public_key`, `pq_key_id`, `pq_signature` | optional; the anchor's ML-DSA half, under purpose `worm-anchor` (see Post-quantum signatures). |

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
| `hash_alg` | the imprint algorithm, always `"sha256"` — **enforced**: required, and any other value is refused (checked once `token` reads as base64, before the token itself); the token's own imprint algorithm is checked independently. |
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

## Transparency log

Every checkpoint the recorder signs is also a leaf of one append-only
Merkle tree per deployment, so a whole run cannot be deleted, and one run
cannot be shown with two different heads, without parties outside the
deployment noticing. The optional `tlog` object proves the bundle's head
checkpoint (the last element of `checkpoints`) is in that log:

| Field | Meaning |
|---|---|
| `leaf` | the canonical JSON of the head checkpoint's attested body `{run_id, seq, steps, head_hash, prev_checkpoint, alg, key_id}` — **enforced**: it must be exactly that body. |
| `index` | the leaf's position in the log, from 0. |
| `size` | the log size the proof is into; must equal the note's size. |
| `proof` | the RFC 9162 inclusion proof: base64 SHA-256 node hashes, leaf to root. |
| `note` | a C2SP signed-note `tlog-checkpoint` of the log at `size`: its text is `origin`, `size` (ASCII decimal, no leading zero, below 2^64), the base64 root (32 bytes), then any extension lines, every line non-empty and ending in a newline; then a blank line and the signature lines. **Enforced**: a text of fewer than three lines, with an empty line, a malformed size or a root that is not 32 bytes of base64 is refused. |

Hashing is RFC 9162: a leaf hashes as `SHA-256(0x00 || leaf)` and a node as
`SHA-256(0x01 || left || right)`. The note must carry a signature by the
head checkpoint's own `public_key` under the note's origin (an ed25519 note
key: key id `SHA-256(origin || "\n" || 0x01 || public_key)[:4]`). When the
head checkpoint carries a `pq_signature`, the note must also carry that
key's ML-DSA line, signed-note type `0xff` (see Post-quantum signatures),
on every verifier, whether or not its library has ML-DSA.
With a recorder key pinned, the log is therefore pinned to it too.

Extension lines follow c2sp.org/tlog-checkpoint: opaque and optional. The
log's note signatures and `cosignature/v1` cosignatures sign the whole
text, extension lines included; an ML-DSA-44 `0x06` cosignature signs the
CosignedSubtree, which does not include them. BitExact's own log writes
none.

Cosignature lines are C2SP `cosignature/v1` (key id type `0x04`, an 8-byte
big-endian timestamp, then ed25519 over `"cosignature/v1\ntime <t>\n"`
followed by the checkpoint text), or ML-DSA-44 `0x06` cosignatures (see
Post-quantum signatures). A verifier counts only cosignatures by
witness keys the relying party pins (`--expect-witness NAME=KEY`), and with
any pinned demands at least `--witness-threshold` of them (default 1). A
bundle with no `tlog` is refused when witnesses are pinned; otherwise its
verdict says nothing about a log. A `tlog` present with no `checkpoints`
is refused. The bundle signature covers `tlog`.

A cosigned note proves the head was in the one history the witnesses saw.
On its own it does not prove that the head is the run's latest. A relying
party that holds more of the log says so with three options:

- `--log-checkpoint FILE` (repeatable): a checkpoint note of the log the
  relying party holds, from a witness or kept earlier. A note of another
  log is passed over; one naming this log that its key did not sign is
  refused. Two roots at one size, both signed by the log's key - the
  bundle's own checkpoint and each held one - are refused as a split view.
- `--log-tail FILE`: the log's leaves from the bundle's head on, as
  `bitexact log tail` writes them: `{"from", "leaves", "left"}` - the first
  leaf's index, the leaves from it (each one line of text), and base64 of
  the 32-byte roots before `from`, one per set bit of it. The tail must hold
  the bundle's head and end at a held checkpoint's size or the bundle's;
  its leaves with `left` must give that root, and each other held root
  within its range must match the one its leaves give, or the bundle is
  refused as a split view.
- A held checkpoint later than the bundle's needs a tail reaching it, or the
  bundle cannot be shown to be the run's latest logged head and is refused.
  A later leaf of the run in the tail refuses the bundle, naming that
  leaf, its checkpoint `seq`, its step and its head. With
  `--point-in-time` the bundle is verified as the run stood at its own
  checkpoint: the later head is named instead of refused, and a held size
  no tail reached is named as not searched for a later head.

`bitexact log heads` lists every head the log holds for a run.

## Signature

```json
{"algorithm": "ed25519", "key_id": "<16 hex>", "public_key": "<64 hex>",
 "signed_at": "<RFC 3339>", "signature": "<128 hex>",
 "pq_alg": "ML-DSA-65", "pq_public_key": "<hex>", "pq_key_id": "<16 hex>",
 "pq_signature": "<hex>"}
```

The signature is ed25519 over the canonical JSON of `{"format",
"run_id", "chain", "signed_at", "key_id"}` (the signature object's own
`signed_at` and `key_id`) plus `"checkpoints"`,
`"anchors"`, `"tlog"` and `"redactions"` when present. The chain head commits to
every entry's committed values; the signature additionally binds the
redaction markers as `"redactions"` — a map of `str(entry index)` to the
sorted `redacted` path list, present only when some entry is redacted — so
a committed field cannot be suppressed after signing. `redacted` is
excluded from the entry hash, so without this a party holding no key could
add a marker and strip a value while the signature stayed valid; a
legitimate redaction is applied before signing (or the bundle is re-signed)
and is covered. The checkpoint set, signing time, and key identity are all
pinned. **Enforced**: `signed_at` and `key_id` are always present and
always in the signed body; `signed_at` is an RFC 3339 date-time in the
grammar of an entry's `ts`, and `key_id` is BLAKE2b-64 of the raw public
key - a signature without either, or whose `key_id` does not derive from
`public_key`, is refused.
The optional `pq_alg`, `pq_public_key`, `pq_key_id` and `pq_signature`
carry the signature's ML-DSA half, under purpose `bundle` (see
Post-quantum signatures).
Each `redactions` path list is sorted by Unicode code point (Python's
`sorted`; a JavaScript implementation must not rely on the default
`Array.prototype.sort`, which compares UTF-16 code units and differs for
astral characters). Hex keys compare case-insensitively wherever a
verifier pins one. A verifier given a
trusted key (or trust file) must reject an unsigned bundle. Trust files list `bundle_keys` and `recorder_keys`
as `{key_id, public_key}` entries, supporting rotation; an entry's optional
`pq_public_key` pins the key's post-quantum half (see Post-quantum
signatures). A trust file
that is empty, misspells a key list, omits `public_key` from an entry, or
gives a `public_key` that is not 64 hex digits (an Ed25519 public key,
either case) must be rejected outright — a malformed trust file must never
silently constrain nothing.

## Post-quantum signatures

Every Ed25519 signature in a bundle may carry, in the same object, a
post-quantum half: an ML-DSA (FIPS 204) signature. Ed25519 falls to a
quantum computer, and a bundle carries the recorder's public key in every
checkpoint, so whoever holds a bundle and such a computer can recover the
key and re-sign a doctored history. The ML-DSA half is what such a forger
cannot make. Both halves are kept: if ML-DSA is broken, the Ed25519 half
still holds against a classical forger.

Four fields sit beside the object's `public_key` and `signature` (or
`sig`): checkpoints, WORM anchors, the bundle `signature`, each DSSE
signature entry, signed ledger and refusal events, license certificates,
and signed reports.

| Field | Value |
|---|---|
| `pq_alg` | `"ML-DSA-65"` (the default) or `"ML-DSA-87"`. No other value is accepted. |
| `pq_public_key` | lowercase hex of the raw ML-DSA public key: 3,904 hex for ML-DSA-65, 5,184 for ML-DSA-87. |
| `pq_key_id` | BLAKE2b-64 of the raw ML-DSA public key — **enforced**: it must derive from `pq_public_key`. |
| `pq_signature` | lowercase hex of the signature: 6,618 hex for ML-DSA-65, 9,254 for ML-DSA-87. |

**Enforced**: the four fields are present together or not at all; hex is
lowercase and exactly the size its `pq_alg` gives (one spelling per value);
and a half that is present must verify — it is a failure, never a warning,
whether or not any key is pinned.

**The message.** Every PQ half signs one construction, with an **empty**
ML-DSA context (domain separation is inside the body, so any FIPS 204
implementation can check it):

```
canonical({"aer_pq": "<purpose>",
           "classical_public_key": <the object's Ed25519 public_key>,
           "pq_alg": <pq_alg>, "pq_key_id": <pq_key_id>,
           "message_sha512": <hex SHA-512 of the exact bytes Ed25519 signed>})
```

`purpose` is the kind of object: `checkpoint`, `worm-anchor`, `bundle`,
`dsse`, `note`, `license`, `license-request`, `token`, `retention`,
`ledger`, `report`, `release-manifest` or `ledger-heads`. A PQ
signature made for one kind therefore never verifies as another, and one
made beside one Ed25519 key never verifies beside another. Signing is
hedged (randomized), so two signatures over the same message differ.

**Checkpoints.** Once a checkpoint carries a PQ half, every later one must
too, and a recorder key keeps the PQ key it started with — **enforced**,
pinned or not: a classical checkpoint after a hybrid one, or a new PQ key
beside the same Ed25519 key, is what someone holding only the Ed25519 key
would write. The one allowed change is a rotation the relying party
vouches for: a later checkpoint may carry a different PQ key under the same
Ed25519 key when the trust file lists that new key for it (a second
`recorder_keys` entry with the same `public_key` and the new
`pq_public_key`). The PQ fields are outside the attested body, so
`prev_checkpoint` and the transparency-log leaf are unchanged by them.

**The transparency-log note.** A hybrid head checkpoint's key also signs the
log note with its PQ half: a second signature line under the note's origin,
signed-note type `0xff` followed by the identifier `aer-mldsa65-note`
(`aer-mldsa87-note` for ML-DSA-87), key id `SHA-256(origin || "\n" ||
0xff || identifier || pq_public_key)[:4]`, signing the note text under
purpose `note`. **Enforced**: a note for a hybrid head checkpoint without
such a line - its blob 4 key-id bytes and a signature of its `pq_alg`'s
size, the key id that of the head checkpoint's `pq_public_key` - is
refused by every verifier; a verifier whose library has ML-DSA also
refuses one whose signature does not verify, and one without ML-DSA leaves
that signature unchecked, as it does every post-quantum half (Pins,
below). Witnesses may cosign with ML-DSA-44 per
c2sp.org/tlog-cosignature: type `0x06`, an 8-byte big-endian timestamp,
then ML-DSA-44 over the `CosignedSubtree` (`"subtree/v1\n\0"`, the
1-byte-length-prefixed cosigner name, the timestamp, the
1-byte-length-prefixed origin, start 0, end the tree size, the root). A
witness pinned by an ML-DSA-44 key counts only a valid `0x06` line.

**Pins.** A relying party pins a key's PQ half with a trust-file entry's
`pq_public_key`, or `--expect-recorder-pq-key` (beside
`--expect-recorder-key`) and `--expect-pq-key` (beside `--expect-key`). A
key pinned with its PQ half requires that half — by exactly the pinned key
— on every object it signed, and a stripped half fails. `--require-pq`
requires a PQ half on everything signed, whatever key signed it, and fails a
bundle with nothing signed at all. A verifier whose library has no ML-DSA
fails any pinned or required PQ check, and otherwise checks the Ed25519
halves and says the PQ half was not checked.

**RFC 3161 tokens** may be signed by an ML-DSA timestamp authority
(RFC 9882: pure ML-DSA, empty context, over the signed attributes; OIDs
`id-ml-dsa-44/65/87` of RFC 9881); such a token's time claim is
post-quantum, a classical one's is not.

**The verdict** names the suite it checked on every OK line —
`signatures: Ed25519 + ML-DSA-65 (post-quantum)`, `signatures: Ed25519 only
- not resistant to a quantum forger`, or `post-quantum signature present,
not checked (library)` — and how each RFC 3161 token is signed.

## DSSE envelope

`bitexact export --format dsse` wraps the bundle as the predicate of an
in-toto Statement (`predicateType` `urn:aer:run`,
subject digest pinning the chain head) inside a DSSE envelope
(`payloadType` `application/vnd.in-toto+json`, signatures over the DSSE
PAE with ed25519, `public_key` carried alongside each `keyid`). The
verifier consumes envelopes directly and applies every bundle check to
the embedded predicate. **Enforced**: the envelope's `payloadType` is
`application/vnd.in-toto+json`; its `payload` is base64 of a JSON in-toto
Statement whose `_type` is exactly `https://in-toto.io/Statement/v1` and
whose `predicateType` is exactly `urn:aer:run`; the first
`subject` has the predicate bundle's `run_id` as its `name` and pins its
`chain.head_hash` as `digest.head` (any further subjects are not read); a
signature entry by an acceptable key must verify over the PAE, and one
whose `keyid` is present but is not BLAKE2b-64 of its `public_key` is
refused. Any other value of each is refused. A signature entry may carry `pq_alg`,
`pq_public_key`, `pq_key_id` and `pq_signature`, its ML-DSA half over the
same PAE under purpose `dsse` (see Post-quantum signatures).

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
    runs/<run_id>.bundle.json  one aer-bundle (optionally signed) per run
    fork-matrix/<...>.json      fork-matrix reports, verbatim
    provenance-graph.json       the cross-run graph (below)
    attestations/provenance.dsse.json   signed graph attestation (with --sign)
    view.html                   the reading view (below); absent with --no-view
```

**Bag integrity (enforced, every bag).** No read leaves the bag: a bag
holding a symbolic link or a junction anywhere, or an entry that resolves
outside the bag's directory, is refused before anything is read, and
every later read is of a regular file inside it. `bagit.txt` begins
`BagIt-Version:`. `manifest-sha256.txt` lists exactly the files under
`data/` - none added, none missing - each matching its sha256.
`tagmanifest-sha256.txt` must be present, and every tag file it lists must
be a file of the bag outside `data/` and match its sha256; its coverage is
what it lists, so a tag file it does not list is not checked (the producer
lists `bagit.txt`, `bag-info.txt` and `manifest-sha256.txt`). When
`bag-info.txt` declares `Payload-Oxum`, it must be exactly
`<octets>.<files>` of the payload (RFC 8493 section 2.2.2). Each manifest
line is `<64 hex>  <path>`, two spaces between; a malformed line is
refused. This profile reads paths literally and never percent-decodes:
a manifest path must be relative POSIX segments, none empty, `.` or
`..`, holding no `%`, CR, LF, `:` or `\` (characters RFC 8493 would
encode, or that name a drive or a Windows separator); any other path is
refused. A bag from another tool whose paths needed encoding is
therefore refused rather than read two ways.

`provenance-graph.json` (`format` `aer-provenance-graph`) lists
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
whose `predicateType` is `urn:aer:provenance-graph`,
predicate is the graph, and subject list pins every run's head — binding
the *set* of runs under one signature, so hiding a fork is detectable.
**Enforced** when the attestation is present (and it must be when a
bundle key is pinned): the envelope is accepted as a run envelope is (DSSE
section); the Statement's `_type` is exactly
`https://in-toto.io/Statement/v1`; its `predicateType` is exactly
`urn:aer:provenance-graph`; its `predicate` equals the bag's graph
(canonical JSON equality); every subject names a run in the bag with that
run's verified head as `digest.head`; and the subjects name each run in
the bag exactly once.
**Enforced listing rules**: `bag-info.txt`'s `External-Identifier` must
equal the graph `root`; each node's `role` must be what its own fork
entry makes it; and `edges` must be exactly the fork relationships the
bundles commit to (each `child`, `source_run`, `at_step`,
`source_prev_hash` re-derived from the committed entries, compared as
canonical JSON) — no edge missing, none invented. A fork's committed
`at_step` must be an integer from 0 to its source's entry count. What the
bag says about itself must be what its runs prove. The nodes' `bundle`
paths must be exactly the bag's `data/runs/*.bundle.json` files — no
bundle held that the graph does not name, none named outside `runs/` —
checked before any bundle is read, so a node's path is never followed out
of `runs/`, and the reading view never shows a run the verdict did not
verify. Every ledger and refusal file the bag carries (see Ledgers;
refusals under `data/refusals/`) is walked and counted exactly as in an
evidence pack. Informative, not verified: the `<run_id>` file name within `runs/`
(each node's `run_id` must equal its bundle's own), and the content of
`fork-matrix/` reports, which are copied verbatim and are covered by the
payload manifest only.

**Reading view.** `data/view.html`, when present, is a script-free HTML page
showing the bag's runs as readable steps. It is rendered by the verifier's
`render_view` from the bag's own files only - its run bundles, refusals,
ledgers and capture policies - and `bag-info.txt`'s `External-Identifier`;
nothing from a store, a clock or a host enters it, so the same bag renders
the same bytes anywhere. A run whose entries carry `aer_source` blocks with a
`source_id` - one recorded from more than one host - is listed in its step
table in causal order, derived again from the entries themselves (each
source's own `seq` and the `caused_by` links, ties broken by the source's
clock and then by chain position); the page says so, names any steps caught
in a cycle of causes, which are listed last in chain order, and notes when
the bundle's own `causal_order` field does not give that order. Steps in
full stay in chain order. A step-table cell past the view's length limit is
shortened and names its step, the field's path and the run's file under
`data/runs/`. **Enforced**: once the bag's checksums and every
run verify, the verifier renders the page again and requires it to equal
`data/view.html` byte for byte. A page that differs fails the bag
(`data/view.html does not match the runs it describes`); one that matches
adds `view matches the bundles` to the OK line; a bag without one verifies
the same. The page itself proves nothing, and where it and the bundles
disagree the bundles are the record. Every other payload file the verifier
does not walk - the workpaper, the trust index, the runbook, the vendored
verifier, fork-matrix reports - is named after the OK line as
`not checked against the runs`: sealed against later change by the payload
manifest, and nothing more.

The standalone verifier checks a bag directly:
`python bitexact_verifier.py <bag-dir> [--expect-key HEX | --trust-file f]`.

## Evidence pack (BagIt)

A bag with no `data/provenance-graph.json` is an evidence pack - a case,
workflow or selection pack - held to the same bag integrity.
**Enforced**: every `data/runs/*.bundle.json` is verified as a bundle, in
the order of the UTF-8 bytes of their file names, and the pack fails on
the first that does not, naming its run; a pack holding
neither a run bundle nor a refusal ledger is refused, since nothing to
verify is not evidence. The reading view rule above applies to a pack as
to a provenance bag.

**Ledgers.** Every ledger a bag carries - each `*.jsonl` file, and each
`*.ledger.json` holding `events`, anywhere under `data/` except the
vendored verifier's own top-level directory `data/verification/` (a
directory named `verification` deeper down, such as
`data/cases/verification/`, is walked like any other) - is walked, in a
provenance bag as in a pack, in the order of the UTF-8 bytes of each
file's POSIX path relative to the bag.
**Enforced**: each event names a supported `alg`; its `prev` is the
previous event's `hash` (64 zeros for the first); and its `hash` is the
hash under that `alg` of the canonical `{ts, kind, by, data, prev, alg}`,
with `submitted_by` and `verified_identity` added when the event carries
them. The recorder writes
`submitted_by` on every event it appends because a peer asked for it - a
role definition or group binding, a case or workflow event, a capture
expectation, a refusal - as the identity in the client certificate of the
mTLS connection the event arrived on: `by` is what that peer asserts,
`submitted_by` who asserted it. An event written in the recorder's own
process carries none, and the field never appears inside `data`. Where the
recorder verified the person behind the event, it writes
`verified_identity` too (Verified identity), never inside `data`.
**Enforced**: an event's `verified_identity` is a verified identity of its
`by`.
An event carrying `sig` must verify: Ed25519 by its `public_key` over the
canonical event without `sig`, `public_key`, `key_id` and the post-quantum
fields, with a `key_id` derived from that key and any post-quantum half
under purpose `ledger`. The walk proves the events present, not that none
followed; the tail is anchored by the signed ledger heads.

**Ledger heads.** `data/ledger-heads.json` is the recorder's signed
statement of where every ledger the bag carries ends. Its attested part is
`{format, ledgers, runs, key_id}`: `format` is `aer-ledger-heads`;
`ledgers` lists each ledger file, sorted by the UTF-8 bytes of its path
(the POSIX path relative to the bag, `data/...`: compared byte by byte,
never by path component and never case-folded, so `data/B.jsonl`,
`data/a-b/x.jsonl`, `data/a.jsonl`, `data/a/x.jsonl` is the one order on
every host), as `{path, events,
head_hash, problem}` - its path in the bag, its event count, its last
event's `hash` (null when it is empty) and `problem`, what the recorder's
own verification of that ledger in its store found when it signed (null
when it verified); `runs` lists each `data/runs/*.bundle.json`, sorted by
the UTF-8 bytes of its path, as `{run_id, steps, head_hash}`, binding the heads to this
pack's runs. When a keyless pack writer asked the recorder to sign it,
the attested part also holds `submitted_by`, the identity in the client
certificate of the mTLS connection the request arrived on. It carries
`public_key` and `signature`, Ed25519 over the
canonical attested part, as a checkpoint does, with any post-quantum half
under purpose `ledger-heads`. **Enforced**: every evidence pack, and every
provenance bag that carries a ledger, carries it; its signature verifies
with a `key_id` derived from its key, by a pinned recorder key when one is
pinned, and its post-quantum half under the caller's pins; no signed
`problem` is set; `ledgers` equals what the bag holds, in that order
(canonical JSON equality), so a ledger whose newest events were dropped,
an older copy put in its place, or a ledger removed or added fails, naming
the ledger and the head the recorder signed, and a list in any other order
fails for its order; and `runs` equals the bag's runs, so an older ledger cannot ride
into a newer pack with the head an older pack signed for it. The OK line
names each ledger with its event count. The anchor proves no newest event
is missing only when the recorder key is pinned: unpinned, anyone holding
the pack can sign a cut ledger under a key of their own, and the OK line
says the key was not pinned.

**Refusals.** Each `data/refusals/<run id>.jsonl` is the ledger of the
executions refused at open, which left no run. Besides the ledger rules,
**enforced**: every event is `kind: refused` with a string `data.cause`,
and names no run or its own file's. A signed refusal counts as signed only
when a pinned recorder key signed it, if one is pinned; an unsigned one
still counts - it can only add an execution that left no evidence, never
excuse one.

## Streamed form — `aer-bundle-jsonl`

`bitexact export --format jsonl` writes the same evidence as one JSON
object per line so a GB-scale run verifies without being held in memory:

```
{"format": "aer-bundle-jsonl", "run_id": ..., "chain": {...},
 "checkpoints": [...], "anchors": [...], "tlog": {...}, "signature": {...}, "license_cert": {...}}
<entry 0>
<entry 1>
...
```

The first non-blank line is the header — the top-level object without
`entries` — and every following non-blank line is one entry, in step
order. Blank lines are skipped and CRLF line endings are tolerated. A
line that is not JSON is refused naming its line number. Every rule of
the object form applies unchanged: the same chain, seal, redaction,
checkpoint, anchor, transparency-log and signature checks, the same signed body (a JSONL
signature is over `"format": "aer-bundle-jsonl"`), and the same
verdict.

## Exit status

The reference verifier's command line and the `bitexact` command line
share one contract, in these words:

| Exit | Contract |
|---|---|
| `0` | OK - the evidence verifies, or the command did what it was asked |
| `1` | operational error - a usage error, a missing run or file, input that cannot be read, or a license refusal: no verdict was reached |
| `2` | FAIL - the evidence does not verify, or a check it requires cannot run on this install (a library is missing) |
| `3` | verified, with declared capture gaps - an intact record of an incomplete capture |

A missing run and a license refusal arise only in the `bitexact`
command. Verifying a container, the cases are:

| Exit | When verifying a container |
|---|---|
| `0` | the evidence verifies |
| `1` | a usage error, a container path that does not exist, a bundle or bag file that exists but this host cannot read, or a pin or trust file that cannot be read or is malformed |
| `2` | the evidence does not verify (bytes that are not JSON, or not UTF-8, included), or a check it requires cannot run on this install: a missing library, or a post-quantum half pinned or required where the library has no ML-DSA |
| `3` | verified, with declared capture gaps (`--allow-gaps` turns it into `0`) |

A bag is first checked for its own shape (Bag integrity) - so a link,
a path outside the bag or a listed file that is missing is a FAIL - and
only a read that then fails is the host's, exit `1`.

## License provenance

`license_cert` is the vendor-signed `bitexact-license` document the
recorder ran under: `{"license_id", "licensee", "expires", "tier",
"entitlements", "recorder_keys": [<hex>...], "scope"?, "signature"}`,
signed by the BitExact vendor key over the canonical JSON of every field
but `signature`. It is informational: outside the bundle signature,
never consulted by integrity verification, and advisory only.
`bitexact_verifier.py --vendor-key HEX` prints a report after the
verdict and never changes it: whether the vendor signature verifies,
whether the license has expired (evaluated against the verifier's clock,
so it is a hint, not an attestation), and whether the run's recorder
key (from its checkpoints or WORM anchors) is one the license names —
a run signed by a key the license does not cover reads as a possible
license replay.
