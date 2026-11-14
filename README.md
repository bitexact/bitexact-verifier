# bitexact-verifier

A standalone, independent verifier for BitExact evidence bundles
(`aer-bundle`). It re-derives every hash and signature in a
bundle from first principles and reports whether the evidence is
intact — with no dependency on BitExact and no license required.

Anyone who receives a signed BitExact bundle — an auditor, a regulator,
a counterparty — can verify it here, offline, on an air-gapped machine
if they choose. The implementation is a single Python file that depends
only on the standard library, [`cryptography`](https://pypi.org/project/cryptography/),
and [`asn1crypto`](https://pypi.org/project/asn1crypto/) (both pure-Python
or self-contained wheels) — `asn1crypto` solely to verify RFC 3161
timestamp anchors.

## Install

Requires Python 3.12+. Each `verifier-v<version>` release of this
repository is published to PyPI under that version:

```bash
pip install bitexact-verifier==<version>
bitexact-verifier bundle.json
```

PyPI never accepts the same version twice, so a published version's files
never change: any change to the verifier ships under a new version number.

The `verifier-v2.3.0` tag is an earlier prototype. It was never published to
PyPI and has no post-quantum checks. Numbering restarted at 0.0.1a0, the
version of the BitExact release whose bundles this verifier reads.

From a checkout of this repository:

```bash
pip install .
```

Or run the single file directly, without installing:

```bash
pip install cryptography asn1crypto
python bitexact_verifier.py bundle.json
```


## Usage

```bash
# Verify a bundle's integrity
bitexact-verifier run-42.bundle.json

# Require a specific signing key (hex-encoded ed25519 public key)
bitexact-verifier run-42.bundle.json --expect-key <64-hex public key>

# Verify against a trust file of accepted bundle- and recorder-keys
bitexact-verifier run-42.bundle.json --trust-file trust.json

# Large runs export as a streaming JSONL bundle — verified the same way
bitexact-verifier run-42.bundle.jsonl

# DSSE envelopes (in-toto statements) are detected and verified automatically
bitexact-verifier run-42.dsse.json

# Require every RFC 3161 timestamp anchor to come from a specific TSA
bitexact-verifier run-42.bundle.json --expect-tsa tsa-root.pem

# Require the run to be sealed (refuse an unfinished run; applies to a
# bundle, a streamed jsonl bundle, and a provenance bag's root run)
bitexact-verifier run-42.bundle.json --require-sealed

# Require the head to be attested by a specific recorder key
bitexact-verifier run-42.bundle.json --expect-recorder-key <64-hex public key>

# ...and its post-quantum (ML-DSA) half: every checkpoint, anchor and signed
# record by that key must carry a post-quantum signature by this key, so a
# forger who recovers the Ed25519 key with a quantum computer still fails.
# A trust-file entry's `pq_public_key` pins the same way.
bitexact-verifier run-42.bundle.json --expect-recorder-key <64-hex> \
  --expect-recorder-pq-key <ML-DSA public key hex, or a file holding it>

# Require a post-quantum signature on everything signed, whatever key signed
# it. It pins no key: a forger who recovers the Ed25519 key can add an ML-DSA
# key of their own, so pin the key to refuse that.
bitexact-verifier run-42.bundle.json --require-pq

# Report whether the vendor's post-quantum key signed the license too
bitexact-verifier run-42.bundle.json --vendor-key <hex> --vendor-pq-key <hex>

# An evidence pack, or a provenance bag: give the directory. Every run in
# it, its ledgers and the bag's checksums are verified together; refusals
# under data/refusals/ are checked and counted as declared capture gaps
bitexact-verifier run-42.evidence-pack --expect-recorder-key <64-hex public key>

# A pack handed over without its reading view (data/view.html): once the bag
# verifies (exit 0 or 3), write the page yourself. It is your own rendering
# of the verified bag, not part of it; a bag that fails writes nothing
# (exit 2), and a single bundle file is refused (exit 1)
bitexact-verifier run-42.evidence-pack --render-view view.html

# Require the bundle's transparency-log proof to be in a log checkpoint the
# witnesses you trust cosigned (repeat --expect-witness for each; by default
# one of them must have cosigned)
bitexact-verifier run-42.bundle.json \
  --expect-witness witness.example=<64-hex public key> \
  --expect-witness audit.example=<64-hex public key> --witness-threshold 2

# Report, beside the verdict, which license the recording deployment held
# (advisory: it never changes the integrity verdict)
bitexact-verifier run-42.bundle.json --vendor-key <64-hex vendor public key>
```

### Exit codes

The verifier and the BitExact CLI share one contract, in the same words:

| Exit | Meaning |
|---|---|
| `0` | OK - the evidence verifies, or the command did what it was asked |
| `1` | operational error - a usage error, a missing run or file, input that cannot be read, or a license refusal: no verdict was reached |
| `2` | FAIL - the evidence does not verify, or a check it requires cannot run on this install (a library is missing) |
| `3` | verified, with declared capture gaps - an intact record of an incomplete capture |

A `FAIL:` line (exit 2) names the exact failing step or check; an `error:`
line (exit 1) names the input the verifier could not use - a bundle path
that does not exist, a bundle or bag file this host cannot read, a trust
file or pin that makes no sense, a mistyped flag - and says nothing about
the evidence. Exit 3 counts the gaps on the
`OK:` line; `--allow-gaps` accepts any gaps (exit 0), where `bitexact
verify --allow-gaps` names which causes to accept (`license_lapsed,run_ended`,
or `all`). A CI gate on either tool passes on 0 only, or on 0 and 3 when it
accepts gaps.

### The `OK:` line

It says what was proved and no more. Two runs over the conformance
fixtures this repository ships, the first with the recorder key pinned:

```
$ bitexact-verifier testdata/adverse-decision.bundle.json --trust-file testdata/trust.json
OK: adverse-decision - 10 steps (observed 4 / asserted 6 / synthetic 0), chain verified, sealed, signed, recorder-attested, in transparency log bitexact.log/cecb6ee8074e6fba (leaf 43 of 44) - witnesses not pinned: pass --expect-witness to know there is one history, signatures: Ed25519 + ML-DSA-65 (post-quantum), post-quantum key pinned
captured via sdk-python 8, proxy 1, unlabeled 1 (attribution, not proof)
$ bitexact-verifier testdata/valid.bundle.jsonl
OK: golden-run - 4 steps (observed 4 / asserted 0 / synthetic 0), chain verified, sealed, bundle unsigned, in transparency log bitexact.log/cecb6ee8074e6fba (leaf 3 of 4) - witnesses not pinned: pass --expect-witness to know there is one history, signatures: Ed25519 + ML-DSA-65 (post-quantum) - post-quantum key not pinned: a forger who recovers the Ed25519 key can add an ML-DSA key of their own; pin it with --expect-recorder-pq-key, or a trust file naming it (jsonl, streamed)
captured via sdk-python 3, unlabeled 1 (attribution, not proof)
```

The bracket is what the steps are made of, and it is proven, not read off
a label - each entry's provenance class is inside its hash: `observed` the
recorder saw on the wire, `asserted` the agent's code declared (a tool
call, a decision), `synthetic` a marked counterfactual (an injected
response in a fork, also counted after the bracket). `sealed` means a
terminal marker attests the run's end (and, for a recorder-signed run, a
checkpoint covers that head); `unsealed - end not attested` means the chain
is intact up to its last entry but nothing says it is the last. `signed`
reports a valid bundle signature, with a caveat until you pin its key with
`--expect-key`; `bundle unsigned` means the bundle carries none (the
recorder's checkpoints may still sign the run); `recorder-attested` appears
only when you pinned a recorder key and a checkpoint or WORM anchor under it
covers the head. A transparency-log proof, anchors, redactions and declared
gaps are each named after that. `signatures:` says which suite the verdict
checked - Ed25519 with its ML-DSA post-quantum half, or Ed25519 alone, which
a quantum computer could forge - and whether the post-quantum key was pinned.

On an evidence pack or a provenance bag, `view matches the bundles` ends the
OK line when the bag carries a reading view (`data/view.html`) and the page
this verifier renders again from the bag's own bundles is the same, byte for
byte; a page that differs fails the bag instead (exit 2). A line after it
names every other payload file the verdict does not stand behind:
`not checked against the runs (the producer's own statements, sealed against
later change only): ` followed by their paths - the workpaper, the trust
index, the runbook and the like. The bag's checksums prove only that those
did not change after bagging; nothing here checks what they say.

## Confirming this verifier is genuine

This tool is your root of trust, so confirm the copy you hold is authentic
without having to trust BitExact — a vendor signature would only move the
question to "do I trust their key?":

```bash
bitexact-verifier --version        # the release and spec identity it claims
sha256sum bitexact_verifier.py     # compare to CHECKSUMS.txt for that version
```

Confirm that `sha256` against the canonical digest for the version it claims —
in [`CHECKSUMS.txt`](CHECKSUMS.txt), on the `verifier-v<version>` git tag, or on
PyPI once the version is published there — obtained through a channel
**independent** of wherever you got the file,
and never only from a copy handed to you by the party whose evidence you audit.
Better still, read it: it is one file. The trusted base beyond this file is
CPython, `cryptography`/OpenSSL (48 or later, for ML-DSA), and `asn1crypto`.

## What it checks

- **Hash chain** — every entry's hash over its canonical body, linked to
  its predecessor, from genesis to the recorded head (BLAKE2b-256, or
  SHA-256 for FIPS-mode bundles).
- **Field commitments** — each committed field's salted commitment, so a
  redacted field still verifies while any tampered value fails.
- **Redaction integrity** — a bundle that *claims* to have redacted a
  field must actually have removed it; a false redaction claim fails.
- **Seal semantics** — a sealed run's terminal marker must be final and
  attest the correct step count, so a complete run is distinguishable
  from a truncated one; a sealed run that carries recorder checkpoints
  must have its head covered by one, so nothing was appended after the
  recorder finished.
- **Recorder tier** — with `--expect-recorder-key` or a trust file, the
  head must be covered by a checkpoint or WORM anchor under that key and
  every withheld field must carry an on-chain redaction claim, whatever
  else signed the bundle.
- **External anchors** — a WORM anchor's recorder signature and an RFC
  3161 timestamp token (its CMS signature, imprint, and timeStamping
  certificate), each bound to the bundle head, so truncation below an
  externally held anchor fails. `--expect-tsa <cert>` pins the timestamp
  authority.
- **Signed checkpoints** and the **detached ed25519 bundle signature**,
  including DSSE envelopes wrapping in-toto statements.
- **Post-quantum signatures** — the ML-DSA-65 or ML-DSA-87 (FIPS 204) half
  beside each Ed25519 signature: bound to that Ed25519 key and to the kind of
  object it signs, required by a hybrid pin or `--require-pq`, never allowed
  to disappear part-way through a run, and checked on the transparency-log
  note and on C2SP ML-DSA-44 witness cosignatures. A present half that does
  not verify always fails. Every OK line says which suite it checked.
- **Reading view** — a bag's `data/view.html` is rendered again from the
  bag's own bundles, refusals and ledgers once they verify, and must equal
  the page the bag carries byte for byte, so a page cannot show what the
  bundles do not say. The page is a reading aid, never a verdict: it has no
  script and no external reference, and it reads in a text editor. A bag
  without one verifies the same.
- **Canonicalization** — `aer-jcs`: RFC 8785 (JCS) restricted to
  values that canonicalize identically everywhere, so hashes are
  reproducible across languages. Values that would not are refused at
  record time rather than committed to; see `bundle-spec.md`.

The wire format is specified in [`bundle-spec.md`](bundle-spec.md), and
`testdata/` holds the golden conformance fixtures and the `aer-jcs`
vector corpus — both the accepted bytes and the refusals — that any
independent implementation can validate against. One directory there is
not a conformance vector: `hostile-view.bag` exercises the reading view
(`data/view.html`) with hostile text, and its run carries no chain, so it
does not verify.

## Development

```bash
pip install cryptography asn1crypto pytest
pytest test_vectors.py
```

`test_vectors.py` is the cross-implementation conformance suite; it
imports only this package, never BitExact.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
