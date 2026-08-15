# bitexact-verifier

A standalone, independent verifier for BitExact evidence bundles
(`bitexact-bundle/1`). It re-derives every hash and signature in a
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

Requires Python 3.10+.

```bash
pip install .
bitexact-verifier bundle.json
```

Or run the single file directly, without installing:

```bash
pip install cryptography asn1crypto
python bitexact_verifier.py bundle.json
```

> A published `pip install bitexact-verifier` release will follow; until
> then, install from source as above.

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
```

**Exit code `0`** means the bundle verifies; **`1`** means it does not,
printing `FAIL:` with the exact failing step or check.

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
  from a truncated one.
- **External anchors** — a WORM anchor's recorder signature and an RFC
  3161 timestamp token (its CMS signature, imprint, and timeStamping
  certificate), each bound to the bundle head, so truncation below an
  externally held anchor fails. `--expect-tsa <cert>` pins the timestamp
  authority.
- **Signed checkpoints** and the **detached ed25519 bundle signature**,
  including DSSE envelopes wrapping in-toto statements.
- **Canonicalization** — RFC 8785 (JCS), so hashes are reproducible
  across languages.

The wire format is specified in [`bundle-spec.md`](bundle-spec.md), and
`testdata/` holds the golden conformance fixtures and RFC 8785 vectors
that any independent implementation can validate against.

## Development

```bash
pip install cryptography asn1crypto pytest
pytest test_vectors.py
```

`test_vectors.py` is the cross-implementation conformance suite; it
imports only this package, never BitExact.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
