# bitexact-verifier

Standalone verifier for BitExact evidence bundles (`bitexact-bundle/1`).
Verifies the hash chain (BLAKE2b-256, or SHA-256 for FIPS-mode
bundles) and, for signed bundles, the ed25519 signature —
independently of BitExact, with no BitExact license required. Bundles
from every prior release verify under their original scheme. The
format is specified in `bundle-spec.md`.

This directory is a self-contained package (stdlib + `cryptography`
only, no imports from BitExact) that splits out to its own public
repository at GA. Until it is published to PyPI, install it from this
directory:

```
pip install cryptography
python bitexact_verifier.py bundle.json
python bitexact_verifier.py bundle.json --expect-key <64-hex ed25519 public key>
# once published:  pip install bitexact-verifier && bitexact-verifier bundle.json
```

Exit code 0 means the bundle verifies; 1 means it does not, with the
exact failing step or check printed.

Licensed under Apache-2.0.
