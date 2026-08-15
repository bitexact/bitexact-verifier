"""Standalone verifier for BitExact evidence bundles.

Implements bundle-spec.md (bitexact-bundle/1): hash-chain verification
over salted data commitments — so redacted entries still verify —
plus optional ed25519 signature checking. Depends only on the standard
library, plus `cryptography` when a bundle is signed.

SPDX-License-Identifier: Apache-2.0
"""

import argparse
import base64
import hashlib
import hmac
import json
import math
import re
import sys

FORMAT = "bitexact-bundle/1"
GENESIS = "0" * 64
_MAX_SAFE_INTEGER = 2 ** 53 - 1
_SURROGATES = re.compile("[\ud800-\udfff]")


def _jcs_string(value: str) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return _SURROGATES.sub(lambda m: f"\\u{ord(m.group()):04x}", text)


def _es6_number(value: float) -> str:
    """ECMAScript Number::toString, per RFC 8785."""
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity cannot be canonicalized")
    if value == 0:
        return "0"
    text = repr(value)
    sign = ""
    if text.startswith("-"):
        sign, text = "-", text[1:]
    exp_value = 0
    if "e" in text:
        text, exp_text = text.split("e")
        exp_value = int(exp_text)
    if "." in text:
        first, last = text.split(".")
    else:
        first, last = text, ""
    if last == "0":
        last = ""
    if 0 < exp_value < 21:
        digits = first + last
        zeros = exp_value - (len(digits) - len(first))
        return sign + digits + "0" * zeros
    if -7 < exp_value < 0:
        digits = first + last
        return sign + "0." + "0" * (-exp_value - 1) + digits
    if exp_value == 0:
        return sign + first + ("." + last if last else "")
    mantissa = first + ("." + last if last else "")
    return f"{sign}{mantissa}e{'+' if exp_value > 0 else '-'}{abs(exp_value)}"


def _jcs(value, out: list) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_jcs_string(value))
    elif isinstance(value, int):
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            raise ValueError(
                f"integer {value} exceeds the I-JSON safe range")
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_es6_number(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _jcs(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        keys = sorted(value, key=lambda k: str(k).encode("utf-16-be",
                                                         "surrogatepass"))
        for i, key in enumerate(keys):
            if i:
                out.append(",")
            out.append(_jcs_string(str(key)))
            out.append(":")
            _jcs(value[key], out)
        out.append("}")
    else:
        raise ValueError(
            f"{type(value).__name__} cannot be canonicalized as JSON")


def _canonical(obj) -> bytes:
    """RFC 8785 canonical bytes."""
    out: list = []
    _jcs(obj, out)
    return "".join(out).encode("utf-8")


_HASH_ALGS = ("blake2b-256", "sha256")


def _hash_hex(alg: str, data: bytes) -> str:
    if alg == "sha256":
        return hashlib.sha256(data).hexdigest()
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def _field_commitment(salt_hex: str, value, alg: str) -> str:
    if alg == "sha256":
        return hmac.new(bytes.fromhex(salt_hex), _canonical(value),
                        hashlib.sha256).hexdigest()
    return hashlib.blake2b(_canonical(value), digest_size=32,
                           key=bytes.fromhex(salt_hex)).hexdigest()


def _unescape_key(key: str) -> str:
    return key.replace("~1", ".").replace("~0", "~")


def _escape_key(key: str) -> str:
    return key.replace("~", "~0").replace(".", "~1")


def _value_at(data: dict, path: str):
    if "." in path:
        head, sub = path.split(".", 1)
        parent = data.get(_unescape_key(head))
        sub_key = _unescape_key(sub)
        if not isinstance(parent, dict) or sub_key not in parent:
            return False, None
        return True, parent[sub_key]
    key = _unescape_key(path)
    if key not in data:
        return False, None
    return True, data[key]


def _data_paths(data: dict) -> list:
    paths = []
    for key, value in data.items():
        if isinstance(value, dict) and value:
            paths.extend(f"{_escape_key(key)}.{_escape_key(sub)}"
                         for sub in value)
        else:
            paths.append(_escape_key(key))
    return paths


def _verify_entry_data(entry: dict):
    data = entry.get("data", {})
    salts = entry.get("salts", {})
    commitments = entry.get("commitments", {})
    redacted = set(entry.get("redacted", []))
    alg = entry.get("alg", "blake2b-256")
    for path in commitments:
        present, value = _value_at(data, path)
        if path in redacted:
            if present:
                return False, (f"path {path} is marked redacted but its "
                               f"value is still present")
            continue
        if not present:
            return False, f"path {path} missing without a redaction marker"
        try:
            commitment = _field_commitment(salts.get(path, ""), value, alg)
        except ValueError:
            return False, f"malformed salt for path {path}"
        if commitment != commitments[path]:
            return False, (f"data hash mismatch at path {path} — value "
                           f"tampered or corrupted")
    for path in _data_paths(data):
        if path not in commitments:
            husk = data.get(_unescape_key(path))
            if ("." not in path and isinstance(husk, dict) and not husk
                    and any(c.startswith(path + ".") for c in commitments)):
                continue
            return False, f"uncommitted data at path {path}"
    return True, None


def verify_bundle(bundle: dict, expect_key: str | None = None,
                  expect_recorder_key: str | None = None,
                  trusted_bundle_keys: list | None = None,
                  trusted_recorder_keys: list | None = None):
    """Return (ok, error). The error names what failed and where.

    Total: hostile input of any shape is a failed verification, never an
    exception."""
    try:
        return _verify_bundle(bundle, expect_key, expect_recorder_key,
                              trusted_bundle_keys, trusted_recorder_keys)
    except RuntimeError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"malformed bundle: {exc!r}"


def _verify_bundle(bundle, expect_key, expect_recorder_key,
                   trusted_bundle_keys, trusted_recorder_keys):
    if bundle.get("format") != FORMAT:
        return False, f"unsupported format {bundle.get('format')!r}"

    entries = bundle.get("entries", [])
    prev = GENESIS
    claims = []
    markers = {}
    run_end_at = None
    for i, entry in enumerate(entries):
        ok, err = _entry_check(entry, i, prev, bundle.get("run_id"))
        if not ok:
            return False, err
        prev = entry["hash"]
        err = _seal_step(entry, i, run_end_at)
        if err:
            return False, err
        if entry.get("kind") == "run_end":
            run_end_at = i
        if entry.get("kind") == "redaction":
            claims.extend((i, t) for t in
                          (entry.get("data") or {}).get("fields") or [])
        marks = entry.get("redacted")
        if isinstance(marks, list) and marks:
            markers[i] = marks

    head = entries[-1]["hash"] if entries else None
    if bundle.get("chain", {}).get("head_hash") != head:
        return False, "chain head_hash does not match the final entry"

    err = _redaction_incomplete(claims, markers, len(entries))
    if err:
        return False, err

    def hash_at(index: int):
        return entries[index].get("hash") if 0 <= index < len(entries) \
            else None

    return _check_seals(bundle, len(entries), hash_at, expect_key,
                        expect_recorder_key, trusted_bundle_keys,
                        trusted_recorder_keys)


def _seal_step(entry, i, run_end_at):
    """Enforce run_end seal semantics as each entry streams past: only
    redaction/repair audit entries may follow a seal, and a seal's
    attested step count must equal its own position + 1. Matches the
    product's verify_run/verify_stream so the public verifier proves the
    same 'complete run vs truncated' distinction the docs claim."""
    if run_end_at is not None and entry.get("kind") not in (
            "redaction", "repair"):
        return (f"step {run_end_at}: run_end seal is not final — only "
                f"redaction and repair audit entries may follow a seal")
    if entry.get("kind") == "run_end":
        sealed = (entry.get("data") or {}).get("steps")
        if sealed != i + 1:
            return (f"step {i}: run_end seal attests {sealed} steps but "
                    f"was sealed at {i + 1}")
    return None


def _redaction_incomplete(claims, markers, total):
    """Error if a recorded redaction claim was never applied to its
    target step — a bundle asserting 'we redacted X' where X is still
    present must FAIL. Mirrors the product's verify_run/verify_stream."""
    for red_step, token in claims:
        step_text, _, path = token.partition(":")
        if not step_text.isdigit() or int(step_text) >= total:
            continue
        marks = markers.get(int(step_text))
        if not isinstance(marks, list) or path not in marks:
            return (f"step {red_step}: redaction of {token} recorded but "
                    f"not applied — the bundle's redaction claim is false")
    return None


def _entry_check(entry: dict, i: int, prev: str, run_id):
    """One entry against its position, predecessor, and run identity."""
    if entry.get("v") != 2:
        return False, f"step {i}: unsupported entry version {entry.get('v')!r}"
    body = {k: v for k, v in entry.items()
            if k not in ("hash", "data", "salts", "redacted")}
    payload = _canonical(body)
    if entry.get("alg") not in _HASH_ALGS:
        return False, f"step {i}: unsupported hash algorithm {entry.get('alg')!r}"
    if body.get("run_id") != run_id:
        return False, (f"step {i}: entry run_id {body.get('run_id')!r} "
                       f"does not match bundle run_id")
    if body.get("step") != i:
        return False, f"step {i}: step index mismatch"
    if body.get("prev") != prev:
        return False, f"step {i}: chain broken"
    if _hash_hex(entry.get("alg"), payload) != entry.get("hash"):
        return False, f"step {i}: hash mismatch — entry tampered or corrupted"
    ok, err = _verify_entry_data(entry)
    if not ok:
        return False, f"step {i}: {err}"
    return True, None


def _check_seals(container: dict, entries_len: int, hash_at, expect_key,
                 expect_recorder_key, trusted_bundle_keys,
                 trusted_recorder_keys):
    """Checkpoint chain and bundle signature for both bundle forms."""
    checkpoints = container.get("checkpoints", [])
    if ((expect_recorder_key is not None
         or trusted_recorder_keys is not None) and not checkpoints):
        return False, ("a recorder key was required but the bundle has no "
                       "checkpoints for it to have signed")
    prev_checkpoint = GENESIS
    for i, cp in enumerate(checkpoints):
        attested = {"run_id": cp.get("run_id"), "seq": cp.get("seq"),
                    "steps": cp.get("steps"),
                    "head_hash": cp.get("head_hash"),
                    "prev_checkpoint": cp.get("prev_checkpoint"),
                    "alg": cp.get("alg"), "key_id": cp.get("key_id")}
        if cp.get("run_id") != container.get("run_id"):
            return False, (f"checkpoint {i}: run_id {cp.get('run_id')!r} "
                           f"does not match bundle run_id")
        if cp.get("seq") != i:
            return False, f"checkpoint {i}: sequence gap"
        if cp.get("prev_checkpoint") != prev_checkpoint:
            return False, f"checkpoint {i}: checkpoint chain broken"
        if (expect_recorder_key is not None
                and cp.get("public_key") != expect_recorder_key):
            return False, (f"checkpoint {i}: not signed by the trusted "
                           f"recorder key")
        if (trusted_recorder_keys is not None
                and cp.get("public_key") not in trusted_recorder_keys):
            return False, (f"checkpoint {i}: not signed by a trusted "
                           f"recorder key")
        if not _ed25519_verify(cp.get("public_key", ""), _canonical(attested),
                               cp.get("signature", "")):
            return False, f"checkpoint {i}: signature invalid"
        steps = cp.get("steps", 0)
        if steps > entries_len:
            return False, (f"checkpoint {i}: attests {steps} steps but the "
                           f"bundle has {entries_len} — history removed "
                           f"below a signed checkpoint")
        if steps > 0 and hash_at(steps - 1) != cp.get("head_hash"):
            return False, (f"checkpoint {i}: attested head does not match "
                           f"the chain at step {steps - 1}")
        prev_checkpoint = _hash_hex(cp.get("alg", "blake2b-256"),
                                    _canonical(attested))

    signature = container.get("signature")
    if signature is None:
        if expect_key is not None or trusted_bundle_keys is not None:
            return False, ("bundle is unsigned but a trusted key was "
                           "required — refusing to verify")
        return True, None
    if signature.get("algorithm") != "ed25519":
        return False, (f"unsupported signature algorithm "
                       f"{signature.get('algorithm')!r}")
    if expect_key is not None and signature.get("public_key") != expect_key:
        return False, "signature public_key is not the trusted key"
    if (trusted_bundle_keys is not None
            and signature.get("public_key") not in trusted_bundle_keys):
        return False, "signature public_key is not among the trusted keys"
    signed_body = {"format": container.get("format"),
                   "run_id": container.get("run_id"),
                   "chain": container.get("chain")}
    if "signed_at" in signature:
        signed_body["signed_at"] = signature["signed_at"]
    if "key_id" in signature:
        signed_body["key_id"] = signature["key_id"]
    if "checkpoints" in container:
        signed_body["checkpoints"] = container["checkpoints"]
    if not _ed25519_verify(signature["public_key"], _canonical(signed_body),
                           signature["signature"]):
        return False, "signature check failed — bundle altered after signing"
    return True, None


JSONL_FORMAT = "bitexact-bundle-jsonl/1"


def verify_jsonl(lines, expect_key: str | None = None,
                 expect_recorder_key: str | None = None,
                 trusted_bundle_keys: list | None = None,
                 trusted_recorder_keys: list | None = None):
    """Streaming verification of the JSONL bundle form.

    `lines` is any iterable of text lines: header first, then one entry
    per line. Entries are verified as they stream and never held
    together — the GB-scale path. Returns (ok, error, summary) where
    summary carries steps/signed/redacted counts. Total: hostile input
    is a failed verification, never an exception."""
    try:
        return _verify_jsonl(lines, expect_key, expect_recorder_key,
                             trusted_bundle_keys, trusted_recorder_keys)
    except RuntimeError as exc:
        return False, str(exc), None
    except Exception as exc:
        return False, f"malformed bundle: {exc!r}", None


def _verify_jsonl(lines, expect_key, expect_recorder_key,
                  trusted_bundle_keys, trusted_recorder_keys):
    stream = (line for line in lines if line.strip())
    first = next(stream, None)
    if first is None:
        return False, "empty bundle", None
    header = json.loads(first)
    if header.get("format") != JSONL_FORMAT:
        return False, f"unsupported format {header.get('format')!r}", None
    run_id = header.get("run_id")
    checkpoints = header.get("checkpoints", [])
    needed = {cp.get("steps", 0) - 1 for cp in checkpoints
              if cp.get("steps", 0) > 0}
    captured: dict[int, str] = {}
    markers: dict[int, list] = {}
    claims = []
    prev = GENESIS
    count = 0
    redacted = 0
    run_end_at = None
    for i, line in enumerate(stream):
        entry = json.loads(line)
        ok, err = _entry_check(entry, i, prev, run_id)
        if not ok:
            return False, err, None
        prev = entry["hash"]
        count = i + 1
        err = _seal_step(entry, i, run_end_at)
        if err:
            return False, err, None
        if entry.get("kind") == "run_end":
            run_end_at = i
        if i in needed:
            captured[i] = prev
        marks = entry.get("redacted")
        if isinstance(marks, list) and marks:
            markers[i] = marks
        redacted += len(marks) if isinstance(marks, list) else (1 if marks
                                                                else 0)
        if entry.get("kind") == "redaction":
            claims.extend((i, t) for t in
                          (entry.get("data") or {}).get("fields") or [])
    head = prev if count else None
    if header.get("chain", {}).get("head_hash") != head:
        return False, "chain head_hash does not match the final entry", None
    err = _redaction_incomplete(claims, markers, count)
    if err:
        return False, err, None
    ok, err = _check_seals(header, count, captured.get, expect_key,
                           expect_recorder_key, trusted_bundle_keys,
                           trusted_recorder_keys)
    if not ok:
        return False, err, None
    summary = {"steps": count, "signed": "signature" in header,
               "redacted": redacted}
    return True, None, summary


def _ed25519_verify(public_hex: str, data: bytes, signature_hex: str) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)
    except ImportError:
        raise RuntimeError(
            "verifying signatures requires the 'cryptography' package — "
            "pip install cryptography") from None

    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        key.verify(bytes.fromhex(signature_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    return (b"DSSEv1 " + str(len(payload_type)).encode() + b" "
            + payload_type.encode() + b" " + str(len(payload)).encode()
            + b" " + payload)


def verify_envelope(envelope: dict, expect_key=None,
                    expect_recorder_key=None, trusted_bundle_keys=None,
                    trusted_recorder_keys=None):
    """Verify a DSSE envelope carrying an in-toto statement whose
    predicate is a bundle; returns (ok, error, bundle_or_none).

    Total: hostile input of any shape is a failed verification, never an
    exception."""
    try:
        return _verify_envelope(envelope, expect_key, expect_recorder_key,
                                trusted_bundle_keys, trusted_recorder_keys)
    except RuntimeError as exc:
        return False, str(exc), None
    except Exception as exc:
        return False, f"malformed envelope: {exc!r}", None


def _verify_envelope(envelope, expect_key, expect_recorder_key,
                     trusted_bundle_keys, trusted_recorder_keys):
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        return False, (f"unsupported payloadType "
                       f"{envelope.get('payloadType')!r}"), None
    try:
        payload = base64.b64decode(envelope.get("payload", ""),
                                   validate=True)
    except Exception:
        return False, "envelope payload is not valid base64", None
    pae = _dsse_pae(DSSE_PAYLOAD_TYPE, payload)
    signatures = envelope.get("signatures") or []
    verified = False
    for entry in signatures:
        try:
            sig_hex = base64.b64decode(entry.get("sig", ""),
                                       validate=True).hex()
        except Exception:
            continue
        public = entry.get("public_key", "")
        if expect_key is not None and public != expect_key:
            continue
        if (trusted_bundle_keys is not None
                and public not in trusted_bundle_keys):
            continue
        if _ed25519_verify(public, pae, sig_hex):
            verified = True
            break
    if not verified:
        return False, ("envelope signature verification failed — no "
                       "acceptable signature over the payload"), None
    try:
        statement = json.loads(payload)
    except ValueError:
        return False, "envelope payload is not JSON", None
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        return False, f"unsupported statement type {statement.get('_type')!r}", None
    bundle = statement.get("predicate") or {}
    subjects = statement.get("subject") or [{}]
    if subjects[0].get("name") != bundle.get("run_id"):
        return False, "statement subject does not name the bundle run", None
    if (subjects[0].get("digest", {}).get("head")
            != bundle.get("chain", {}).get("head_hash")):
        return False, "statement subject digest does not pin the chain head", None
    ok, err = verify_bundle(bundle, expect_key=expect_key,
                            expect_recorder_key=expect_recorder_key,
                            trusted_bundle_keys=trusted_bundle_keys,
                            trusted_recorder_keys=trusted_recorder_keys)
    if not ok:
        return False, err, None
    return True, None, bundle


def _validate_trust(trust) -> str | None:
    """A malformed trust file must refuse to verify, never silently
    constrain nothing."""
    if not isinstance(trust, dict):
        return "trust file is not a JSON object"
    unknown = set(trust) - {"bundle_keys", "recorder_keys"}
    if unknown:
        return f"trust file has unrecognized key {sorted(unknown)[0]!r}"
    if not trust:
        return "trust file names no bundle_keys or recorder_keys"
    for name in ("bundle_keys", "recorder_keys"):
        if name in trust:
            if not isinstance(trust[name], list):
                return f"trust file {name} must be a list"
            for k in trust[name]:
                if not isinstance(k, dict) or not k.get("public_key"):
                    return f"trust file {name} entry has no public_key"
    return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="bitexact-verifier",
        description="Verify a BitExact evidence bundle")
    parser.add_argument("bundle", help="path to a bundle JSON file")
    parser.add_argument("--expect-key",
                        help="require this ed25519 public key (hex)")
    parser.add_argument("--expect-recorder-key",
                        help="require every checkpoint to be signed by this "
                             "ed25519 public key (hex)")
    parser.add_argument("--trust-file",
                        help="JSON file with bundle_keys/recorder_keys "
                             "lists of {key_id, public_key} entries")
    args = parser.parse_args(argv)

    trusted_bundle_keys = trusted_recorder_keys = None
    if args.trust_file:
        with open(args.trust_file, encoding="utf-8") as f:
            trust = json.load(f)
        problem = _validate_trust(trust)
        if problem:
            print(f"FAIL: {problem}")
            return 1
        if "bundle_keys" in trust:
            trusted_bundle_keys = [k["public_key"]
                                   for k in trust["bundle_keys"]]
        if "recorder_keys" in trust:
            trusted_recorder_keys = [k["public_key"]
                                     for k in trust["recorder_keys"]]

    with open(args.bundle, encoding="utf-8") as f:
        first = f.readline()
        try:
            first_doc = json.loads(first)
        except ValueError:
            first_doc = None
        if (isinstance(first_doc, dict)
                and first_doc.get("format") == JSONL_FORMAT):
            def _lines():
                yield first
                yield from f
            ok, err, summary = verify_jsonl(
                _lines(), expect_key=args.expect_key,
                expect_recorder_key=args.expect_recorder_key,
                trusted_bundle_keys=trusted_bundle_keys,
                trusted_recorder_keys=trusted_recorder_keys)
            if ok:
                signed = "signed" if summary["signed"] else "unsigned"
                note = ""
                if summary["redacted"]:
                    note = f", {summary['redacted']} field(s) redacted"
                    if not summary["signed"]:
                        note += (" (unsigned redaction — demand a signed "
                                 "bundle)")
                print(f"OK: {first_doc.get('run_id')} — "
                      f"{summary['steps']} steps, chain verified, "
                      f"{signed}{note} (jsonl, streamed)")
                return 0
            print(f"FAIL: {err}")
            return 1
        f.seek(0)
        bundle = json.load(f)
    if "payloadType" in bundle:
        ok, err, inner = verify_envelope(
            bundle, expect_key=args.expect_key,
            expect_recorder_key=args.expect_recorder_key,
            trusted_bundle_keys=trusted_bundle_keys,
            trusted_recorder_keys=trusted_recorder_keys)
        bundle = inner or {}
    else:
        ok, err = verify_bundle(
            bundle, expect_key=args.expect_key,
            expect_recorder_key=args.expect_recorder_key,
            trusted_bundle_keys=trusted_bundle_keys,
            trusted_recorder_keys=trusted_recorder_keys)
    if ok:
        n = len(bundle.get("entries", []))
        signed = "signed" if bundle.get("signature") else "unsigned"
        marks = [e.get("redacted") for e in bundle.get("entries", [])]
        redacted = sum(len(r) if isinstance(r, list) else 1
                       for r in marks if r)
        note = ""
        if redacted:
            note = f", {redacted} field(s) redacted"
            if not bundle.get("signature"):
                note += " (unsigned redaction — demand a signed bundle)"
        print(f"OK: {bundle.get('run_id')} — {n} steps, chain verified, "
              f"{signed}{note}")
        return 0
    print(f"FAIL: {err}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
