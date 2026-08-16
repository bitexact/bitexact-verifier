"""Standalone conformance tests: committed fixtures only, no product code.

These are the tests that run in the public verifier repository; they must
never import bitexact.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bitexact_verifier import (main, verify_bundle,  # noqa: E402
                               verify_envelope)

TESTDATA = Path(__file__).parent / "testdata"


def _load(name):
    return json.loads((TESTDATA / name).read_text(encoding="utf-8"))


def test_canonicalization_vectors():
    from bitexact_verifier import _canonical

    for case in _load("jcs-vectors.json")["cases"]:
        assert _canonical(case["input"]).decode("utf-8") == \
            case["expected_canonical"], case["name"]


def test_golden_signed_bundle_verifies():
    bundle = _load("valid-signed.bundle.json")
    ok, err = verify_bundle(bundle)
    assert ok, err
    ok, err = verify_bundle(bundle,
                            expect_key=bundle["signature"]["public_key"])
    assert ok, err


def test_golden_worm_anchor_verifies():
    ok, err = verify_bundle(_load("valid-worm-anchor.bundle.json"))
    assert ok, err


def test_golden_rfc3161_anchor_verifies_and_pins_tsa():
    bundle = _load("valid-rfc3161-anchor.bundle.json")
    ok, err = verify_bundle(bundle)
    assert ok, err
    tsa = (TESTDATA / "tsa.crt").read_text(encoding="utf-8")
    ok, err = verify_bundle(bundle, expect_tsa=tsa)
    assert ok, err


def test_golden_rfc3161_anchor_tamper_fails():
    import base64
    bundle = _load("valid-rfc3161-anchor.bundle.json")
    token = bytearray(base64.b64decode(bundle["anchors"][0]["token"]))
    token[-1] ^= 0xFF
    bundle["anchors"][0]["token"] = base64.b64encode(bytes(token)).decode()
    ok, err = verify_bundle(bundle)
    assert not ok


def test_golden_redacted_bundle_verifies_with_trust_file():
    bundle = _load("valid-redacted.bundle.json")
    trust = _load("trust.json")
    ok, err = verify_bundle(
        bundle,
        trusted_bundle_keys=[k["public_key"] for k in trust["bundle_keys"]],
        trusted_recorder_keys=[k["public_key"]
                               for k in trust["recorder_keys"]])
    assert ok, err
    assert any(e.get("redacted") for e in bundle["entries"])


def test_golden_dsse_envelope_verifies():
    envelope = _load("valid.dsse.json")
    ok, err, bundle = verify_envelope(envelope)
    assert ok, err
    assert bundle["run_id"] == "golden-run"


def test_golden_adverse_decision_bundle_is_identity_rich_and_verifies():
    # The auditor-pack sample: an automated loan decline carrying bound
    # identity, retrieval context, an observed tool call, the model
    # decision, a human oversight decision, and an honest capture-gap
    # marker. It must verify, and its provenance must be exactly as
    # claimed -- asserted evidence is never presented as observed capture.
    bundle = _load("adverse-decision.bundle.json")
    ok, err = verify_bundle(bundle,
                            expect_key=bundle["signature"]["public_key"])
    assert ok, err

    by_kind = {}
    for e in bundle["entries"]:
        by_kind.setdefault(e["kind"], []).append(e)
    for kind in ("run_meta", "identity", "context", "tool_call",
                 "http_call", "human_decision", "marker", "run_end"):
        assert kind in by_kind, f"sample missing a {kind} entry"

    for kind in ("identity", "context", "human_decision", "marker"):
        assert all(e["prov"] == "asserted" for e in by_kind[kind]), kind
    assert by_kind["http_call"][0]["prov"] == "observed"
    assert any(e["prov"] == "observed" for e in by_kind["tool_call"])

    identity = by_kind["identity"][0]["data"]
    assert identity["principal"] and identity["model_version"]
    assert identity["policy_version"].startswith("sha256:")
    assert identity["prompt_pack_version"].startswith("sha256:")
    assert by_kind["context"][0]["data"]["content_hash"]
    decision = by_kind["human_decision"][0]["data"]
    assert decision["decision"] == "uphold"
    assert decision["binds_step"] == by_kind["http_call"][0]["step"]
    assert by_kind["marker"][0]["data"]["note"]


def test_every_single_byte_matters():
    """Flip each structural element of the golden bundle; all must fail."""
    golden = _load("valid-signed.bundle.json")

    tampered = json.loads(json.dumps(golden))
    tampered["entries"][1]["data"]["result"]["temp"] = -40
    assert verify_bundle(tampered)[0] is False

    tampered = json.loads(json.dumps(golden))
    tampered["run_id"] = "someone-else"
    assert verify_bundle(tampered)[0] is False

    tampered = json.loads(json.dumps(golden))
    tampered["entries"].pop()
    assert verify_bundle(tampered)[0] is False

    tampered = json.loads(json.dumps(golden))
    del tampered["checkpoints"]
    assert verify_bundle(tampered)[0] is False  # signature pins checkpoints

    tampered = json.loads(json.dumps(golden))
    sig = tampered["signature"]["signature"]
    tampered["signature"]["signature"] = \
        ("0" if sig[0] != "0" else "1") + sig[1:]
    assert verify_bundle(tampered)[0] is False


def test_cli_consumes_fixtures(capsys):
    assert main([str(TESTDATA / "valid-signed.bundle.json")]) == 0
    assert "OK" in capsys.readouterr().out
    assert main([str(TESTDATA / "valid.dsse.json")]) == 0
    assert main([str(TESTDATA / "valid-redacted.bundle.json"),
                 "--trust-file", str(TESTDATA / "trust.json")]) == 0
    out = capsys.readouterr().out
    assert "redacted" in out


def _golden():
    return _load("valid-signed.bundle.json")


def test_malformed_entries_fail_with_named_reasons():
    cases = []

    b = _golden()
    b["entries"][1]["redacted"] = ["result.temp"]  # marker without removal
    cases.append((b, "still present"))

    b = _golden()
    b["entries"][1]["salts"]["result.temp"] = "zz"
    cases.append((b, "malformed salt"))

    b = _golden()
    b["entries"][0]["v"] = 3
    cases.append((b, "unsupported entry version"))

    b = _golden()
    b["entries"][0]["alg"] = "md5"
    cases.append((b, "unsupported hash algorithm"))

    for bundle, needle in cases:
        ok, err = verify_bundle(bundle)
        assert not ok and needle in err, (needle, err)


def test_wrong_recorder_trust_fails():
    bundle = _load("valid-redacted.bundle.json")
    ok, err = verify_bundle(bundle,
                            trusted_recorder_keys=["ab" * 32])
    assert not ok and "trusted" in err and "recorder" in err


def test_envelope_failure_modes():
    import base64

    good = _load("valid.dsse.json")

    e = dict(good, payloadType="application/json")
    ok, err, _ = verify_envelope(e)
    assert not ok and "payloadType" in err

    e = dict(good, payload="!!not-base64!!")
    ok, err, _ = verify_envelope(e)
    assert not ok and "base64" in err

    e = json.loads(json.dumps(good))
    e["signatures"][0]["sig"] = "!!not-base64!!"
    ok, err, _ = verify_envelope(e)
    assert not ok and "signature" in err

    ok, err, _ = verify_envelope(good, expect_key="ab" * 32)
    assert not ok and "signature" in err

    ok, err, _ = verify_envelope(good, trusted_bundle_keys=["ab" * 32])
    assert not ok and "signature" in err

    raw = base64.b64decode(good["payload"])
    e = json.loads(json.dumps(good))
    e["payload"] = base64.b64encode(b"not json").decode()
    ok, err, _ = verify_envelope(e)
    assert not ok  # signature over altered payload fails first

    statement = json.loads(raw)
    statement["subject"][0]["digest"]["head"] = "0" * 64
    # re-signing is impossible without the key, so digest tampering is
    # caught by the envelope signature — craft an unsigned-check instead
    ok, err, _ = verify_envelope(dict(good, signatures=[]))
    assert not ok and "signature" in err


def test_canonicalization_rejects_nan_and_unsupported_types():
    import pytest

    from bitexact_verifier import _canonical

    with pytest.raises(ValueError):
        _canonical(float("nan"))
    with pytest.raises(ValueError):
        _canonical({"x": object()})


def test_sha256_bundle_verifies():
    """The fixture is built with hashlib/hmac directly, independent of the
    verifier's own alg dispatch."""
    import hashlib
    import hmac

    from bitexact_verifier import _canonical

    salt = "ab" * 32
    commitment = hmac.new(bytes.fromhex(salt), _canonical(1),
                          hashlib.sha256).hexdigest()
    entry = {"v": 2, "alg": "sha256", "run_id": "r", "step": 0, "kind": "k",
             "prov": "observed",
             "ts": "t", "prev": "0" * 64, "commitments": {"x": commitment}}
    entry["hash"] = hashlib.sha256(_canonical(entry)).hexdigest()
    entry["data"] = {"x": 1}
    entry["salts"] = {"x": salt}
    bundle = {"format": "bitexact-bundle/1", "run_id": "r",
              "entries": [entry], "chain": {"head_hash": entry["hash"]}}
    ok, err = verify_bundle(bundle)
    assert ok, err

    tampered = json.loads(json.dumps(bundle))
    tampered["entries"][0]["data"]["x"] = 2
    assert verify_bundle(tampered)[0] is False


def test_bundle_signature_outside_trusted_keys_fails():
    bundle = _load("valid-signed.bundle.json")
    ok, err = verify_bundle(bundle, trusted_bundle_keys=["ab" * 32])
    assert not ok and "trusted keys" in err


def test_statement_checks_run_after_a_valid_envelope_signature():
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import DSSE_PAYLOAD_TYPE, _dsse_pae

    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def envelope(payload: bytes) -> dict:
        pae = _dsse_pae(DSSE_PAYLOAD_TYPE, payload)
        return {"payloadType": DSSE_PAYLOAD_TYPE,
                "payload": base64.b64encode(payload).decode(),
                "signatures": [
                    {"public_key": public,
                     "sig": base64.b64encode(key.sign(pae)).decode()}]}

    ok, err, _ = verify_envelope(envelope(b"not json"))
    assert not ok and "not JSON" in err

    stmt = {"_type": "wrong", "subject": [], "predicate": {}}
    ok, err, _ = verify_envelope(envelope(json.dumps(stmt).encode()))
    assert not ok and "statement type" in err

    golden = json.loads(base64.b64decode(_load("valid.dsse.json")["payload"]))

    s = json.loads(json.dumps(golden))
    s["subject"][0]["name"] = "someone-else"
    ok, err, _ = verify_envelope(envelope(json.dumps(s).encode()))
    assert not ok and "does not name" in err

    s = json.loads(json.dumps(golden))
    s["subject"][0]["digest"]["head"] = "0" * 64
    ok, err, _ = verify_envelope(envelope(json.dumps(s).encode()))
    assert not ok and "pin the chain head" in err

    s = json.loads(json.dumps(golden))
    s["predicate"]["entries"][1]["data"]["result"]["temp"] = -40
    ok, err, _ = verify_envelope(envelope(json.dumps(s).encode()))
    assert not ok and "tampered" in err


def test_recorder_key_demand_fails_without_checkpoints(tmp_path, capsys):
    bundle = _golden()
    del bundle["checkpoints"]
    del bundle["signature"]
    ok, err = verify_bundle(bundle)
    assert ok, err  # unsigned, nothing demanded — still fine

    ok, err = verify_bundle(bundle, expect_recorder_key="ab" * 32)
    assert not ok and "checkpoint" in err

    ok, err = verify_bundle(bundle, trusted_recorder_keys=["ab" * 32])
    assert not ok and "checkpoint" in err

    path = tmp_path / "forged.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert main([str(path), "--expect-recorder-key", "ab" * 32]) == 1
    assert "FAIL" in capsys.readouterr().out

    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps(
        {"recorder_keys": [{"key_id": "x", "public_key": "ab" * 32}]}),
        encoding="utf-8")
    assert main([str(path), "--trust-file", str(trust)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_trust_file_must_be_well_formed(tmp_path, capsys):
    bundle_path = TESTDATA / "valid-signed.bundle.json"
    cases = [
        ("{}", "no bundle_keys or recorder_keys"),
        ("[]", "not a JSON object"),
        ('{"bundle-keys": []}', "unrecognized key"),
        ('{"bundle_keys": "zz"}', "must be a list"),
        ('{"bundle_keys": [{"key_id": "x"}]}', "public_key"),
    ]
    for text, needle in cases:
        trust = tmp_path / "trust.json"
        trust.write_text(text, encoding="utf-8")
        assert main([str(bundle_path), "--trust-file", str(trust)]) == 1, text
        out = capsys.readouterr().out
        assert "FAIL" in out and needle in out, (text, out)


def test_verify_functions_never_throw(tmp_path, capsys):
    b = _golden()
    b["entries"][1]["salts"] = ["not", "a", "dict"]
    ok, err = verify_bundle(b)
    assert ok is False and isinstance(err, str)

    b = _golden()
    b["entries"] = [1, 2]
    ok, err = verify_bundle(b)
    assert ok is False and isinstance(err, str)

    b = _golden()
    b["entries"][1]["data"] = ["not", "a", "dict"]
    ok, err = verify_bundle(b)
    assert ok is False and isinstance(err, str)

    b = _golden()
    b["checkpoints"] = "zz"
    ok, err = verify_bundle(b)
    assert ok is False and isinstance(err, str)

    ok, err, _ = verify_envelope({"payloadType": DSSE_TYPE, "payload": 7,
                                  "signatures": "zz"})
    assert ok is False and isinstance(err, str)

    path = tmp_path / "bad.json"
    b = _golden()
    b["entries"][1]["commitments"] = None
    path.write_text(json.dumps(b), encoding="utf-8")
    assert main([str(path)]) == 1
    assert "FAIL" in capsys.readouterr().out


DSSE_TYPE = "application/vnd.in-toto+json"


def test_checkpoint_from_another_run_fails_even_at_zero_steps():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import _canonical

    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    bundle = _golden()
    del bundle["signature"]
    attested = {"run_id": "some-other-run", "seq": 0, "steps": 0,
                "head_hash": "0" * 64, "prev_checkpoint": "0" * 64,
                "alg": "blake2b-256", "key_id": "aa" * 8}
    bundle["checkpoints"] = [dict(
        attested, public_key=public,
        signature=key.sign(_canonical(attested)).hex())]
    ok, err = verify_bundle(bundle)
    assert not ok and "run_id" in err


def test_missing_cryptography_fails_clean(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_crypto(name, *a, **kw):
        if name.startswith("cryptography"):
            raise ImportError("No module named 'cryptography'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_crypto)
    ok, err = verify_bundle(_golden())
    assert ok is False and "cryptography" in err and "pip install" in err

    ok, err, _ = verify_envelope(_load("valid.dsse.json"))
    assert ok is False and "cryptography" in err


def test_envelope_of_wrong_type_fails_clean():
    ok, err, _ = verify_envelope(7)
    assert ok is False and isinstance(err, str)


def test_lone_surrogates_escape_and_big_ints_reject():
    import pytest

    from bitexact_verifier import _canonical

    lone = json.loads('"\\ud834"')
    assert _canonical({"s": lone}) == b'{"s":"\\ud834"}'
    astral = json.loads('"\\ud834\\udd1e"')
    lone_d835 = json.loads('"\\ud835"')
    keys = {lone_d835: 1, astral: 2}
    # the astral char's first UTF-16 unit (d834) sorts below the lone d835
    assert _canonical(keys).startswith(b'{"' + astral.encode("utf-8"))

    assert _canonical({"n": 2 ** 53 - 1}) == b'{"n":9007199254740991}'
    with pytest.raises(ValueError):
        _canonical({"n": 2 ** 53})
    with pytest.raises(ValueError):
        _canonical({"n": -(2 ** 53)})


def test_cli_rejects_malformed_bundle_with_nan(tmp_path, capsys):
    bad = tmp_path / "nan.json"
    bad.write_text('{"format": "bitexact-bundle/1", "run_id": "r", '
                   '"entries": [{"v": 2, "alg": "blake2b-256", '
                   '"run_id": "r", "step": 0, "kind": "x", "ts": "t", '
                   '"prev": "' + "0" * 64 + '", "data": {"x": NaN}, '
                   '"salts": {}, "commitments": {}, "hash": "beef"}], '
                   '"chain": {"head_hash": "beef"}}', encoding="utf-8")
    assert main([str(bad)]) == 1
    assert "FAIL" in capsys.readouterr().out


def _jsonl_lines(bundle, signature=None):
    header = {"format": "bitexact-bundle-jsonl/1",
              "run_id": bundle["run_id"], "chain": bundle["chain"]}
    if "checkpoints" in bundle:
        header["checkpoints"] = bundle["checkpoints"]
    if signature is not None:
        header["signature"] = signature
    return [json.dumps(header)] + [json.dumps(e)
                                   for e in bundle["entries"]]


def test_jsonl_form_verifies_and_fails_loud(tmp_path, capsys):
    from bitexact_verifier import verify_jsonl

    bundle = _golden()
    del bundle["signature"]
    del bundle["checkpoints"]

    ok, err, summary = verify_jsonl(_jsonl_lines(bundle))
    assert ok, err
    assert summary["steps"] == len(bundle["entries"])
    assert summary["signed"] is False

    lines = _jsonl_lines(bundle)
    entry = json.loads(lines[2])
    entry["data"]["result"]["temp"] = -40
    lines[2] = json.dumps(entry)
    ok, err, _ = verify_jsonl(lines)
    assert not ok and "step 1" in err

    lines = _jsonl_lines(bundle)[:-1]  # drop the last entry
    ok, err, _ = verify_jsonl(lines)
    assert not ok and "head_hash" in err

    ok, err, _ = verify_jsonl([])
    assert not ok and "empty" in err

    ok, err, _ = verify_jsonl(['{"format": "wrong/1"}'])
    assert not ok and "unsupported format" in err

    ok, err, _ = verify_jsonl([json.dumps(
        {"format": "bitexact-bundle-jsonl/1", "run_id": "r",
         "chain": {"head_hash": None}}), "{not json"])
    assert not ok and isinstance(err, str)  # total, never throws

    path = tmp_path / "b.jsonl"
    path.write_text(chr(10).join(_jsonl_lines(bundle)) + chr(10),
                    encoding="utf-8")
    assert main([str(path)]) == 0
    assert "jsonl, streamed" in capsys.readouterr().out

    bad = tmp_path / "bad.jsonl"
    lines = _jsonl_lines(bundle)
    entry = json.loads(lines[1])
    entry["data"] = {"smuggled": True}
    lines[1] = json.dumps(entry)
    bad.write_text(chr(10).join(lines) + chr(10), encoding="utf-8")
    assert main([str(bad)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_jsonl_signature_and_recorder_demand(tmp_path):
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import _canonical, verify_jsonl

    bundle = _golden()
    del bundle["signature"]
    del bundle["checkpoints"]
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    signed_body = {"format": "bitexact-bundle-jsonl/1",
                   "run_id": bundle["run_id"], "chain": bundle["chain"],
                   "signed_at": "t", "key_id": "aa" * 8}
    signature = {"algorithm": "ed25519", "key_id": "aa" * 8,
                 "public_key": public, "signed_at": "t",
                 "signature": key.sign(_canonical(signed_body)).hex()}

    ok, err, summary = verify_jsonl(_jsonl_lines(bundle, signature),
                                    expect_key=public)
    assert ok, err
    assert summary["signed"] is True

    ok, err, _ = verify_jsonl(_jsonl_lines(bundle, signature),
                              expect_key="bb" * 32)
    assert not ok and "trusted key" in err

    ok, err, _ = verify_jsonl(_jsonl_lines(bundle),
                              expect_recorder_key="ab" * 32)
    assert not ok and "checkpoint" in err


def test_jsonl_checkpoints_no_crypto_and_redaction_note(tmp_path,
                                                        monkeypatch,
                                                        capsys):
    import builtins

    from bitexact_verifier import verify_jsonl

    bundle = _golden()
    del bundle["signature"]  # checkpoints stay: their hashes are captured
    ok, err, _ = verify_jsonl(_jsonl_lines(bundle))
    assert ok, err

    real_import = builtins.__import__

    def no_crypto(name, *a, **kw):
        if name.startswith("cryptography"):
            raise ImportError("no module")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_crypto)
    ok, err, _ = verify_jsonl(_jsonl_lines(bundle))
    assert not ok and "cryptography" in err
    monkeypatch.setattr(builtins, "__import__", real_import)

    redacted = _load("valid-redacted.bundle.json")
    redacted.pop("signature", None)
    redacted.pop("checkpoints", None)
    path = tmp_path / "red.jsonl"
    path.write_text(chr(10).join(_jsonl_lines(redacted)) + chr(10),
                    encoding="utf-8")
    assert main([str(path)]) == 0
    out = capsys.readouterr().out
    assert "redacted" in out and "unsigned redaction" in out


def _sealed_bundle():
    """A minimal signed-fixture-shaped bundle with a run_end seal, rebuilt
    so hashes are valid, using the verifier's own primitives."""
    import hashlib

    from bitexact_verifier import _canonical, _field_commitment

    run_id = "sealed-run"
    entries = []
    prev = "0" * 64
    salt = "cd" * 16

    def add(kind, data):
        nonlocal prev
        i = len(entries)
        commitments = {k: _field_commitment(salt, v, "blake2b-256")
                       for k, v in data.items()}
        body = {"v": 2, "alg": "blake2b-256", "run_id": run_id, "step": i,
                "kind": kind, "prov": "observed", "ts": "t", "prev": prev,
                "commitments": commitments}
        h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
        entries.append({**body, "hash": h, "data": data,
                        "salts": {k: salt for k in data}})
        prev = h

    add("http_call", {"model": "gpt-4o"})
    add("run_end", {"steps": 2})
    return {"format": "bitexact-bundle/1", "run_id": run_id,
            "entries": entries, "chain": {"head_hash": entries[-1]["hash"]}}


def test_verifier_enforces_run_end_seal_finality():
    import hashlib

    from bitexact_verifier import _canonical, verify_bundle

    bundle = _sealed_bundle()
    ok, err = verify_bundle(bundle)
    assert ok, err

    # append a behavioral entry after the seal — must FAIL
    tampered = json.loads(json.dumps(bundle))
    prev = tampered["entries"][-1]["hash"]
    body = {"v": 2, "alg": "blake2b-256", "run_id": "sealed-run", "step": 2,
            "kind": "http_call", "prov": "observed", "ts": "t",
            "prev": prev, "commitments": {}}
    h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
    tampered["entries"].append({**body, "hash": h, "data": {}, "salts": {}})
    tampered["chain"]["head_hash"] = h
    ok, err = verify_bundle(tampered)
    assert not ok and "not final" in err


def test_verifier_enforces_run_end_step_count():
    import hashlib

    from bitexact_verifier import _canonical, verify_bundle

    from bitexact_verifier import _field_commitment

    bundle = _sealed_bundle()
    tampered = json.loads(json.dumps(bundle))
    seal = tampered["entries"][1]
    seal["data"]["steps"] = 5
    seal["commitments"]["steps"] = _field_commitment(
        seal["salts"]["steps"], 5, "blake2b-256")
    body = {k: v for k, v in seal.items()
            if k not in ("hash", "data", "salts", "redacted")}
    seal["hash"] = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
    tampered["chain"]["head_hash"] = seal["hash"]
    ok, err = verify_bundle(tampered)
    assert not ok and "seal attests" in err


def test_jsonl_verifier_enforces_seal_finality():
    from bitexact_verifier import verify_jsonl
    import hashlib
    from bitexact_verifier import _canonical

    bundle = _sealed_bundle()
    header = {"format": "bitexact-bundle-jsonl/1", "run_id": "sealed-run",
              "chain": bundle["chain"]}
    lines = [json.dumps(header)] + [json.dumps(e) for e in bundle["entries"]]
    ok, err, _ = verify_jsonl(lines)
    assert ok, err

    prev = bundle["entries"][-1]["hash"]
    body = {"v": 2, "alg": "blake2b-256", "run_id": "sealed-run", "step": 2,
            "kind": "http_call", "prov": "observed", "ts": "t",
            "prev": prev, "commitments": {}}
    h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
    extra = {**body, "hash": h, "data": {}, "salts": {}}
    header2 = {**header, "chain": {"head_hash": h}}
    lines = ([json.dumps(header2)]
             + [json.dumps(e) for e in bundle["entries"]]
             + [json.dumps(extra)])
    ok, err, _ = verify_jsonl(lines)
    assert not ok and "not final" in err


def test_verify_bundle_flags_unapplied_redaction_claim():
    from bitexact_verifier import verify_bundle

    import hashlib

    from bitexact_verifier import _canonical, _field_commitment

    bundle = _sealed_bundle()  # http_call + run_end
    # a redaction entry claiming step 0's model was redacted, but it is
    # still present — the claim is false and must FAIL
    entries = bundle["entries"][:1]  # just the http_call
    salt = "ef" * 16
    data = {"fields": ["0:model"], "by": "auditor"}
    commitments = {k: _field_commitment(salt, v, "blake2b-256")
                   for k, v in data.items()}
    body = {"v": 2, "alg": "blake2b-256", "run_id": "sealed-run", "step": 1,
            "kind": "redaction", "prov": "observed", "ts": "t",
            "prev": entries[0]["hash"], "commitments": commitments}
    h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
    entries.append({**body, "hash": h, "data": data,
                    "salts": {k: salt for k in data}})
    b = {"format": "bitexact-bundle/1", "run_id": "sealed-run",
         "entries": entries, "chain": {"head_hash": h}}
    ok, err = verify_bundle(b)
    assert not ok and "redaction claim is false" in err

    header = {"format": "bitexact-bundle-jsonl/1", "run_id": "sealed-run",
              "chain": {"head_hash": h}}
    from bitexact_verifier import verify_jsonl
    ok, err, _ = verify_jsonl([json.dumps(header)]
                              + [json.dumps(e) for e in entries])
    assert not ok and "redaction claim is false" in err


def test_verify_bundle_ignores_inert_redaction_tokens():
    import hashlib

    from bitexact_verifier import (_canonical, _field_commitment,
                                   verify_bundle)

    bundle = _sealed_bundle()
    entries = bundle["entries"][:1]
    salt = "ef" * 16
    # both tokens are inert: non-digit step and out-of-range step
    data = {"fields": ["bogus", "99:x"], "by": "auditor"}
    commitments = {k: _field_commitment(salt, v, "blake2b-256")
                   for k, v in data.items()}
    body = {"v": 2, "alg": "blake2b-256", "run_id": "sealed-run", "step": 1,
            "kind": "redaction", "prov": "observed", "ts": "t",
            "prev": entries[0]["hash"], "commitments": commitments}
    h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
    entries.append({**body, "hash": h, "data": data,
                    "salts": {k: salt for k in data}})
    b = {"format": "bitexact-bundle/1", "run_id": "sealed-run",
         "entries": entries, "chain": {"head_hash": h}}
    ok, err = verify_bundle(b)
    assert ok, err


def test_verifier_rejects_unknown_provenance():
    import hashlib

    from bitexact_verifier import _canonical, verify_bundle

    body = {"v": 2, "alg": "blake2b-256", "run_id": "r", "step": 0,
            "kind": "http_call", "prov": "sneaky", "ts": "t",
            "prev": "0" * 64, "commitments": {}}
    h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
    bundle = {"format": "bitexact-bundle/1", "run_id": "r",
              "entries": [{**body, "hash": h, "data": {}, "salts": {}}],
              "chain": {"head_hash": h}}
    ok, err = verify_bundle(bundle)
    assert not ok and "provenance" in err
