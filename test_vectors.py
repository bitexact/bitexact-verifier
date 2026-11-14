"""Standalone conformance tests: committed fixtures only, no product code.

These are the tests that run in the public verifier repository; they must
never import bitexact.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bitexact_verifier import (main, verify_bundle,  # noqa: E402
                               verify_envelope)

TESTDATA = Path(__file__).parent / "testdata"


def _load(name):
    return json.loads((TESTDATA / name).read_text(encoding="utf-8"))


def _every_pin():
    """The trust file's bundle and recorder keys, Ed25519 and ML-DSA, and
    every published witness."""
    pins = ["--trust-file", str(TESTDATA / "trust.json")]
    for name, key in _load("witnesses.json").items():
        pins += ["--expect-witness", f"{name}={key}"]
    return pins


def test_the_witnessed_vectors_verify_with_every_key_pinned(capsys):
    """valid-hybrid-witnessed is a signed run exported after a witness
    cosigned the log, so every key it carries is pinned and its verdict
    names nothing unsigned or unpinned; valid-gap-witnessed declares a
    capture gap under the same pins: intact, but exit 3 unless --allow-gaps
    accepts it."""
    whole = str(TESTDATA / "valid-hybrid-witnessed.bundle.json")
    gap = str(TESTDATA / "valid-gap-witnessed.bundle.json")
    assert main([whole, *_every_pin()]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK: golden-run - ")
    assert "not pinned" not in out and "unsigned" not in out, out
    assert main([gap, *_every_pin()]) == 3
    out = capsys.readouterr().out
    assert "1 declared capture gap - the capture is incomplete" in out
    assert "not pinned" not in out and "unsigned" not in out, out
    assert main([gap, *_every_pin(), "--allow-gaps"]) == 0


def test_an_empty_redaction_marker_is_refused():
    """`redacted` is absent until a path is redacted. It sits outside the
    entry hash and the signed redaction map, so an empty list is a second
    spelling of "nothing redacted" anyone could add: it is refused."""
    bundle = _load("valid-sha256.bundle.json")
    assert verify_bundle(bundle) == (True, None)
    bundle["entries"][0]["redacted"] = []
    ok, err = verify_bundle(bundle)
    assert not ok and "entry redacted is an empty list" in err, err


def test_capture_controls_vectors(capsys):
    """A bundle recorded under a capture policy verifies, and its verdict
    says what the policy kept; every way an entry can contradict its capture
    declaration outside the chain body is refused for its own reason."""
    bundle = _load("valid-capture.bundle.json")
    assert verify_bundle(bundle) == (True, None)
    assert main([str(TESTDATA / "valid-capture.bundle.json")]) == 0
    out = capsys.readouterr().out
    assert ", 1 field scrubbed before capture (pan 1), 1 field hash-only " \
           "(never held; 1 can be opened with key " in out
    # The scope sentence, on its own line after the verdict, whenever the
    # policy kept less.
    assert out.splitlines()[1] == (
        "Scrubbed and hash-only fields prove that a value was presented and "
        "which rule removed it. They do not prove what the value was, they "
        "cannot be replayed, and hash-only custody is not HIPAA "
        "de-identification.")
    doc = _load("capture-negative-vectors.json")
    assert doc["format"] == "aer-capture-negative-vectors"
    assert len(doc["cases"]) >= 4
    for case in doc["cases"]:
        ok, err = verify_bundle(case["bundle"])
        assert not ok and case["refusal"] in err, (case["name"], err)


def test_a_bundle_under_the_retired_vendor_format_name_is_refused(
        tmp_path, capsys):
    """The record format is `aer-bundle`; a document naming the vendor format
    it replaced is refused exactly as any unknown format is, in both the
    whole and the streamed form, and from the command line."""
    bundle = _load("valid-signed.bundle.json")
    assert verify_bundle(bundle) == (True, None)
    for retired in ("bitexact-bundle", "bitexact-bundle-jsonl"):
        assert verify_bundle(dict(bundle, format=retired)) == (
            False, f"unsupported format {retired!r}")
    assert verify_bundle(dict(bundle, format="x-bundle")) == (
        False, "unsupported format 'x-bundle'")

    whole = tmp_path / "retired.bundle.json"
    whole.write_text(json.dumps(dict(bundle, format="bitexact-bundle")),
                     encoding="utf-8")
    assert main([str(whole)]) == 2
    assert "unsupported format 'bitexact-bundle'" in capsys.readouterr().out

    lines = (TESTDATA / "valid.bundle.jsonl").read_text(
        encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    assert header["format"] == "aer-bundle-jsonl"
    assert main([str(TESTDATA / "valid.bundle.jsonl")]) == 0
    capsys.readouterr()
    streamed = tmp_path / "retired.bundle.jsonl"
    streamed.write_text("\n".join(
        [json.dumps(dict(header, format="bitexact-bundle-jsonl")),
         *lines[1:]]) + "\n", encoding="utf-8")
    assert main([str(streamed)]) == 2
    assert "OK" not in capsys.readouterr().out


def test_post_quantum_negative_vectors():
    """Every way a post-quantum half can be wrong, each refused for its own
    reason: the corpus an independent verifier is held to. The genuine
    bundle they are cut from verifies under the same pins."""
    doc = _load("pq-negative-vectors.json")
    assert doc["format"] == "aer-pq-negative-vectors"
    assert len(doc["cases"]) >= 12
    trust = _load("trust.json")
    pins = {"expect_recorder_key": trust["recorder_keys"][0]["public_key"],
            "expect_recorder_pq_key": trust["recorder_keys"][0]["pq_public_key"],
            "expect_key": trust["bundle_keys"][0]["public_key"],
            "expect_pq_key": trust["bundle_keys"][0]["pq_public_key"]}
    assert verify_bundle(_load("valid-signed.bundle.json"), **pins) == (True, None)
    assert verify_bundle(_load("valid-signed.bundle.json"), require_pq=True) == \
        (True, None)
    for case in doc["cases"]:
        ok, err = verify_bundle(case["bundle"], **case["pins"])
        assert not ok and case["refusal"] in err, (case["name"], err)


def test_chain_negative_vectors():
    """Every rule that leaves a chain one reading - a body named by its step
    when it cannot be canonicalized, data and commitments always present,
    no boolean where an integer belongs, a seal never redacted, one fork
    entry, one timestamp grammar, a signature that always names its time and
    key - each refused for its own reason. The genuine bundle they are cut
    from verifies."""
    doc = _load("chain-negative-vectors.json")
    assert doc["format"] == "aer-chain-negative-vectors"
    assert len(doc["cases"]) >= 10
    assert verify_bundle(_load("valid-signed.bundle.json")) == (True, None)
    for case in doc["cases"]:
        ok, err = verify_bundle(case["bundle"])
        assert not ok and case["refusal"] in err, (case["name"], err)


def test_canonicalization_vectors():
    from bitexact_verifier import _canonical

    for case in _load("jcs-vectors.json")["cases"]:
        assert _canonical(case["input"]).decode("utf-8") == \
            case["expected_canonical"], case["name"]


def test_canonicalization_refusal_vectors():
    """The corpus's refused half is normative: what the recorder will not
    commit to, this verifier must refuse identically."""
    import pytest

    from bitexact_verifier import MAX_DEPTH, _canonical

    for case in _load("jcs-vectors.json")["refused"]:
        with pytest.raises(ValueError, match=case["reason"]):
            _canonical(case["input"])

    with pytest.raises(ValueError, match="keys must be strings"):
        _canonical({1: "a"})
    pair, astral = chr(0xD834) + chr(0xDD1E), chr(0x1D11E)
    with pytest.raises(ValueError, match="collide"):
        _canonical({pair: 1, astral: 2})

    # The nesting cap is part of the format, not a per-verifier knob: pinned
    # to the literal 128 so a standalone verifier cannot silently choose a
    # different depth and split verdicts with the recorder on a deep value.
    assert MAX_DEPTH == 128

    def nest(levels):
        value: object = 1
        for _ in range(levels):
            value = [value]
        return value

    assert _canonical(nest(128))
    with pytest.raises(ValueError, match="nesting"):
        _canonical(nest(129))


def test_signature_strictness_is_this_files_own():
    """The checks a raw RFC 8032 backend does not make must hold here no
    matter which backend is beneath: a small-order key (one signature
    authenticating two chosen messages), a malleated S >= L spelling of a
    valid signature, a whitespace spelling of one, and the range predicate's
    wiring itself."""
    import bitexact_verifier
    from bitexact_verifier import _L, _canonical, _canonical_scalar, \
        _ed25519_verify

    # eprint 2020/1244, Appendix A: against this small-order key the same
    # signature authenticates both messages under a verifier without the
    # blocklist.
    key = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    signature = ("a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a"
                 "7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc66"
                 "37b45450ac04")
    assert _ed25519_verify(key, b"Send 100 USD to Alice", signature) is False
    assert _ed25519_verify(key, b"Send 100000 USD to Alice",
                           signature) is False

    # the range predicate is exact at the boundary
    assert _canonical_scalar((_L - 1).to_bytes(32, "little")) is True
    assert _canonical_scalar(_L.to_bytes(32, "little")) is False
    assert _canonical_scalar((_L + 1).to_bytes(32, "little")) is False

    # a real signature from the golden bundle: verifies as spelled, fails
    # under the S + L spelling and under a whitespace-padded spelling
    bundle = _load("valid-signed.bundle.json")
    signed = bundle["signature"]
    body = {"format": bundle["format"], "run_id": bundle["run_id"],
            "chain": bundle["chain"], "signed_at": signed["signed_at"],
            "key_id": signed["key_id"]}
    if "checkpoints" in bundle:
        body["checkpoints"] = bundle["checkpoints"]
    if "anchors" in bundle:
        body["anchors"] = bundle["anchors"]
    if "tlog" in bundle:
        body["tlog"] = bundle["tlog"]
    data = _canonical(body)
    good = signed["signature"]
    assert _ed25519_verify(signed["public_key"], data, good) is True
    s_value = int.from_bytes(bytes.fromhex(good[64:]), "little")
    malleated = good[:64] + (s_value + _L).to_bytes(32, "little").hex()
    assert _ed25519_verify(signed["public_key"], data, malleated) is False
    # whitespace-padded spellings all decode to the same bytes; the
    # full-string hex match refuses interior AND trailing padding, where a
    # prefix match would let the trailing spellings verify.
    for spelling in (good[:64] + "  " + good[64:], good + " ", good + "\n"):
        assert bytes.fromhex(spelling) == bytes.fromhex(good)
        assert _ed25519_verify(signed["public_key"], data, spelling) is False
    assert _ed25519_verify(signed["public_key"] + " ", data, good) is False

    # the predicate is consulted, not inherited from the backend
    original = bitexact_verifier._canonical_scalar
    bitexact_verifier._canonical_scalar = lambda s: False
    try:
        assert _ed25519_verify(signed["public_key"], data, good) is False
    finally:
        bitexact_verifier._canonical_scalar = original


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
    """The golden redacted bundle was redacted at EXPORT time: its markers
    carry no on-chain claim. Under bundle-key trust it verifies; under
    recorder-key trust it is refused as unaccountable, because an export
    redaction is the exporter's act and the recorder never attested it -
    however valid the exporter's own signature is."""
    bundle = _load("valid-redacted.bundle.json")
    trust = _load("trust.json")
    ok, err = verify_bundle(
        bundle,
        trusted_bundle_keys=[k["public_key"] for k in trust["bundle_keys"]])
    assert ok, err
    assert any(e.get("redacted") for e in bundle["entries"])
    ok, err = verify_bundle(
        bundle,
        trusted_bundle_keys=[k["public_key"] for k in trust["bundle_keys"]],
        trusted_recorder_keys=[k["public_key"]
                               for k in trust["recorder_keys"]])
    assert not ok and "unaccountable" in err


def test_golden_dsse_envelope_verifies():
    envelope = _load("valid.dsse.json")
    ok, err, bundle = verify_envelope(envelope)
    assert ok, err
    assert bundle["run_id"] == "golden-run"


def test_envelope_pins_keys_with_expect_key_and_trust():
    # A DSSE envelope must honor key pinning: the right key passes, a
    # wrong one fails. Without this, the envelope's key-match logic is
    # untested and could be inverted without any test noticing.
    envelope = _load("valid.dsse.json")
    key = envelope["signatures"][0]["public_key"]
    ok, err, _ = verify_envelope(envelope, expect_key=key)
    assert ok, err
    ok, _, _ = verify_envelope(envelope, expect_key="aa" * 32)
    assert not ok
    ok, err, _ = verify_envelope(envelope, trusted_bundle_keys=[key])
    assert ok, err
    ok, _, _ = verify_envelope(envelope, trusted_bundle_keys=["bb" * 32])
    assert not ok


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
    assert by_kind["context"][0]["data"]["content"]
    assert "content_hash" not in by_kind["context"][0]["data"]
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


def _reforge_entries(bundle):
    """Recompute every entry hash and prev-link so a body edit yields a
    self-consistent chain - the re-forge a tamperer performs, leaving only
    the targeted integrity check to fire. Sets the chain head to match."""
    from bitexact_verifier import _canonical, _hash_hex

    prev = "0" * 64
    for i, entry in enumerate(bundle["entries"]):
        entry["prev"] = prev
        body = {k: v for k, v in entry.items()
                if k not in ("hash", "data", "salts", "redacted")}
        entry["hash"] = _hash_hex(entry["alg"], _canonical(body))
        prev = entry["hash"]
    bundle["chain"] = {"head_hash": prev}
    return bundle


def _unsigned_base():
    """A signed golden bundle stripped to its unsigned chain: it verifies
    with no key, so each entry-level integrity check is the sole defense and
    a tamper isolates exactly the check meant to catch it."""
    bundle = _load("valid-signed.bundle.json")
    for key in ("signature", "checkpoints", "anchors", "tlog"):
        bundle.pop(key, None)
    assert verify_bundle(bundle) == (True, None)
    return bundle


def test_entry_chain_integrity_checks_are_each_pinned():
    """Every per-entry and chain-head integrity check the verifier walks is
    the sole defense on an unsigned bundle; deleting any one lets a forged
    bundle verify. Each tamper below fails today and fails only because its
    check is present."""
    # per-entry body hash: a backdated timestamp with its stale hash kept -
    # nothing else covers ts/kind/ctx, so this is a standalone fail-open if
    # the hash check goes.
    b = _unsigned_base()
    b["entries"][0]["ts"] = "1999-01-01T00:00:00+00:00"
    assert verify_bundle(b)[0] is False

    # per-entry run_id binding: the bundle is relabeled while its entries
    # keep the original id - run misattribution.
    b = _unsigned_base()
    b["run_id"] = "some-other-run"
    assert verify_bundle(b)[0] is False

    # per-entry step index: a re-forged chain whose one entry claims the
    # wrong position.
    b = _unsigned_base()
    b["entries"][1]["step"] = 99
    _reforge_entries(b)
    assert verify_bundle(b)[0] is False

    # per-entry prev link: the first entry must chain from genesis. Its own
    # hash is recomputed over the bad prev so the body-hash check passes and
    # only the prev-link check fires.
    from bitexact_verifier import _canonical, _hash_hex
    b = _unsigned_base()
    e0 = b["entries"][0]
    e0["prev"] = "ff" * 32
    body0 = {k: v for k, v in e0.items()
             if k not in ("hash", "data", "salts", "redacted")}
    e0["hash"] = _hash_hex(e0["alg"], _canonical(body0))
    _reforge_entries_from(b, 1)
    assert verify_bundle(b)[0] is False

    # chain head_hash: the declared head must equal the final entry's hash.
    b = _unsigned_base()
    b["chain"]["head_hash"] = "ab" * 32
    assert verify_bundle(b)[0] is False

    # uncommitted data: a field present in data with no commitment binding it.
    b = _unsigned_base()
    b["entries"][0]["data"]["smuggled"] = "unbound"
    assert verify_bundle(b)[0] is False

    # an unsigned bundle presented under a trusted-key demand must be
    # refused rather than waved through - the spec-mandated posture.
    b = _unsigned_base()
    assert verify_bundle(b, expect_key="ab" * 32)[0] is False
    assert verify_bundle(b, trusted_bundle_keys=["ab" * 32])[0] is False


def _reforge_entries_from(bundle, start):
    """Re-link the chain from entry `start` onward, leaving earlier entries
    (and any deliberate corruption in them) untouched."""
    from bitexact_verifier import _canonical, _hash_hex

    prev = bundle["entries"][start - 1]["hash"]
    for entry in bundle["entries"][start:]:
        entry["prev"] = prev
        body = {k: v for k, v in entry.items()
                if k not in ("hash", "data", "salts", "redacted")}
        entry["hash"] = _hash_hex(entry["alg"], _canonical(body))
        prev = entry["hash"]
    bundle["chain"] = {"head_hash": prev}
    return bundle


def _signed_checkpointed_bundle():
    """Build a two-entry bundle with two recorder-signed checkpoints from
    scratch, using cryptography directly (no product import). Returns the
    bundle, the recorder public hex, and a re-sign helper so a structural
    checkpoint field can be tampered while its signature stays valid - which
    is what isolates each checkpoint check from the checkpoint signature."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import _canonical, _hash_hex

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def entry(i, prev):
        body = {"alg": "blake2b-256","run_id": "r", "step": i,
                "kind": "run_meta" if i == 0 else "tool_call", "prev": prev,
                "prov": "observed", "ts": "2026-09-02T00:00:00+00:00",
                "commitments": {}}
        return {**body, "hash": _hash_hex("blake2b-256", _canonical(body)),
                "data": {}}

    e0 = entry(0, "0" * 64)
    e1 = entry(1, e0["hash"])
    entries = [e0, e1]

    def checkpoint(seq, steps, head, prev_cp):
        from bitexact_verifier import _key_id
        attested = {"run_id": "r", "seq": seq, "steps": steps,
                    "head_hash": head, "prev_checkpoint": prev_cp,
                    "alg": "blake2b-256", "key_id": _key_id(pub)}
        sig = priv.sign(_canonical(attested)).hex()
        return {**attested, "public_key": pub, "signature": sig}

    cp0 = checkpoint(0, 1, e0["hash"], "0" * 64)
    cp0_hash = _hash_hex("blake2b-256", _canonical(
        {k: cp0[k] for k in ("run_id", "seq", "steps", "head_hash",
                             "prev_checkpoint", "alg", "key_id")}))
    cp1 = checkpoint(1, 2, e1["hash"], cp0_hash)
    bundle = {"format": "aer-bundle", "run_id": "r",
              "entries": entries, "chain": {"head_hash": e1["hash"]},
              "checkpoints": [cp0, cp1]}

    def resign(cp):
        attested = {k: cp[k] for k in ("run_id", "seq", "steps", "head_hash",
                                       "prev_checkpoint", "alg", "key_id")}
        cp["signature"] = priv.sign(_canonical(attested)).hex()
        return cp

    return bundle, pub, resign


def test_checkpoint_structural_checks_are_each_pinned():
    """Each structural checkpoint check, and the checkpoint signature and
    recorder-key pin, is pinned separately. A structural tamper is re-signed
    so the signature stays valid and only the structural check fires; the
    signature and key-pin blocks pin those directly."""
    base, pub, resign = _signed_checkpointed_bundle()
    assert verify_bundle(base, expect_recorder_key=pub) == (True, None)

    # Each block rebuilds with its own recorder key, tampers one structural
    # field, and re-signs - so the checkpoint signature stays valid and the
    # structural check is the sole remaining defense.

    # sequence gap
    b, pub, resign = _signed_checkpointed_bundle()
    b["checkpoints"][1]["seq"] = 5
    resign(b["checkpoints"][1])
    assert verify_bundle(b, expect_recorder_key=pub)[0] is False

    # checkpoint chain broken (wrong prev_checkpoint)
    b, pub, resign = _signed_checkpointed_bundle()
    b["checkpoints"][1]["prev_checkpoint"] = "ab" * 32
    resign(b["checkpoints"][1])
    assert verify_bundle(b, expect_recorder_key=pub)[0] is False

    # truncation semantic: a checkpoint attesting more steps than the bundle
    # carries is refused - history removed below a signed checkpoint. The
    # step-count check and the attested-head check both guard this; the head
    # check is isolated in its own block below.
    b, pub, resign = _signed_checkpointed_bundle()
    b["checkpoints"][1]["steps"] = 9
    resign(b["checkpoints"][1])
    assert verify_bundle(b, expect_recorder_key=pub)[0] is False

    # attested head does not match the chain at that step
    b, pub, resign = _signed_checkpointed_bundle()
    b["checkpoints"][1]["head_hash"] = "cd" * 32
    resign(b["checkpoints"][1])
    assert verify_bundle(b, expect_recorder_key=pub)[0] is False

    # run_id mismatch between checkpoint and bundle
    b, pub, resign = _signed_checkpointed_bundle()
    b["checkpoints"][1]["run_id"] = "other"
    resign(b["checkpoints"][1])
    assert verify_bundle(b, expect_recorder_key=pub)[0] is False

    # step-count truncation, isolated with a null attested head so the
    # attested-head check does not also fire on the missing step.
    b, pub, resign = _signed_checkpointed_bundle()
    b["checkpoints"][1]["steps"] = 9
    b["checkpoints"][1]["head_hash"] = None
    resign(b["checkpoints"][1])
    assert verify_bundle(b, expect_recorder_key=pub)[0] is False

    # checkpoint signature: a corrupted signature over otherwise valid
    # structure - the signature is the checkpoint's whole authenticity.
    b, pub, resign = _signed_checkpointed_bundle()
    sig = b["checkpoints"][1]["signature"]
    b["checkpoints"][1]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    assert verify_bundle(b, expect_recorder_key=pub)[0] is False

    # checkpoint recorder-key pin: a checkpoint validly signed by a key that
    # is not the demanded recorder key must be refused.
    b, pub, resign = _signed_checkpointed_bundle()
    assert verify_bundle(b, expect_recorder_key="ab" * 32)[0] is False
    assert verify_bundle(b, trusted_recorder_keys=["ab" * 32])[0] is False


def test_worm_anchor_authenticity_is_pinned():
    """A WORM anchor's recorder signature and key pinning are its whole
    authenticity; each is the sole guard against a forged external anchor."""
    base = _load("valid-worm-anchor.bundle.json")
    assert verify_bundle(base)[0] is True

    b = _load("valid-worm-anchor.bundle.json")
    sig = b["anchors"][0]["signature"]
    b["anchors"][0]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    assert verify_bundle(b)[0] is False

    assert verify_bundle(base, expect_recorder_key="ab" * 32)[0] is False
    assert verify_bundle(base, trusted_recorder_keys=["ab" * 32])[0] is False


def test_rfc3161_anchor_tsa_pin_is_enforced():
    """A pinned TSA certificate that did not sign the token is refused - a
    timestamp from any other authority must not pass as the trusted one."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    base = _load("valid-rfc3161-anchor.bundle.json")
    assert verify_bundle(base)[0] is True

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-the-tsa")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2040, 1, 1))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    assert verify_bundle(base, expect_tsa=pem)[0] is False


def test_ledger_heads_negative_vectors_each_fail_closed(tmp_path, capsys):
    """A workflow pack the product wrote verifies, its governance ledger
    anchored at the head the recorder signed; every cut its holder can make
    and reseal without the recorder key - the newest event dropped, an older
    prefix put in its place, the signed heads or the ledger removed - fails
    with exit 2 and the vector's refusal, the recorder key pinned or not."""
    import shutil

    from bitexact_verifier import main
    data = _load("ledger-heads-negative-vectors.json")
    source = Path(__file__).parent / "testdata" / data["bag"]
    [recorder] = _load("trust.json")["recorder_keys"]
    pins = ([], ["--expect-recorder-key", recorder["public_key"],
                 "--expect-recorder-pq-key", recorder["pq_public_key"]])
    for pin in pins:
        assert main([str(source), *pin]) == 0
        line = capsys.readouterr().out.splitlines()[0]
        assert "data/governance.jsonl at 3 events" in line
    assert "anchored at the head the pinned recorder key signed" in line
    assert len(data["cases"]) == 4
    for n, case in enumerate(data["cases"]):
        bag = tmp_path / f"c{n}"
        shutil.copytree(source, bag)
        ledger = bag / "data" / "governance.jsonl"
        if case["keep_events"] is not None:
            lines = ledger.read_text(encoding="utf-8").splitlines(
                keepends=True)
            ledger.write_text("".join(lines[:case["keep_events"]]),
                              encoding="utf-8")
        if case["remove"] is not None:
            (bag / case["remove"]).unlink()
        _reseal(bag)
        for pin in pins:
            assert main([str(bag), *pin]) == 2, case["name"]
            assert f"FAIL: {case['refusal']}" in capsys.readouterr().out, \
                case["name"]


def test_anchor_negative_vectors_each_fail_closed():
    """Every guard in the verifier's external-anchor path is pinned red-if-
    removed by a committed vector: a bundle that is valid but for one defective
    anchor must FAIL, naming the guard that caught it. Anchors are what detect a
    store rolled back below an externally-held head, or a timestamp that proves
    nothing about this run - so if an independent reimplementation of the trust
    root (or a refactor of this file) dropped rollback detection, head-binding,
    imprint-binds-head, or the timeStamping-EKU check, it must FAIL conformance,
    not silently accept a truncated-below-anchor bundle. Each case carries the
    shared valid `base` plus a single anchor tripping exactly one guard."""
    data = _load("anchor-negative-vectors.json")
    base = data["base"]
    # positive control: the shared base, anchor-free, verifies - so every
    # failure below is the anchor's doing, not a broken base.
    ok, err = verify_bundle({k: v for k, v in base.items() if k != "anchors"})
    assert ok, err
    assert len(data["cases"]) >= 17
    for case in data["cases"]:
        bundle = {**base, "anchors": [case["anchor"]]}
        ok, err = verify_bundle(bundle)
        assert not ok, f"{case['guard']}: a defective anchor was accepted"
        assert case["expect_substring"] in err, (case["guard"], err)


def test_recorder_key_pin_requires_the_head_to_be_covered():
    """Under recorder-key pinning an unsigned tail past the last recorder
    checkpoint must be refused. A bundle whose HEAD is not covered by a
    recorder checkpoint or worm anchor is not recorder-authenticated, however
    valid its prefix checkpoints - this is what rejects a forged tail appended
    past genuine recorder material (an unsigned run_end's step count is not
    hash-covered). Without a shipping vector an independent verifier could drop
    the head-coverage check, still pass conformance, and certify a forged tail
    as recorder-signed."""
    base, pub, _resign = _signed_checkpointed_bundle()
    # cp1 covers the head (steps == entries) -> the full bundle is accepted.
    assert verify_bundle(base, expect_recorder_key=pub) == (True, None)
    # Drop the head-covering checkpoint, leaving only cp0 (steps=1) while the
    # head is entry 2 - a prefix checkpoint with an unsigned tail past it.
    base["checkpoints"] = [base["checkpoints"][0]]
    ok, err = verify_bundle(base, expect_recorder_key=pub)
    assert not ok and "covers the bundle head" in err
    # identical under the trust-file path
    ok, err = verify_bundle(base, trusted_recorder_keys=[pub])
    assert not ok and "covers the bundle head" in err


def _signed_bundle_no_recorder_material():
    """A validly bundle-key-signed bundle with NO checkpoints and NO anchors,
    built from scratch (no product import). Returns (bundle, bundle_public_hex).
    The signed body is exactly what the verifier's signed branch re-checks:
    {format, run_id, chain, signed_at, key_id}."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import _canonical, _hash_hex, _key_id

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def entry(i, prev):
        body = {"alg": "blake2b-256","run_id": "r", "step": i,
                "kind": "run_meta" if i == 0 else "tool_call", "prev": prev,
                "prov": "observed", "ts": "2026-09-02T00:00:00+00:00",
                "commitments": {}}
        return {**body, "hash": _hash_hex("blake2b-256", _canonical(body)),
                "data": {}}

    e0 = entry(0, "0" * 64)
    e1 = entry(1, e0["hash"])
    bundle = {"format": "aer-bundle", "run_id": "r",
              "entries": [e0, e1], "chain": {"head_hash": e1["hash"]}}
    stamp = "2026-09-02T00:00:00+00:00"
    signed_body = {"format": bundle["format"], "run_id": bundle["run_id"],
                   "chain": bundle["chain"], "signed_at": stamp,
                   "key_id": _key_id(pub)}
    bundle["signature"] = {"algorithm": "ed25519", "public_key": pub,
                           "key_id": _key_id(pub), "signed_at": stamp,
                           "signature": priv.sign(_canonical(signed_body)).hex()}
    return bundle, pub


def test_signed_bundle_with_no_recorder_material_fails_a_recorder_demand():
    """A validly bundle-key-signed bundle that carries NO checkpoints and NO
    worm anchors verifies on its own, but must FAIL an --expect-recorder-key /
    --trust-file recorder demand: there is nothing the recorder signed. The
    signed branch checks only the bundle key, never the recorder key, so this
    is the sole guard for a signed, checkpoint-less bundle - without it a bundle
    with zero recorder attestation would be certified as recorder-authenticated,
    the exact downgrade recorder-key pinning exists to prevent."""
    b, _pub = _signed_bundle_no_recorder_material()
    assert verify_bundle(b) == (True, None)                    # valid on its own
    ok, err = verify_bundle(b, expect_recorder_key="cd" * 32)
    assert not ok and "no checkpoints or worm anchors" in err
    ok, err = verify_bundle(b, trusted_recorder_keys=["cd" * 32])
    assert not ok and "no checkpoints or worm anchors" in err


def test_dsse_envelope_signature_is_pinned():
    """The envelope signature authenticates the whole in-toto statement; an
    envelope carrying a forged signature must not verify."""
    import base64

    from bitexact_verifier import verify_envelope

    env = _load("valid.dsse.json")
    assert verify_envelope(env)[0] is True

    forged = json.loads(json.dumps(env))
    forged["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64).decode()
    assert verify_envelope(forged)[0] is False


def test_a_committed_field_dropped_without_a_marker_is_refused():
    """Evidence cannot be silently removed: a committed field whose value is
    gone with no redaction marker fails, so a bundle cannot drop data while
    claiming to preserve it."""
    base = _load("valid-redacted.bundle.json")
    assert verify_bundle(base)[0] is True

    b = _load("valid-redacted.bundle.json")
    entry = b["entries"][2]
    del entry["data"]["result"]["temp"]
    entry.get("salts", {}).pop("result.temp", None)
    ok, err = verify_bundle(b)
    assert ok is False and "without a redaction marker" in err


def test_cli_consumes_fixtures(capsys):
    assert main([str(TESTDATA / "valid-signed.bundle.json")]) == 0
    assert "OK" in capsys.readouterr().out
    assert main([str(TESTDATA / "valid.dsse.json")]) == 0
    # The full trust file names recorder keys, and an export-time redaction is
    # not recorder-accountable: the CLI refuses it. Bundle-key trust alone
    # verifies the exporter's signature and reports the redaction.
    assert main([str(TESTDATA / "valid-redacted.bundle.json"),
                 "--trust-file", str(TESTDATA / "trust.json")]) == 2
    assert "unaccountable" in capsys.readouterr().out
    bundle_only = TESTDATA.parent / "test_bundle_only_trust.json"
    trust = _load("trust.json")
    bundle_only.write_text(json.dumps({"bundle_keys": trust["bundle_keys"]}),
                           encoding="utf-8")
    try:
        assert main([str(TESTDATA / "valid-redacted.bundle.json"),
                     "--trust-file", str(bundle_only)]) == 0
        out = capsys.readouterr().out
        assert "redacted" in out
    finally:
        bundle_only.unlink()


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
    b["entries"][0]["v"] = 2  # a version field is no part of an entry
    cases.append((b, "step 0: hash mismatch"))

    b = _golden()
    b["entries"][0]["alg"] = "md5"
    cases.append((b, "unsupported hash algorithm"))

    for bundle, needle in cases:
        ok, err = verify_bundle(bundle)
        assert not ok and needle in err, (needle, err)


def test_wrong_recorder_trust_fails():
    bundle = _load("valid-signed.bundle.json")
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

    e = json.loads(json.dumps(good))
    e["payload"] = base64.b64encode(b"not json").decode()
    ok, err, _ = verify_envelope(e)
    assert not ok  # signature over altered payload fails first

    # re-signing is impossible without the key, so digest tampering is
    # caught by the envelope signature - craft an unsigned-check instead
    ok, err, _ = verify_envelope(dict(good, signatures=[]))
    assert not ok and "signature" in err


def test_canonicalization_rejects_nan_and_unsupported_types():
    import pytest

    from bitexact_verifier import _canonical

    with pytest.raises(ValueError):
        _canonical(float("nan"))
    # TypeError for a type JSON has no representation for, matching the
    # product's canonicalizer - the two refuse the same values with the same
    # exception, so neither can drift without a test noticing.
    with pytest.raises(TypeError):
        _canonical({"x": object()})


def test_canonicalization_is_not_steerable_by_subclasses():
    """A str/int/float/dict subclass overriding its dunders cannot change the
    bytes: the canonicalizer reads the true value, or refuses. A drifted
    mirror that trusted the subclass would split verdicts from the recorder."""
    from bitexact_verifier import _canonical

    class EvilStr(str):
        def encode(self, *a, **k):
            return b"\x00"

    class EvilInt(int):
        def __repr__(self):
            return "999"

    class EvilFloat(float):
        def __repr__(self):
            return "9.9"

    class EvilGet(dict):
        def __getitem__(self, key):
            return "STEERED"

    assert _canonical({EvilStr("b"): 1, "a": 2}) == b'{"a":2,"b":1}'
    assert _canonical({"n": EvilInt(1)}) == b'{"n":1}'
    assert _canonical({"n": EvilFloat(1.5)}) == b'{"n":1.5}'
    assert _canonical(EvilGet({"a": "kept"})) == b'{"a":"kept"}'


def test_number_formatter_matches_the_v8_corpus():
    """The hand-written ECMAScript number formatter is the piece most likely
    to drift from the spec. These vectors were generated by V8 itself (via
    the generator published with RFC 8785), so they are an independent oracle
    rather than a sibling Python port that could drift in step."""
    import struct

    import pytest

    from bitexact_verifier import _es6_number

    checked = 0
    refused = []
    for line in (TESTDATA / "es6-numbers.txt").read_text(
            encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        bits, expected = line.split(",", 1)
        (value,) = struct.unpack(">d", bytes.fromhex(bits.rjust(16, "0")))
        checked += 1
        try:
            assert _es6_number(value) == expected, bits
        except ValueError:
            refused.append(bits)
    assert checked >= 4000, f"corpus shrank to {checked} vectors"
    # negative zero is the dialect's one refusal in the corpus (errata 7920)
    assert set(refused) == {"8000000000000000"}, sorted(set(refused))


# Table 6b of "Taming the many EdDSAs" (eprint.iacr.org/2020/1244): all
# fourteen serializations of ed25519's eight small-order points, both sign
# bits. Held in full so this suite fails if the shipped blocklist loses an
# entry or drops the sign-bit mask that folds the pairs together.
_SMALL_ORDER_ENCODINGS = (
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
)


def test_small_order_blocklist_is_complete():
    """Against any of these keys a zero signature verifies every message, so
    the blocklist must recognize all fourteen - tested through the predicate,
    since through _ed25519_verify an invalid signature fails anyway and the
    assertion would pass with entries missing."""
    from bitexact_verifier import _is_small_order

    for encoding in _SMALL_ORDER_ENCODINGS:
        assert _is_small_order(bytes.fromhex(encoding)) is True, encoding


def test_a_public_key_with_whitespace_in_its_hex_is_refused():
    """bytes.fromhex skips embedded ASCII whitespace, so a padded spelling of
    a key would decode to fewer than 32 bytes; the strict-hex shape check
    refuses it rather than reading short."""
    import pytest

    from bitexact_verifier import _ed25519_verify

    good = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
    spaced = good[:60] + "  " + good[62:]
    assert len(bytes.fromhex(spaced)) == 31
    assert _ed25519_verify(spaced, b"m", "ab" * 64) is False


def test_a_bundle_repeating_an_object_key_is_refused():
    """RFC 8785 section 3.1 forbids duplicate names; a parser has already discarded
    the repeat before canonicalization, so the refusal lives at the parse
    boundary. A relying party must not get a clean verdict on a line two
    parsers read differently."""
    import pytest

    from bitexact_verifier import _loads

    with pytest.raises(ValueError, match="duplicate key"):
        _loads('{"a": 1, "a": 2}')


def test_sha256_bundle_verifies():
    """The fixture is built with hashlib/hmac directly, independent of the
    verifier's own alg dispatch."""
    import hashlib
    import hmac

    from bitexact_verifier import _canonical

    salt = "ab" * 16
    commitment = hmac.new(bytes.fromhex(salt), _canonical(1),
                          hashlib.sha256).hexdigest()
    entry = {"alg": "sha256", "run_id": "r", "step": 0,
             "kind": "http_call", "prov": "observed",
             "ts": "2026-09-02T00:00:00+00:00", "prev": "0" * 64,
             "commitments": {"x": commitment}}
    entry["hash"] = hashlib.sha256(_canonical(entry)).hexdigest()
    entry["data"] = {"x": 1}
    entry["salts"] = {"x": salt}
    bundle = {"format": "aer-bundle", "run_id": "r",
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
    assert not ok and "tlog" in err   # a log proof of a checkpoint not carried
    del bundle["tlog"]
    ok, err = verify_bundle(bundle)
    assert ok, err  # unsigned, nothing demanded - still fine

    ok, err = verify_bundle(bundle, expect_recorder_key="ab" * 32)
    assert not ok and "checkpoint" in err

    ok, err = verify_bundle(bundle, trusted_recorder_keys=["ab" * 32])
    assert not ok and "checkpoint" in err

    path = tmp_path / "forged.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert main([str(path), "--expect-recorder-key", "ab" * 32]) == 2
    assert "FAIL" in capsys.readouterr().out

    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps(
        {"recorder_keys": [{"key_id": "x", "public_key": "ab" * 32}]}),
        encoding="utf-8")
    assert main([str(path), "--trust-file", str(trust)]) == 2
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
        # The trust file is the auditor's input: a bad one is an operational
        # error (exit 1), never a verdict on the bundle.
        assert main([str(bundle_path), "--trust-file", str(trust)]) == 1, text
        out = capsys.readouterr().out
        assert out.startswith("error: ") and needle in out, (text, out)


def test_verify_functions_never_throw(tmp_path, capsys):
    # salts/commitments/redacted are guarded with a precise reason, not left to
    # the outer catch-all, so the standalone agrees with the product on the
    # reason - and a `redacted` that is iterable (a dict) would verify ok
    # without the guard, so its guard is verdict-load-bearing, not cosmetic.
    b = _golden()
    b["entries"][1]["salts"] = ["not", "a", "dict"]
    ok, err = verify_bundle(b)
    assert ok is False and "salts is not a JSON object" in err

    b = _golden()
    b["entries"][1]["redacted"] = {"a": 1}  # iterable -> would verify ok
    ok, err = verify_bundle(b)
    assert ok is False and "redacted is not a JSON array" in err

    b = _golden()
    b["entries"][1]["redacted"] = [["x"]]  # list w/ unhashable element -> set()
    ok, err = verify_bundle(b)
    assert ok is False and "redacted is not a JSON array of strings" in err

    from bitexact_verifier import _canonical, _hash_hex  # noqa: E402
    b = _golden()  # commitments IS hash-covered: recompute so the guard is hit
    e = b["entries"][1]
    e["commitments"] = 5
    body = {k: v for k, v in e.items()
            if k not in ("hash", "data", "salts", "redacted")}
    e["hash"] = _hash_hex(e["alg"], _canonical(body))
    ok, err = verify_bundle(b)
    assert ok is False and "commitments is not a JSON object" in err

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
    assert main([str(path)]) == 2
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
    from bitexact_verifier import _key_id
    attested = {"run_id": "some-other-run", "seq": 0, "steps": 0,
                "head_hash": "0" * 64, "prev_checkpoint": "0" * 64,
                "alg": "blake2b-256", "key_id": _key_id(public)}
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
    # Kept when a JSON parser reading the digits back as a double reproduces
    # them; refused when it would not, which is what makes the bytes the same
    # in every implementation.
    assert _canonical({"n": 2 ** 53}) == b'{"n":9007199254740992}'
    with pytest.raises(ValueError):
        _canonical({"n": 2 ** 53 + 1})
    with pytest.raises(ValueError):
        _canonical({"n": 10 ** 21})


def test_cli_rejects_malformed_bundle_with_nan(tmp_path, capsys):
    bad = tmp_path / "nan.json"
    bad.write_text('{"format": "aer-bundle", "run_id": "r", '
                   '"entries": [{"alg": "blake2b-256",'
                   '"run_id": "r", "step": 0, "kind": "http_call", "ts": "2026-09-02T00:00:00+00:00", '
                   '"prev": "' + "0" * 64 + '", "data": {"x": NaN}, '
                   '"salts": {}, "commitments": {}, "hash": "beef"}], '
                   '"chain": {"head_hash": "beef"}}', encoding="utf-8")
    assert main([str(bad)]) == 2
    assert "FAIL" in capsys.readouterr().out


def test_cli_rejects_duplicate_keys(tmp_path, capsys):
    # A duplicate key makes the document ambiguous - two values, and a lenient
    # last-wins parser would silently pick one. The CLI refuses it with a
    # verdict and exit 1, not a traceback: the same refusal the loader gives
    # everywhere, extended to the last two unguarded parses (bundle, trust).
    dup = tmp_path / "dup.json"
    dup.write_text('{"format": "aer-bundle", '
                   '"format": "aer-bundle", "run_id": "r", '
                   '"entries": [], "chain": {"head_hash": "beef"}}',
                   encoding="utf-8")
    assert main([str(dup)]) == 2
    assert "FAIL" in capsys.readouterr().out

    bundle_path = TESTDATA / "valid-signed.bundle.json"
    trust = tmp_path / "trust.json"
    trust.write_text('{"bundle_keys": [], "bundle_keys": []}',
                     encoding="utf-8")
    assert main([str(bundle_path), "--trust-file", str(trust)]) == 1
    assert capsys.readouterr().out.startswith("error: ")


def test_cli_totality_on_invalid_utf8(tmp_path, capsys):
    # main() reads the bundle/trust files with a strict UTF-8 codec. The read
    # decodes BEFORE the parse, so the decode must be guarded too: a stray
    # 0xFF (a truncated multibyte char, latin-1 mojibake) in a bundle is a
    # FAIL (exit 2), in the auditor's trust file an error (exit 1), and never
    # a traceback.
    bad = tmp_path / "bad.json"
    bad.write_bytes(b'{"format": "aer-bundle", "run_id": "r\xff", '
                    b'"entries": [], "chain": {"head_hash": "beef"}}\n')
    assert main([str(bad)]) == 2
    assert "FAIL" in capsys.readouterr().out

    bundle_path = TESTDATA / "valid-signed.bundle.json"
    bad_trust = tmp_path / "trust.bin"
    bad_trust.write_bytes(b'{"bundle_keys": "\xff"}')
    assert main([str(bundle_path), "--trust-file", str(bad_trust)]) == 1
    assert capsys.readouterr().out.startswith("error: ")


def test_cli_main_is_total_on_hostile_files(tmp_path, capsys):
    # main() is a verify surface. The class the per-round audits kept
    # surfacing one instance at a time is "glue code (decode, DSSE dispatch,
    # indexing) touches a hostile shape before a verify call and escapes as a
    # traceback." This sweeps the hostile file shapes and asserts the closure:
    # main() renders a verdict (returns 0 or 2), never raises. A future glue
    # crash on any of these shapes turns it red.
    text_shapes = [
        "null", "123", "1.5", "true", "false", '"a string"',
        "[]", "[1, 2, 3]", "{}", '{"format": 5}',
        "", "   ", "not json", "{", "[", "}{",
        '{"format": "aer-bundle"',            # truncated
        '{"a": 1} trailing',                         # trailing junk
        '{"a": 1, "a": 2}',                          # duplicate key
        '{"x": NaN}', '{"x": Infinity}',             # non-finite literals
        '{"payloadType": 5}',                        # DSSE-shaped, unsupported
        '{"format": "aer-bundle-jsonl"}',     # jsonl header, no entries
    ]
    byte_shapes = [b"\xff\xfe", b'{"run_id": "\xff"}', b"\xef\xbb\xbf null",
                   b"\xc3"]                            # BOM+scalar, lone byte
    p = tmp_path / "b.json"
    for text in text_shapes:
        p.write_text(text, encoding="utf-8")
        assert main([str(p)]) in (0, 2), text     # the point: it does not raise
        capsys.readouterr()
    for data in byte_shapes:
        p.write_bytes(data)
        assert main([str(p)]) in (0, 2), data
        capsys.readouterr()

    # the top-level boundary: a nonexistent path is a named error, not a
    # traceback
    assert main([str(tmp_path / "missing.json")]) == 1
    assert capsys.readouterr().out.startswith("error: no such file")
    # the scalar-dispatch instance specifically: routed to verify_bundle (a
    # clean "not a bundle" verdict), not a TypeError from `in` on a scalar.
    p.write_text("null", encoding="utf-8")
    assert main([str(p)]) == 2
    assert "not a bundle: the document is null" in capsys.readouterr().out


def test_loads_rejects_nonfinite():
    # Mirror the product loader: Infinity/-Infinity/NaN are refused at the
    # parse boundary (RFC 8785 section 3.2), not left to trip a downstream encoder.
    from bitexact_verifier import _loads
    for tok in ("Infinity", "-Infinity", "NaN", '{"x": NaN}',
                '{"x": 1e999}', "[-1e999]",  # overflow literal parses to inf too
                "[" * 1500 + "]" * 1500):  # deeper than MAX_DEPTH too
        try:
            _loads(tok)
        except ValueError:
            continue
        raise AssertionError(f"{tok[:20]!r} was not refused")
    assert _loads('{"a": 1}') == {"a": 1}


def test_a_stack_exhausted_parse_is_refused_by_name():
    """The refusal must not depend on which interpreter the auditor ran.

    How deep CPython's JSON scanner recurses before exhausting the stack
    depends on the host's stack. Where a deeply nested array raises
    RecursionError inside json.loads, before the MAX_DEPTH check downstream
    of it can refuse, the caller would read `malformed bundle:
    RecursionError(...)` rather than the reason.

    `setrecursionlimit` cannot reproduce that on the C scanner, so the guard
    itself is what is pinned here: whatever exhausts the parser, the seam
    refuses by name.
    """
    import bitexact_verifier as bv
    from bitexact_verifier import _loads

    def _exhausted(*args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    real = bv.json.loads
    bv.json.loads = _exhausted
    try:
        _loads("[]")
    except ValueError as exc:
        assert "nesting deeper" in str(exc), f"refused, but as {exc!r}"
    except RecursionError as exc:
        raise AssertionError(
            f"an exhausted parse escaped the seam as {exc!r}, not a named "
            f"refusal") from None
    else:
        raise AssertionError("an exhausted parse was not refused")
    finally:
        bv.json.loads = real


def test_data_paths_skip_non_string_keys():
    # Byte-identical to the product's commitment_paths: a non-string key is
    # skipped, not a crash. Unreachable through JSON (object keys are always
    # strings), but the two path generators must not diverge on a hand-built
    # dict passed straight to verify_bundle.
    from bitexact_verifier import _data_paths
    assert _data_paths({1: "x"}) == []                       # non-string top key
    assert _data_paths({"a": {"b": 1}, 3: "z"}) == ["a.b"]   # top key 3 skipped
    assert _data_paths({"a": {"b": 1, 4: "q"}}) == ["a.b"]   # sub-key 4 skipped


def _jsonl_lines(bundle, signature=None):
    header = {"format": "aer-bundle-jsonl",
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
        {"format": "aer-bundle-jsonl", "run_id": "r",
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
    assert main([str(bad)]) == 2
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
    from bitexact_verifier import _key_id
    signed_body = {"format": "aer-bundle-jsonl",
                   "run_id": bundle["run_id"], "chain": bundle["chain"],
                   "signed_at": "2026-09-02T00:00:00Z",
                   "key_id": _key_id(public)}
    signature = {"algorithm": "ed25519", "key_id": _key_id(public),
                 "public_key": public, "signed_at": "2026-09-02T00:00:00Z",
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
        from bitexact_verifier import PROV_BY_KIND
        body = {"alg": "blake2b-256","run_id": run_id, "step": i,
                "kind": kind, "prov": PROV_BY_KIND[kind][0],
                "ts": "2026-09-02T00:00:00+00:00", "prev": prev,
                "commitments": commitments}
        h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
        entries.append({**body, "hash": h, "data": data,
                        "salts": {k: salt for k in data}})
        prev = h

    add("http_call", {"model": "gpt-4o"})
    add("run_end", {"steps": 2})
    return {"format": "aer-bundle", "run_id": run_id,
            "entries": entries, "chain": {"head_hash": entries[-1]["hash"]}}


def test_verifier_enforces_run_end_seal_finality():
    import hashlib

    from bitexact_verifier import _canonical, verify_bundle

    bundle = _sealed_bundle()
    ok, err = verify_bundle(bundle)
    assert ok, err

    # append a behavioral entry after the seal - must FAIL
    tampered = json.loads(json.dumps(bundle))
    prev = tampered["entries"][-1]["hash"]
    body = {"alg": "blake2b-256","run_id": "sealed-run", "step": 2,
            "kind": "http_call", "prov": "observed", "ts": "2026-09-02T00:00:00+00:00",
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
    header = {"format": "aer-bundle-jsonl", "run_id": "sealed-run",
              "chain": bundle["chain"]}
    lines = [json.dumps(header)] + [json.dumps(e) for e in bundle["entries"]]
    ok, err, _ = verify_jsonl(lines)
    assert ok, err

    prev = bundle["entries"][-1]["hash"]
    body = {"alg": "blake2b-256","run_id": "sealed-run", "step": 2,
            "kind": "http_call", "prov": "observed", "ts": "2026-09-02T00:00:00+00:00",
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
    # still present - the claim is false and must FAIL
    entries = bundle["entries"][:1]  # just the http_call
    salt = "ef" * 16
    data = {"fields": ["0:model"], "by": "auditor"}
    commitments = {k: _field_commitment(salt, v, "blake2b-256")
                   for k, v in data.items()}
    body = {"alg": "blake2b-256","run_id": "sealed-run", "step": 1,
            "kind": "redaction", "prov": "asserted", "ts": "2026-09-02T00:00:00+00:00",
            "prev": entries[0]["hash"], "commitments": commitments}
    h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
    entries.append({**body, "hash": h, "data": data,
                    "salts": {k: salt for k in data}})
    b = {"format": "aer-bundle", "run_id": "sealed-run",
         "entries": entries, "chain": {"head_hash": h}}
    ok, err = verify_bundle(b)
    assert not ok and "redaction claim is false" in err

    header = {"format": "aer-bundle-jsonl", "run_id": "sealed-run",
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
    body = {"alg": "blake2b-256","run_id": "sealed-run", "step": 1,
            "kind": "redaction", "prov": "asserted", "ts": "2026-09-02T00:00:00+00:00",
            "prev": entries[0]["hash"], "commitments": commitments}
    h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
    entries.append({**body, "hash": h, "data": data,
                    "salts": {k: salt for k in data}})
    b = {"format": "aer-bundle", "run_id": "sealed-run",
         "entries": entries, "chain": {"head_hash": h}}
    ok, err = verify_bundle(b)
    assert ok, err


def test_verifier_rejects_unknown_provenance():
    import hashlib

    from bitexact_verifier import _canonical, verify_bundle

    body = {"alg": "blake2b-256","run_id": "r", "step": 0,
            "kind": "http_call", "prov": "sneaky", "ts": "2026-09-02T00:00:00+00:00",
            "prev": "0" * 64, "commitments": {}}
    h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
    bundle = {"format": "aer-bundle", "run_id": "r",
              "entries": [{**body, "hash": h, "data": {}, "salts": {}}],
              "chain": {"head_hash": h}}
    ok, err = verify_bundle(bundle)
    assert not ok and "provenance" in err


def test_verifier_accepts_committed_decision_record():
    """A governance decision_record - retention deadline + basis, per-flag
    output flags, and adverse-action reason codes - verifies offline like any
    committed entry, and tampering a single output flag is caught. Proves the
    new evidence type is independently verifiable and that each flag is its
    own commitment (output_flags is a dict -> one committed path per flag)."""
    import hashlib

    from bitexact_verifier import _canonical, _field_commitment, verify_bundle

    salt = "ab" * 16
    data = {"retention_deadline": "2028-09-14T00:00:00Z",
            "retention_basis": "reg-b-1002.12-25mo",
            "output_flags": {"is_adverse_action": True,
                             "is_automated_decision": True,
                             "contains_pii": True},
            "reason_codes": ["income-insufficient", "credit-history-short"]}
    # Commitment paths mirror the product: one per top-level scalar/list, plus
    # one per second-level key of the output_flags dict.
    commitments = {p: _field_commitment(salt, v, "blake2b-256")
                   for p, v in (("retention_deadline", data["retention_deadline"]),
                                ("retention_basis", data["retention_basis"]),
                                ("reason_codes", data["reason_codes"]))}
    for k, v in data["output_flags"].items():
        commitments[f"output_flags.{k}"] = _field_commitment(salt, v, "blake2b-256")
    body = {"alg": "blake2b-256","run_id": "gov-run", "step": 0,
            "kind": "decision_record", "prov": "asserted", "ts": "2026-09-02T00:00:00+00:00",
            "prev": "0" * 64, "commitments": commitments}
    h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
    entry = {**body, "hash": h, "data": data,
             "salts": {p: salt for p in commitments}}
    bundle = {"format": "aer-bundle", "run_id": "gov-run",
              "entries": [entry], "chain": {"head_hash": h}}
    ok, err = verify_bundle(bundle)
    assert ok, err

    tampered = json.loads(json.dumps(bundle))
    tampered["entries"][0]["data"]["output_flags"]["is_adverse_action"] = False
    assert verify_bundle(tampered)[0] is False


# --- provenance bundles: cross-run graph, built with verifier primitives ---

def _prov_run_bundle(run_id, fork_data=None, via=None):
    """A run bundle as a provenance bag carries it; `via`, when given, names
    the capture path on every entry."""
    import hashlib

    from bitexact_verifier import _canonical, _field_commitment

    salt = "ab" * 16
    entries, prev = [], "0" * 64

    def add(kind, data, prov="observed"):
        nonlocal prev
        commitments = {k: _field_commitment(salt, v, "blake2b-256")
                       for k, v in data.items()}
        body = {"alg": "blake2b-256","run_id": run_id,
                "step": len(entries), "kind": kind, "prov": prov, "ts": "2026-09-02T00:00:00+00:00",
                "prev": prev, "commitments": commitments}
        if via is not None:
            body["via"] = via
        h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
        entries.append({**body, "hash": h, "data": data,
                        "salts": {k: salt for k in data}})
        prev = h

    add("run_meta", {"v": "1"})
    if fork_data is not None:
        add("fork", fork_data)
    add("http_call", {"model": "m"})
    add("run_end", {"steps": len(entries) + 1})
    bundle = {"format": "aer-bundle", "run_id": run_id,
              "entries": entries, "chain": {"head_hash": entries[-1]["hash"]}}
    return bundle, entries


def _write_prov_bag(bag_dir, specs, root, attestation=None, via=None):
    """specs: [(run_id, fork_data|None)]. Returns (graph, {run_id: entries})."""
    import hashlib

    bag = Path(bag_dir)
    (bag / "data" / "runs").mkdir(parents=True)
    ids = {rid for rid, _ in specs}
    nodes, edges, ents = [], [], {}
    for rid, fork in specs:
        bundle, entries = _prov_run_bundle(rid, fork, via)
        (bag / "data" / "runs" / (rid + ".bundle.json")).write_text(
            json.dumps(bundle), encoding="utf-8")
        ents[rid] = entries
        in_bag = fork is not None and fork.get("source_run") in ids
        nodes.append({"run_id": rid, "bundle": "runs/" + rid + ".bundle.json",
                      "head_hash": entries[-1]["hash"],
                      "role": "fork" if in_bag else "original"})
        if in_bag:
            edges.append({"child": rid, "source_run": fork["source_run"],
                          "at_step": fork["at_step"],
                          "source_prev_hash": fork["source_prev_hash"]})
    graph = {"format": "aer-provenance-graph", "root": root,
             "nodes": nodes, "edges": edges, "fork_matrices": []}
    (bag / "data" / "provenance-graph.json").write_text(json.dumps(graph),
                                                        encoding="utf-8")
    if attestation is not None:
        (bag / "data" / "attestations").mkdir(parents=True)
        (bag / "data" / "attestations" / "provenance.dsse.json").write_text(
            json.dumps(attestation), encoding="utf-8")
    payload = sorted(p for p in (bag / "data").rglob("*") if p.is_file())
    lines = [hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.relative_to(bag).as_posix()
             for p in payload]
    (bag / "bagit.txt").write_text(
        "BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n",
        encoding="utf-8")
    (bag / "manifest-sha256.txt").write_text("\n".join(lines) + "\n",
                                             encoding="utf-8")
    (bag / "bag-info.txt").write_text(f"External-Identifier: {root}\n",
                                      encoding="utf-8")
    tags = [hashlib.sha256((bag / n).read_bytes()).hexdigest() + "  " + n
            for n in ("bagit.txt", "bag-info.txt", "manifest-sha256.txt")]
    (bag / "tagmanifest-sha256.txt").write_text("\n".join(tags) + "\n",
                                                encoding="utf-8")
    return graph, ents


def _linked_forks():
    """orig -> fork-a -> fork-b with correct committed prefix hashes."""
    _, orig_e = _prov_run_bundle("orig")
    fa = {"source_run": "orig", "at_step": 2,
          "source_prev_hash": orig_e[1]["hash"]}
    _, fa_e = _prov_run_bundle("fork-a", fa)
    fb = {"source_run": "fork-a", "at_step": 2,
          "source_prev_hash": fa_e[1]["hash"]}
    return [("orig", None), ("fork-a", fa), ("fork-b", fb)], fa, fb


def _pack_run(run_id, *, sealed=True, gap=False, relay=None, via=None):
    """A run bundle as a case, workflow or selection pack carries it; `via`,
    when given, names the capture path on every entry."""
    import hashlib

    from bitexact_verifier import _canonical, _data_paths, _field_commitment
    entries, prev = [], "0" * 64

    def leaf(value, path):
        for part in path.split("."):
            value = value[part]
        return value

    def add(kind, data, prov="observed"):
        nonlocal prev
        paths = list(_data_paths(data))          # one commitment per leaf
        commitments = {p: _field_commitment("ab" * 16, leaf(data, p),
                                            "blake2b-256") for p in paths}
        body = {"alg": "blake2b-256","run_id": run_id,
                "step": len(entries), "kind": kind, "prov": prov,
                "ts": "2026-09-02T00:00:00+00:00", "prev": prev,
                "commitments": commitments}
        if via is not None:
            body["via"] = via
        h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
        entries.append({**body, "hash": h, "data": data,
                        "salts": {p: "ab" * 16 for p in paths}})
        prev = h
    add("run_meta", {"v": "1"})
    add("http_call", {"model": "m"} if relay is None else
        {"model": "m", "aer_source": {"peer": relay, "seq": 1}})
    if gap:
        add("marker", {"note": "capture gap: serialization",
                       "gap": {"cause": "serialization"}}, prov="asserted")
    if sealed:
        add("run_end", {"steps": len(entries) + 1})
    return {"format": "aer-bundle", "run_id": run_id,
            "entries": entries, "chain": {"head_hash": entries[-1]["hash"]}}


def _ledger(n=3):
    """A hash-chained ledger of n events, as the product writes case and
    workflow ledgers."""
    import hashlib

    from bitexact_verifier import _canonical
    events, prev = [], "0" * 64
    for i in range(n):
        body = {"ts": f"2026-09-02T00:00:0{i}+00:00", "kind": "note_added",
                "by": "alice", "data": {"i": i}, "prev": prev,
                "alg": "blake2b-256"}
        h = hashlib.blake2b(_canonical(body), digest_size=32).hexdigest()
        events.append({**body, "hash": h})
        prev = h
    return events


_HEADS_KEY = None


def _heads_key():
    """The recorder key the test packs' ledger heads are signed with."""
    global _HEADS_KEY
    if _HEADS_KEY is None:
        _HEADS_KEY = _ed_key()
    return _HEADS_KEY


def _sign_heads(bag, key=None, edit=None):
    """Sign the bag's ledger heads (`ledger_heads`) as the recorder does,
    with `key` (an Ed25519 private key; the suite's by default), after
    `edit(statement)` when given, and write data/ledger-heads.json."""
    from cryptography.hazmat.primitives import serialization

    from bitexact_verifier import HEADS_FILE, _canonical, _key_id, ledger_heads
    key = key or _heads_key()[0]
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    heads = ledger_heads(bag)
    if edit:
        edit(heads)
    attested = {**heads, "key_id": _key_id(public)}
    (Path(bag) / "data" / HEADS_FILE).write_text(json.dumps({
        **attested, "public_key": public,
        "signature": key.sign(_canonical(attested)).hex()}),
        encoding="utf-8")


def _write_pack(bag_dir, runs, ledgers=None, heads=True):
    """A bag with run bundles and ledgers but no provenance graph:
    {relative path: events} for each ledger, `.jsonl` or `.ledger.json`,
    and the ledger heads signed by the suite's recorder key (`heads`: True,
    a key to sign with, or False for none). A ledger that is not a list of
    events has no head to sign; its walk fails before any head is read."""
    bag = Path(bag_dir)
    (bag / "data" / "runs").mkdir(parents=True)
    for bundle in runs:
        (bag / "data" / "runs" / f"{bundle['run_id']}.bundle.json").write_text(
            json.dumps(bundle), encoding="utf-8")
    for rel, events in (ledgers or {}).items():
        path = bag / "data" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"events": events}) if rel.endswith(".json") else
            "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    if heads and all(isinstance(events, list) and all(
            isinstance(e, dict) for e in events)
            for events in (ledgers or {}).values()):
        _sign_heads(bag, None if heads is True else heads)
    _reseal(bag)
    return bag


def _reseal(bag):
    """Rewrite a bag's checksums over its payload, as anyone holding it can."""
    import hashlib

    payload = sorted(p for p in (bag / "data").rglob("*") if p.is_file())
    (bag / "bagit.txt").write_text(
        "BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n",
        encoding="utf-8")
    (bag / "manifest-sha256.txt").write_text("".join(
        hashlib.sha256(p.read_bytes()).hexdigest() + "  "
        + p.relative_to(bag).as_posix() + "\n" for p in payload),
        encoding="utf-8")
    (bag / "bag-info.txt").write_text("External-Identifier: pack\n",
                                      encoding="utf-8")
    (bag / "tagmanifest-sha256.txt").write_text("".join(
        hashlib.sha256((bag / n).read_bytes()).hexdigest() + "  " + n + "\n"
        for n in ("bagit.txt", "bag-info.txt", "manifest-sha256.txt")),
        encoding="utf-8")
    return bag


def test_an_evidence_pack_verifies_its_runs_and_its_ledgers(tmp_path, capsys):
    """A case, workflow or selection pack carries no provenance graph; the
    verifier checks it whole - the bag, every run, every ledger."""
    from bitexact_verifier import main
    bag = _write_pack(tmp_path / "p", [_pack_run("a"), _pack_run("b")],
                      {"case.jsonl": _ledger(),
                       "case/c.ledger.json": _ledger(2)})
    assert main([str(bag)]) == 0
    line = capsys.readouterr().out.strip()
    assert line.startswith(
        "OK: evidence pack - 2 runs verified, 2 ledgers chain-verified to a "
        "signed head (data/case.jsonl at 3 events; data/case/c.ledger.json at "
        "2 events; recorder key not pinned - pass --expect-recorder-key to "
        "know no newest event is missing)")
    assert "unsigned" in line
    # Pinned: these runs carry no recorder checkpoints, so the pinned pack
    # is one of refusals and a ledger.
    pinned = _write_pack(tmp_path / "r", [], {
        "refusals/job-1.jsonl": _refusals(n=1), "case.jsonl": _ledger(1)})
    assert main([str(pinned), "--expect-recorder-key", _heads_key()[1]]) == 3
    assert ("1 ledger chain-verified and anchored at the head the pinned "
            "recorder key signed (data/case.jsonl at 1 event)"
            ) in capsys.readouterr().out
    bare = _write_pack(tmp_path / "q", [_pack_run("a")])
    assert main([str(bare)]) == 0
    assert "ledger" not in capsys.readouterr().out


def test_a_ledger_cut_or_swapped_under_its_signed_head_fails_the_pack(
        tmp_path, capsys):
    """The pack holder can edit any file in the bag and reseal it, but not
    sign as the recorder. A ledger whose newest events were dropped, or
    which was replaced by an older prefix, still re-walks; it no longer
    ends at the head the recorder signed, and the pack fails naming it."""
    from bitexact_verifier import main
    full = _ledger(3)
    # A pack of refusals and the ledger: its runs would need recorder
    # checkpoints of their own to verify with the recorder key pinned.
    for n, events in enumerate((full[:2], _ledger(1))):
        bag = _write_pack(tmp_path / f"p{n}", [],
                          {"refusals/job-1.jsonl": _refusals(n=1),
                           "governance.jsonl": full})
        (bag / "data" / "governance.jsonl").write_text(
            "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
        _reseal(bag)
        for pins in ([], ["--expect-recorder-key", _heads_key()[1]]):
            assert main([str(bag), *pins]) == 2
            assert (f"FAIL: ledger data/governance.jsonl ends at "
                    f"{len(events)} event{'s' if len(events) > 1 else ''} "
                    f"(head {events[-1]['hash']}), not at the head the "
                    f"recorder signed: 3 events (head {full[-1]['hash']})"
                    ) in capsys.readouterr().out


def test_a_ledger_heads_statement_that_does_not_stand_fails_the_pack(
        tmp_path, capsys):
    from bitexact_verifier import HEADS_FILE, main, verify_provenance_bundle
    other, other_public = _ed_key()

    def bag(name, edit=None, key=None, heads=True, ledgers=None, runs=True):
        path = _write_pack(tmp_path / name, [_pack_run("a")] if runs else [],
                           {"case.jsonl": _ledger()} if ledgers is None
                           else ledgers, heads=heads)
        if edit or key:
            _sign_heads(path, key, edit)
            _reseal(path)
        return path

    def doc_edit(path, change):
        target = path / "data" / HEADS_FILE
        doc = json.loads(target.read_text(encoding="utf-8"))
        target.write_text(json.dumps(change(doc) or doc), encoding="utf-8")
        _reseal(path)
        return path

    def problem(heads):
        heads["ledgers"][0]["problem"] = "event 3: ledger truncated"

    def extra(heads):
        heads["ledgers"].append({"path": "data/gone.jsonl", "events": 1,
                                 "head_hash": "ab" * 32, "problem": None})

    def runs(heads):
        heads["runs"].append({"run_id": "b", "steps": 2,
                              "head_hash": "cd" * 32})

    def unsigned_ledger(heads):
        heads["ledgers"].clear()

    cases = [
        (bag("none", heads=False),
         "the pack carries no signed ledger heads (data/ledger-heads.json) - "
         "nothing anchors its ledgers' newest events"),
        (bag("bare", heads=False, ledgers={}),
         "the pack carries no signed ledger heads"),
        (doc_edit(bag("format"), lambda d: d.update(format="x")),
         "data/ledger-heads.json is not an aer-ledger-heads statement"),
        (doc_edit(bag("list"), lambda d: [d]),
         "data/ledger-heads.json is not an aer-ledger-heads statement"),
        (doc_edit(bag("sig"), lambda d: d.update(signature="00" * 64)),
         "the ledger heads' signature does not verify"),
        (doc_edit(bag("kid"), lambda d: d.update(key_id="00" * 8)),
         "the ledger heads' signature does not verify"),
        (doc_edit(bag("pq"), lambda d: d.update(pq_alg="ML-DSA-65")),
         "the ledger heads: post-quantum signature is incomplete"),
        (bag("problem", problem),
         "ledger data/case.jsonl failed the recorder's own verification "
         "when it signed its head: event 3: ledger truncated"),
        (bag("unsigned", unsigned_ledger),
         "ledger data/case.jsonl ends at 3 events (head "),
        (bag("extra", extra),
         "the recorder signed a head for a ledger the pack does not carry "
         "('data/gone.jsonl') - removed from it"),
        (bag("runs", runs),
         "the ledger heads were signed for another set of runs than the "
         "pack holds - its ledgers and their heads are not this pack's"),
    ]
    for path, why in cases:
        assert main([str(path)]) == 2, why
        assert f"FAIL: {why}" in capsys.readouterr().out, why
    assert "not at the head the recorder signed: none" in (
        verify_provenance_bundle(str(cases[8][0]))[1])

    # Signed by a key the caller did not pin: the holder's own re-signing.
    resigned = bag("resigned", key=other, runs=False,
                   ledgers={"refusals/job-1.jsonl": _refusals(n=1),
                            "case.jsonl": _ledger()})
    assert main([str(resigned)]) == 3                # refusals are gaps
    capsys.readouterr()
    assert main([str(resigned), "--expect-recorder-key",
                 _heads_key()[1]]) == 2
    assert ("FAIL: the ledger heads are not signed by the pinned recorder "
            "key") in capsys.readouterr().out
    ok, err, _ = verify_provenance_bundle(
        str(resigned), trusted_recorder_keys=[_heads_key()[1]])
    assert (ok, err) == (False, "the ledger heads are not signed by the "
                                "pinned recorder key")
    assert verify_provenance_bundle(
        str(resigned), trusted_recorder_keys=[other_public])[0]


def test_a_ledger_that_does_not_rewalk_fails_the_pack(tmp_path, capsys):
    from bitexact_verifier import main
    edited, odd_alg, no_alg = _ledger(), _ledger(1), _ledger(1)
    edited[-1]["data"] = {"i": 99}
    odd_alg[0]["alg"] = "md5"
    del no_alg[0]["alg"]
    cases = [("not a list", "is not a list of events"),
             (["not an object"], "event 0 is not an object"),
             (_ledger()[1:], "event 0: chain broken"),
             (edited, "event 2: hash mismatch"),
             (odd_alg, "event 0: hash mismatch"),
             (no_alg, "event 0: names no hash algorithm")]
    for n, (events, why) in enumerate(cases):
        bag = _write_pack(tmp_path / f"p{n}", [_pack_run("a")],
                          {"case/c.ledger.json": events})
        assert main([str(bag)]) == 2, why
        assert f"ledger data/case/c.ledger.json {why}" in \
            capsys.readouterr().out, why


def test_a_pack_with_a_broken_or_missing_run_fails(tmp_path, capsys):
    from bitexact_verifier import main
    broken = _pack_run("a")
    broken["entries"][1]["data"]["model"] = "other"
    assert main([str(_write_pack(tmp_path / "p", [broken]))]) == 2
    assert "run 'a'" in capsys.readouterr().out
    assert main([str(_write_pack(tmp_path / "q", []))]) == 2
    assert "no run bundles" in capsys.readouterr().out


def test_a_pack_without_bag_info_verifies(tmp_path, capsys):
    """bag-info.txt is optional (RFC 8493 section 2.2.2): a pack that omits
    it declares no Payload-Oxum, so there is no count to check."""
    import hashlib

    from bitexact_verifier import main
    bag = _write_pack(tmp_path / "p", [_pack_run("a")])
    (bag / "bag-info.txt").unlink()
    (bag / "tagmanifest-sha256.txt").write_text("".join(
        hashlib.sha256((bag / n).read_bytes()).hexdigest() + "  " + n + "\n"
        for n in ("bagit.txt", "manifest-sha256.txt")), encoding="utf-8")
    assert main([str(bag)]) == 0
    assert capsys.readouterr().out.startswith(
        "OK: evidence pack - 1 run verified")


def test_a_pack_reports_unsealed_runs_and_gates_on_gaps(tmp_path, capsys):
    from bitexact_verifier import main
    bag = _write_pack(tmp_path / "p", [_pack_run("a", sealed=False),
                                       _pack_run("b", gap=True)])
    assert main([str(bag)]) == 3                     # a declared gap
    line = capsys.readouterr().out.strip()
    assert "1 run unsealed" in line and "1 declared capture gap -" in line
    assert main([str(bag), "--allow-gaps"]) == 0
    capsys.readouterr()
    assert main([str(bag), "--require-sealed"]) == 2
    assert "unsealed run a -" in capsys.readouterr().out


def _refusals(name="job-1", n=2, key=None, run_id="same"):
    """A refusal ledger as the product writes one: `refused` events,
    hash-chained, each signed by `key` (an Ed25519 private key) when given."""
    import hashlib

    from bitexact_verifier import _canonical, _key_id
    events, prev = [], "0" * 64
    for i in range(n):
        body = {"ts": f"2026-10-18T00:00:0{i}+00:00", "kind": "refused",
                "by": "sdk", "prev": prev, "alg": "blake2b-256",
                "data": {"run_id": name if run_id == "same" else run_id,
                         "cause": "license_lapsed", "where": "sdk"}}
        body["hash"] = hashlib.blake2b(
            _canonical({k: v for k, v in body.items()}),
            digest_size=32).hexdigest()
        if key is not None:
            from cryptography.hazmat.primitives import serialization
            public = key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw).hex()
            body = {**body, "sig": key.sign(_canonical(body)).hex(),
                    "public_key": public, "key_id": _key_id(public)}
        events.append(body)
        prev = body["hash"]
    return events


def _ed_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    return key, key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def test_a_pack_counts_its_refusals_as_executions_without_evidence(
        tmp_path, capsys):
    from bitexact_verifier import main
    key, public = _ed_key()
    bag = _write_pack(tmp_path / "p", [_pack_run("a")], {
        "refusals/job-1.jsonl": _refusals(key=key),
        "refusals/job-2.jsonl": _refusals("job-2", n=1),
        "refusals/run-id-rejected.jsonl": _refusals(
            "run-id-rejected", n=1, run_id=None)})
    assert main([str(bag)]) == 3                     # executions lacked evidence
    line = capsys.readouterr().out.strip()
    assert "1 run verified, bag checksums" in line   # refusals are not ledgers
    assert ("4 recorded refusals - executions that left no run (2 signed by "
            "a recorder key, unpinned)") in line
    assert "declared capture gap" not in line
    assert main([str(bag), "--allow-gaps"]) == 0
    capsys.readouterr()
    # The ledger heads are signed by the pinned key in both: the refusals by
    # it in the first, by another key in the second.
    other, other_public = _ed_key()
    for pin, signed, signer in ((public, 2, key), (other_public, 0, other)):
        only = _write_pack(tmp_path / f"q{signed}", [], {
            "refusals/job-1.jsonl": _refusals(key=key),
            "refusals/job-2.jsonl": _refusals("job-2", n=1)}, heads=signer)
        assert main([str(only), "--expect-recorder-key", pin]) == 3
        assert (f"3 recorded refusals - executions that left no run "
                f"({signed} signed by the pinned recorder key)") in \
            capsys.readouterr().out


def test_a_pack_of_only_refusals_verifies_and_is_never_complete(
        tmp_path, capsys):
    from bitexact_verifier import main
    bag = _write_pack(tmp_path / "p", [],
                      {"refusals/job-1.jsonl": _refusals(n=1)})
    assert main([str(bag)]) == 3
    out = capsys.readouterr().out
    assert "0 runs verified" in out and "bundle unsigned" in out


def test_a_refusal_ledger_that_is_not_one_fails_the_pack(tmp_path, capsys):
    from bitexact_verifier import _canonical, main
    key, _ = _ed_key()
    forged = _refusals(key=key)
    forged[1]["sig"] = key.sign(b"something else").hex()
    wrong_id = _refusals(key=key)
    wrong_id[0]["key_id"] = "00" * 8
    import hashlib
    not_refusal = _refusals(n=1)
    not_refusal[0]["kind"] = "note_added"
    del not_refusal[0]["hash"]
    not_refusal[0]["hash"] = hashlib.blake2b(_canonical(
        {k: not_refusal[0][k] for k in ("ts", "kind", "by", "data", "prev",
                                        "alg")}), digest_size=32).hexdigest()
    cases = [(forged, "event 1: signature does not verify"),
             (wrong_id, "event 0: signature does not verify"),
             (_refusals(run_id="job-9"),
              "event 0 names another run than its ledger"),
             (not_refusal, "event 0 is not a refusal"),
             (_refusals()[1:], "event 0: chain broken")]
    for n, (events, why) in enumerate(cases):
        bag = _write_pack(tmp_path / f"p{n}", [_pack_run("a")],
                          {"refusals/job-1.jsonl": events})
        assert main([str(bag)]) == 2, why
        assert f"ledger data/refusals/job-1.jsonl {why}" in \
            capsys.readouterr().out, why


# --- the transparency log, with only the verifier and `cryptography` -------

def _tlog_fixture(n=3, index=1, witnesses=("w1",), threshold=1):
    """A head checkpoint, a log of `n` leaves holding it at `index`, a
    checkpoint note the recorder key signed, and cosignatures from
    `witnesses`. Returns (proof, checkpoints, trust, keys)."""
    import base64
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import Trust, _canonical

    def raw(key):
        return key.public_key().public_bytes_raw()

    def kid(name, kind, key):
        return hashlib.sha256(name.encode() + b"\n" + kind + raw(key)).digest()[:4]

    def h(b):
        return hashlib.sha256(b).digest()

    def mth(leaves):
        if len(leaves) == 1:
            return h(b"\x00" + leaves[0])
        k = 1
        while k * 2 < len(leaves):
            k *= 2
        return h(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))

    def path(leaves, m):
        if len(leaves) == 1:
            return []
        k = 1
        while k * 2 < len(leaves):
            k *= 2
        return (path(leaves[:k], m) + [mth(leaves[k:])] if m < k else
                path(leaves[k:], m - k) + [mth(leaves[:k])])

    recorder = Ed25519PrivateKey.generate()
    head = {"run_id": "r", "seq": 1, "steps": 3, "head_hash": "ab" * 32,
            "prev_checkpoint": None, "alg": "blake2b-256", "key_id": "k1",
            "public_key": raw(recorder).hex()}
    attested = {k: head[k] for k in ("run_id", "seq", "steps", "head_hash",
                                     "prev_checkpoint", "alg", "key_id")}
    leaf = _canonical(attested)
    leaves = [b"other-%d" % i for i in range(n)]
    leaves[index] = leaf
    origin = "log.example/one"
    text = (f"{origin}\n{n}\n{base64.b64encode(mth(leaves)).decode()}\n")
    lines = [f"— {origin} " + base64.b64encode(
        kid(origin, b"\x01", recorder) + recorder.sign(text.encode())).decode()]
    pinned = {}
    for name in witnesses:
        wkey = Ed25519PrivateKey.generate()
        pinned[name] = raw(wkey).hex()
        stamp = (1_700_000_000).to_bytes(8, "big")
        sig = wkey.sign(f"cosignature/v1\ntime 1700000000\n{text}".encode())
        lines.append(f"— {name} " + base64.b64encode(
            kid(name, b"\x04", wkey) + stamp + sig).decode())
    proof = {"note": text + "\n" + "\n".join(lines) + "\n",
             "leaf": leaf.decode(), "index": index, "size": n,
             "proof": [base64.b64encode(p).decode()
                       for p in path(leaves, index)]}
    trust = Trust(expect_witnesses=pinned or None, witness_threshold=threshold)
    return proof, [head], trust, {"recorder": recorder, "text": text}


def test_a_log_proof_with_its_witnesses_holds_at_every_position():
    from bitexact_verifier import _check_tlog, _log_note
    for n, index in ((1, 0), (2, 0), (3, 0), (3, 2), (5, 4), (8, 3)):
        proof, cps, trust, _ = _tlog_fixture(n=n, index=index)
        assert _check_tlog(proof, cps, trust) is None, (n, index)
    assert "witnessed by 1 of 1 pinned" in _log_note(proof, trust)
    unpinned = trust._replace(expect_witnesses=None)
    assert _check_tlog(proof, cps, unpinned) is None
    assert "witnesses not pinned" in _log_note(proof, unpinned)
    assert _log_note(None, trust) == ""


def test_an_unsigned_bundle_under_a_pinned_key_names_its_recorder():
    """A pinned key on an unsigned bundle is most often the recorder's key
    given where the exporter's belongs; the refusal names the recorder key id
    and the flag that pins it, and only key ids it can read."""
    from bitexact_verifier import Trust, _check_bundle_signature
    trust = Trust(expect_key="ab" * 32)
    base = "bundle is unsigned but a trusted key was required - refusing to verify"
    for cps, said in (
            ([{"key_id": "k2"}, {"key_id": "k1"}, {"key_id": "k1"}],
             base + "; its checkpoints are signed by recorder key id k1, k2"
             " - to pin that recorder, pass its public key with"
             " --expect-recorder-key"),
            ([], base), ("not a list", base), ([7, {"key_id": 3}], base)):
        assert _check_bundle_signature({"checkpoints": cps}, trust, []) == (
            False, said), cps
    assert _check_bundle_signature({}, Trust(), []) == (True, None)


def test_a_log_proof_is_checked_against_the_head_checkpoints_key():
    """After a key rotation the log is signed by the head's key, not the
    first checkpoint's."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import _check_tlog
    proof, [head], trust, _ = _tlog_fixture(n=4, index=2)
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    older = {**head, "public_key": other.hex()}
    assert _check_tlog(proof, [older, head], trust) is None
    assert _check_tlog(proof, [head, older], trust) == (
        "tlog checkpoint is not signed by the recorder key")


def test_a_log_proof_that_does_not_hold_is_named():
    import base64

    from bitexact_verifier import _check_tlog
    proof, cps, trust, keys = _tlog_fixture(n=4, index=2)

    def fails(change, why, checkpoints=cps, using=trust):
        bad = dict(proof)
        change(bad)
        assert why in (_check_tlog(bad, checkpoints, using) or ""), why

    assert "carries no transparency-log proof" in _check_tlog(None, cps, trust)
    assert _check_tlog(None, cps, trust._replace(expect_witnesses=None)) is None
    fails(lambda p: None, "not a proof of a checkpoint", checkpoints=[])
    fails(lambda p: p.update(index=-1), "malformed")
    fails(lambda p: p.update(proof=["!!not base64"]), "malformed")
    fails(lambda p: p.update(leaf="{}"), "not the bundle's head")
    fails(lambda p: p.update(note="no blank line"), "not a checkpoint note")
    fails(lambda p: p.update(note="o\n1\n\n\n— x y\n"), "not a checkpoint note")
    fails(lambda p: p.update(note="o\n01\nAA==\n\n"), "not a checkpoint note")
    fails(lambda p: p.update(note="o\n1\n!!\n\n"), "not a checkpoint note")
    fails(lambda p: p.update(note="o\n1\nAAAA\n\n"), "not a checkpoint note")
    fails(lambda p: p.update(size=5), "size does not match")
    fails(lambda p: p.update(index=3), "does not hold")
    fails(lambda p: p.update(index=9), "does not hold")
    fails(lambda p: p.update(proof=p["proof"] + p["proof"]), "does not hold")
    # Lines a note may carry that are nobody's signature are passed over.
    origin = proof["note"].split("\n", 1)[0]
    noisy = (keys["text"] + "\nnot a signature line\n— nospace\n"
             f"— {origin} !!!\n" + proof["note"].split("\n\n", 1)[1])
    assert _check_tlog(dict(proof, note=noisy), cps, trust) is None
    stranger = keys["text"] + "\n— " + origin + " " + base64.b64encode(
        b"\x00" * 68).decode() + "\n"
    fails(lambda p: p.update(note=stranger), "not signed by the recorder")
    fails(lambda p: None, "cosigned by 1 of the pinned witnesses; 2 required",
          using=trust._replace(witness_threshold=2))


def test_the_cli_refuses_a_witness_pin_it_cannot_use(tmp_path, capsys):
    from bitexact_verifier import main
    bundle = tmp_path / "b.json"
    bundle.write_text("{}", encoding="utf-8")
    assert main([str(bundle), "--expect-witness", "nokey"]) == 1
    assert "NAME=KEY" in capsys.readouterr().out
    assert main([str(bundle), "--expect-witness", "w=" + "ab" * 32,
                 "--witness-threshold", "2"]) == 1
    assert "between 1 and the 1 pinned" in capsys.readouterr().out


# --- the log held against what the auditor holds ----------------------------

def _log_world():
    """A log of seven leaves: run r's head checkpoint at leaf 1, the same
    leaf logged again at 2, a refusal leaf at 3, a later head of r at 4,
    another run's head at 5 and a JSON leaf that is no checkpoint at 6.
    Gives notes the recorder key signs at any size, a bundle's proof of r's
    head at size 3, and tails of the log, each computed here from RFC 9162
    directly rather than by the verifier."""
    import base64
    import hashlib
    import types

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import _canonical

    def raw(key):
        return key.public_key().public_bytes_raw()

    def h(b):
        return hashlib.sha256(b).digest()

    def mth(leaves):
        if len(leaves) == 1:
            return h(b"\x00" + leaves[0])
        k = 1
        while k * 2 < len(leaves):
            k *= 2
        return h(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))

    def path(leaves, m):
        if len(leaves) == 1:
            return []
        k = 1
        while k * 2 < len(leaves):
            k *= 2
        return (path(leaves[:k], m) + [mth(leaves[k:])] if m < k else
                path(leaves[k:], m - k) + [mth(leaves[:k])])

    recorder = Ed25519PrivateKey.generate()
    origin = "log.example/one"

    def attested(run_id, seq, steps):
        return {"run_id": run_id, "seq": seq, "steps": steps,
                "head_hash": f"{seq:02x}" * 32, "prev_checkpoint": None,
                "alg": "blake2b-256", "key_id": "k1"}

    leaves = [b"other-0", _canonical(attested("r", 1, 3)),
              _canonical(attested("r", 1, 3)),
              b'{"ledger":"refusals","entity_id":"job"}',
              _canonical(attested("r", 2, 5)),
              _canonical(attested("s", 1, 1)), b"[1]"]

    def note(size, root=None, key=recorder, at=origin):
        text = (f"{at}\n{size}\n"
                f"{base64.b64encode(root or mth(leaves[:size])).decode()}\n")
        kid = hashlib.sha256(at.encode() + b"\n\x01" + raw(key)).digest()[:4]
        return (text + "\n— " + at + " "
                + base64.b64encode(kid + key.sign(text.encode())).decode()
                + "\n")

    def proof(index, size):
        return {"note": note(size), "leaf": leaves[index].decode(),
                "index": index, "size": size,
                "proof": [base64.b64encode(p).decode()
                          for p in path(leaves[:size], index)]}

    def frontier(start, of=leaves):
        out, lo = [], 0
        for bit in range(start.bit_length() - 1, -1, -1):
            if start >> bit & 1:
                out.append(mth(of[lo:lo + (1 << bit)]))
                lo += 1 << bit
        return out

    def tail(start, end, of=leaves):
        return {"from": start, "leaves": [t.decode() for t in of[start:end]],
                "left": [base64.b64encode(r).decode()
                         for r in frontier(start, of)]}

    def head(seq, steps):
        return {**attested("r", seq, steps), "public_key": raw(recorder).hex()}
    return types.SimpleNamespace(
        note=note, proof=proof, tail=tail, frontier=frontier, mth=mth,
        h=h, leaves=leaves, origin=origin, head=head, raw=raw,
        recorder=recorder)


def test_two_roots_at_one_size_fail_as_a_split_view():
    """L3: the log's key signing two roots for one size is the operator's
    own proof of equivocation - the bundle's checkpoint against a held one,
    or two held ones against each other."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import Trust, _check_tlog, _log_note
    w = _log_world()
    proof, cps = w.proof(1, 3), [w.head(1, 3)]

    def check(*held, **kw):
        return _check_tlog(proof, cps, Trust(log_checkpoints=held, **kw))

    split = (f"split view: log {w.origin} has two different roots at size "
             f"{{}}, both signed by its key")
    assert split.format(3) in check(w.note(3, root=bytes(32)))
    assert split.format(5) in check(w.note(5), w.note(5, root=b"\x01" * 32))
    assert check(w.note(3)) is None
    assert _log_note(proof, Trust(log_checkpoints=(w.note(3),)), cps).endswith(
        ", 1 held log checkpoint of this log, no two roots at one size")
    # Another log's checkpoint says nothing of this one; nor does a value
    # that is not a note's text.
    other = w.note(3, root=bytes(32), at="log.example/two")
    assert check(other, b"bytes") is None
    assert "held log checkpoint" not in _log_note(
        proof, Trust(log_checkpoints=(other,)), cps)
    # A note naming this log that its key did not sign is held against
    # nothing; under a trust file's rotation window, the next key's is.
    stranger = Ed25519PrivateKey.generate()
    assert check(w.note(3, key=stranger)) == (
        f"a held checkpoint of log {w.origin} (size 3) is not signed by its "
        f"key - it cannot be held against the bundle")
    rotated = w.raw(stranger).hex()
    assert check(w.note(3, key=stranger),
                 trusted_recorder_keys=[rotated]) is None
    assert split.format(3) in check(w.note(3, root=bytes(32), key=stranger),
                                    trusted_recorder_keys=[rotated])


def test_a_later_checkpoint_needs_the_head_to_be_the_runs_latest():
    """L4: given a checkpoint later than the bundle's, the run's head must
    be shown to be its latest logged one up to it - from the log's leaves
    after the head, which must give the held roots. A later head of the run
    fails the bundle and is named; asked about a point in time, the bundle
    stands as the run stood then and the later head is named."""
    from bitexact_verifier import Trust, _check_tlog, _log_note
    w = _log_world()
    proof, cps = w.proof(1, 3), [w.head(1, 3)]

    def check(held=(), tail=None, at=False):
        trust = Trust(log_checkpoints=held, log_tail=tail, point_in_time=at)
        return _check_tlog(proof, cps, trust), _log_note(proof, trust, cps)

    later = f"leaf 4, checkpoint 2 at step 5, head {'02' * 32}"
    err, _ = check((w.note(7),))
    assert ("a checkpoint of log log.example/one at size 7 is held, later "
            "than the bundle's at 3, but no log tail shows the leaves after "
            "the bundle's head: the bundle cannot be shown to be run 'r''s "
            "latest logged head") == err
    err, note = check((w.note(7),), at=True)
    assert err is None and note.endswith(
        ", as the run stood at log size 3: the log up to the held checkpoint "
        "at size 7 was not searched for a later head (no log tail reaches "
        "it)")
    err, _ = check((w.note(7),), w.tail(1, 7))
    assert err == ("the bundle's head is not run 'r''s latest logged head: "
                   f"log {w.origin} holds a later one - {later}")
    err, note = check((w.note(7),), w.tail(1, 7), at=True)
    assert err is None and note.endswith(
        ", 1 held log checkpoint of this log, no two roots at one size, as "
        "the run stood at log size 3 (asked about that point in time): the "
        f"log holds a later head of it - {later}")
    # A tail shorter than the newest held checkpoint has not shown it.
    err, _ = check((w.note(4), w.note(7)), w.tail(1, 4))
    assert err == (f"the log tail ends at size 4, before the held checkpoint "
                   f"of log {w.origin} at size 7: the bundle cannot be shown "
                   f"to be run 'r''s latest logged head")
    err, note = check((w.note(4), w.note(7)), w.tail(1, 4), at=True)
    assert err is None and note.endswith(
        ", as the run stood at log size 3: the log up to the held checkpoint "
        "at size 7 was not searched for a later head (no log tail reaches "
        "it)")
    # The tail up to the bundle's own checkpoint shows its head latest there.
    err, note = check((), w.tail(1, 3))
    assert err is None and note.endswith(
        ", the run's latest logged head as of log size 3")

    # The later head's own bundle is the run's latest, from any start.
    new, new_cps = w.proof(4, 7), [w.head(2, 5)]
    for start in range(5):
        trust = Trust(log_checkpoints=(w.note(7),), log_tail=w.tail(start, 7))
        assert _check_tlog(new, new_cps, trust) is None, start
        assert _log_note(new, trust, new_cps).endswith(
            ", the run's latest logged head as of log size 7")


def test_a_log_tail_that_is_not_the_logs_is_refused():
    """The tail is the operator's, so it proves nothing until its leaves
    give a root the log's key signed - and a held root they do not give,
    below the one they do, is a fork of the log."""
    from bitexact_verifier import Trust, _check_tlog
    w = _log_world()
    proof, cps = w.proof(1, 3), [w.head(1, 3)]

    def check(tail, held=(), at=False):
        return _check_tlog(proof, cps, Trust(log_checkpoints=held,
                                             log_tail=tail, point_in_time=at))

    assert check(w.tail(2, 7), (w.note(7),)) == (
        "the log tail (leaves 2 to 6) does not hold the bundle's head at "
        "leaf 1")
    assert check(w.tail(0, 1), (w.note(7),)) == (
        "the log tail (leaves 0 to 0) does not hold the bundle's head at "
        "leaf 1")
    forged = w.tail(1, 7)
    forged["leaves"][3] = "hidden"
    assert check(forged, (w.note(7),)) == (
        f"the log tail's leaves do not give log {w.origin}'s root at size 7 "
        f"- they are not the log's leaves")
    assert check(w.tail(1, 6), (w.note(7),), at=True) == (
        f"the log tail ends at size 6, and no checkpoint of log {w.origin} "
        f"at that size is held to check it against")
    assert check(w.tail(1, 7), (w.note(5, root=bytes(32)), w.note(7))) == (
        f"split view: log {w.origin}'s root at size 5 is not the one its "
        f"leaves give at size 7 - the log was forked or rewritten between "
        f"them")
    shape = ('the log tail is not {"from", "leaves", "left"} - the first '
             'leaf index, the leaves from it, and one base64 root per set '
             'bit of the index')
    good = w.tail(1, 7)
    for bent in ([], {**good, "extra": 1}, {**good, "from": -1},
                 {**good, "from": True}, {**good, "leaves": []},
                 {**good, "leaves": "x"}, {**good, "leaves": ["a\nb"]},
                 {**good, "leaves": [7]}, {**good, "left": "x"},
                 {**good, "left": []}, {**good, "left": [7]},
                 {**good, "from": 2 ** 64 - 1}):
        assert check(bent) == shape, bent
    for left in (["!!"], ["AAAA"]):
        assert check({**good, "left": left}) == (
            "the log tail's left roots are not base64 of 32 bytes each")
    assert _check_tlog(None, cps, Trust(log_checkpoints=(w.note(3),))) == (
        "a log checkpoint or log tail was given but the bundle carries no "
        "transparency-log proof to hold it against")
    assert _check_tlog(None, cps, Trust(log_tail=good)) is not None


def test_a_tail_gives_every_root_after_its_start():
    """The roots before a tail's first leaf, one per set bit of its index,
    with the leaves from it give the root at every size after it - checked
    against RFC 9162's own recursion for every start and size of logs up to
    seventeen leaves."""
    from bitexact_verifier import _tail_root
    w = _log_world()
    for n in range(1, 18):
        log = [b"leaf-%d" % i for i in range(n)]
        hashes = [w.h(b"\x00" + t) for t in log]
        for start in range(n):
            left = w.frontier(start, log)
            assert len(left) == bin(start).count("1")
            for size in range(start + 1, n + 1):
                assert _tail_root(size, start, left, hashes[start:]) == \
                    w.mth(log[:size]), (n, start, size)


def test_a_bag_verdict_names_each_runs_log_history():
    """A bag's verdict carries each run's clause on what the held
    checkpoints and tail established, and nothing when none was given or
    they established nothing of the run."""
    from bitexact_verifier import Trust, _run_log_note
    w = _log_world()
    bundle = {"run_id": "r", "tlog": w.proof(1, 3),
              "checkpoints": [w.head(1, 3)]}
    assert _run_log_note(bundle, Trust()) == []
    other = w.note(3, root=bytes(32), at="log.example/two")
    assert _run_log_note(bundle, Trust(log_checkpoints=(other,))) == []
    assert _run_log_note(bundle, Trust(log_tail=w.tail(1, 3))) == [
        ", run 'r', the run's latest logged head as of log size 3"]


def test_the_cli_reads_the_log_an_auditor_holds_before_any_bundle(
        tmp_path, capsys):
    """A held checkpoint or log tail that cannot be read or is not one is
    the auditor's own error (exit 1), named before the bundle is read."""
    from bitexact_verifier import main
    w = _log_world()
    bundle = tmp_path / "b.json"
    bundle.write_text("{}", encoding="utf-8")
    note = tmp_path / "n.note"
    note.write_text(w.note(3), encoding="utf-8")
    for args, said in (
            (["--log-checkpoint", str(tmp_path / "gone")], "cannot read"),
            (["--log-checkpoint", str(bundle)], "is not a checkpoint note"),
            (["--log-tail", str(tmp_path / "gone")], "no such file"),
            (["--log-checkpoint", str(note), "--log-tail", str(note)],
             "is not JSON"),
            (["--log-tail", str(bundle)], 'is not {"from", "leaves"')):
        assert main([str(bundle), *args]) == 1, args
        assert said in capsys.readouterr().out, args
    undecodable = tmp_path / "u.note"
    undecodable.write_bytes(b"\xff\xfe")
    assert main([str(bundle), "--log-checkpoint", str(undecodable)]) == 1
    assert "cannot read" in capsys.readouterr().out
    tail = tmp_path / "t.json"
    tail.write_text(json.dumps(w.tail(1, 3)), encoding="utf-8")
    # Read and accepted, they leave the verdict to the bundle: this one is
    # empty, so it fails (exit 2) rather than erring (exit 1).
    assert main([str(bundle), "--log-checkpoint", str(note), "--log-tail",
                 str(tail), "--point-in-time"]) == 2


def test_the_ok_line_counts_what_remote_hosts_relayed(tmp_path, capsys):
    """An observed entry carrying a source block was captured on that host,
    not seen by the recorder: both bundle forms say how many, from how many
    hosts."""
    from bitexact_verifier import main
    bundle = _pack_run("relayed", relay="spiffe://acme/host-1")
    single = tmp_path / "r.json"
    single.write_text(json.dumps(bundle), encoding="utf-8")
    streamed = tmp_path / "r.jsonl"
    streamed.write_text("\n".join(_jsonl_lines(bundle)) + "\n",
                        encoding="utf-8")
    for path in (single, streamed):
        assert main([str(path)]) == 0
        assert "1 of them captured and relayed by 1 remote host" in \
            capsys.readouterr().out


def test_provenance_bag_verifies_offline(tmp_path):
    from bitexact_verifier import main, verify_provenance_bundle
    specs, _, _ = _linked_forks()
    _write_prov_bag(tmp_path / "bag", specs, "orig")
    ok, err, summary = verify_provenance_bundle(str(tmp_path / "bag"))
    assert ok, err
    assert summary == {"runs": 3, "edges": 2, "root": "orig", "signed": False,
                       "anchors": [], "sealed": True, "gaps": 0,
                       "capture": {"runs": 3},
                       "ledgers": 0, "anchored": [], "refusals": 0,
                       "refusals_signed": 0,
                       "via": {None: 8},
                       "signatures": {"objects": 0, "hybrid": 0, "pinned": 0,
                                      "unpinned": {"recorder": 0,
                                                   "bundle": 0},
                                      "unchecked": 0, "pq_algs": [],
                                      "timestamps": []},
                       "log": []}
    assert main([str(tmp_path / "bag")]) == 0


def test_provenance_bag_fork_edge_tampers(tmp_path):
    from bitexact_verifier import verify_provenance_bundle
    specs, _, fb = _linked_forks()

    outside = [s if s[0] != "fork-b" else
               ("fork-b", dict(fb, at_step=99)) for s in specs]
    _write_prov_bag(tmp_path / "b1", outside, "orig")
    assert "points at step 99 outside" in verify_provenance_bundle(
        str(tmp_path / "b1"))[1]

    rewritten = [s if s[0] != "fork-b" else
                 ("fork-b", dict(fb, source_prev_hash="0" * 64)) for s in specs]
    _write_prov_bag(tmp_path / "b2", rewritten, "orig")
    assert "prefix hash does not match" in verify_provenance_bundle(
        str(tmp_path / "b2"))[1]


def test_provenance_bag_cycle_and_disconnection(tmp_path):
    from bitexact_verifier import verify_provenance_bundle
    # A <-> B mutual forks at step 0 (prefix GENESIS), with a separate root
    a = {"source_run": "B", "at_step": 0, "source_prev_hash": "0" * 64}
    b = {"source_run": "A", "at_step": 0, "source_prev_hash": "0" * 64}
    _write_prov_bag(tmp_path / "cyc", [("orig", None), ("A", a), ("B", b)],
                    "orig")
    assert "cycles" in verify_provenance_bundle(str(tmp_path / "cyc"))[1]

    _write_prov_bag(tmp_path / "dis", [("orig", None), ("lonely", None)],
                    "orig")
    assert "not connected to the root" in verify_provenance_bundle(
        str(tmp_path / "dis"))[1]


def _sign_attestation(statement):
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import DSSE_PAYLOAD_TYPE, _dsse_pae

    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    payload = json.dumps(statement).encode("utf-8")
    sig = key.sign(_dsse_pae(DSSE_PAYLOAD_TYPE, payload))
    return {"payloadType": DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [{"public_key": public,
                            "sig": base64.b64encode(sig).decode()}]}


def test_provenance_bag_attestation_semantic_checks(tmp_path):
    import base64

    from bitexact_verifier import verify_provenance_bundle
    specs, _, _ = _linked_forks()
    graph, _ = _write_prov_bag(tmp_path / "base", specs, "orig")
    subjects = [{"name": n["run_id"], "digest": {"head": n["head_hash"]}}
                for n in graph["nodes"]]

    def stmt(predicate_type="urn:aer:provenance-graph",
             subject=None):
        return {"_type": "https://in-toto.io/Statement/v1",
                "predicateType": predicate_type, "predicate": graph,
                "subject": subject if subject is not None else subjects}

    def check(statement, name):
        _write_prov_bag(tmp_path / name, specs, "orig",
                        attestation=_sign_attestation(statement))
        return verify_provenance_bundle(str(tmp_path / name))[1]

    assert "not a provenance graph" in check(
        stmt(predicate_type="https://evil/v1"), "bad-type")

    ghost = subjects + [{"name": "ghost", "digest": {"head": "0" * 64}}]
    assert "names a run 'ghost'" in check(stmt(subject=ghost), "ghost")

    wrong = [{"name": "orig", "digest": {"head": "0" * 64}}]
    assert "head for 'orig' does not match" in check(stmt(subject=wrong),
                                                     "wrong-head")


def _reseal_bag(bag):
    """Recompute the BagIt payload and tag manifests after tampering the graph
    or a member bundle, so a graph / lineage / member-run guard is isolated from
    the bag-integrity guards, which would otherwise fire first on the now-stale
    checksum."""
    import hashlib

    bag = Path(bag)
    payload = sorted(p for p in (bag / "data").rglob("*") if p.is_file())
    lines = [hashlib.sha256(p.read_bytes()).hexdigest() + "  "
             + p.relative_to(bag).as_posix() for p in payload]
    (bag / "manifest-sha256.txt").write_text("\n".join(lines) + "\n",
                                             encoding="utf-8")
    tags = [hashlib.sha256((bag / n).read_bytes()).hexdigest() + "  " + n
            for n in ("bagit.txt", "bag-info.txt", "manifest-sha256.txt")]
    (bag / "tagmanifest-sha256.txt").write_text("\n".join(tags) + "\n",
                                                encoding="utf-8")


def _sign_bundles_in_bag(bag, priv, pub):
    """Sign every member run bundle in the bag with `priv` (a bundle-key
    signature over the canonical {format, run_id, chain, signed_at, key_id}
    body)."""
    from bitexact_verifier import _canonical, _key_id

    stamp = "2026-09-02T00:00:00+00:00"
    for bf in sorted((Path(bag) / "data" / "runs").glob("*.bundle.json")):
        b = json.loads(bf.read_text(encoding="utf-8"))
        body = {"format": b["format"], "run_id": b["run_id"],
                "chain": b["chain"], "signed_at": stamp,
                "key_id": _key_id(pub)}
        b["signature"] = {"algorithm": "ed25519", "public_key": pub,
                          "key_id": _key_id(pub), "signed_at": stamp,
                          "signature": priv.sign(_canonical(body)).hex()}
        bf.write_text(json.dumps(b), encoding="utf-8")


def test_provenance_bag_bagit_integrity_is_pinned(tmp_path):
    """The BagIt wrapper's own integrity guards (the declaration, the payload
    set, per-payload-file and per-tag-file sha256) each reject a bag whose
    manifest disagrees with its bytes. Without them a provenance bag's evidence
    could be swapped under a stale manifest."""
    from bitexact_verifier import verify_provenance_bundle
    specs, _, _ = _linked_forks()

    b = tmp_path / "g1"
    _write_prov_bag(b, specs, "orig")
    (b / "bagit.txt").write_text("NOT-A-BAG: 1.0\n", encoding="utf-8")
    _reseal_bag(b)   # reseal so the tag-sha guard passes and only G1 stands
    assert "BagIt bag" in verify_provenance_bundle(str(b))[1]

    b = tmp_path / "g3"
    _write_prov_bag(b, specs, "orig")
    (b / "data" / "stray.txt").write_text("x", encoding="utf-8")
    assert "added or removed" in verify_provenance_bundle(str(b))[1]

    b = tmp_path / "g4"
    _write_prov_bag(b, specs, "orig")
    bf = sorted((b / "data" / "runs").glob("*.bundle.json"))[0]
    bf.write_text(bf.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert "fails its sha256" in verify_provenance_bundle(str(b))[1]

    b = tmp_path / "g6"
    _write_prov_bag(b, specs, "orig")
    (b / "bag-info.txt").write_text("External-Identifier: evil\n",
                                    encoding="utf-8")
    assert "tag file bag-info.txt" in verify_provenance_bundle(str(b))[1]


def test_provenance_bag_graph_and_member_runs_are_pinned(tmp_path):
    """The graph format, each member run's own re-verification, and the node
    head binding the run's real chain head, all checked after bag integrity, so
    each tamper is re-sealed to isolate it. Without them a bag could carry an
    unverified/forged member run or a graph node that lies about a run's head."""
    from bitexact_verifier import verify_provenance_bundle
    specs, _, _ = _linked_forks()

    b = tmp_path / "g7"
    _write_prov_bag(b, specs, "orig")
    gp = b / "data" / "provenance-graph.json"
    g = json.loads(gp.read_text(encoding="utf-8"))
    g["format"] = "unknown/9"
    gp.write_text(json.dumps(g), encoding="utf-8")
    _reseal_bag(b)
    assert "unsupported provenance graph format" in \
        verify_provenance_bundle(str(b))[1]

    b = tmp_path / "g8"
    _write_prov_bag(b, specs, "orig")
    bf = b / "data" / "runs" / "orig.bundle.json"
    bundle = json.loads(bf.read_text(encoding="utf-8"))
    bundle["entries"][1]["hash"] = "00" * 32       # break an interior link
    bf.write_text(json.dumps(bundle), encoding="utf-8")
    _reseal_bag(b)
    assert "run 'orig'" in verify_provenance_bundle(str(b))[1]

    b = tmp_path / "g9"
    _write_prov_bag(b, specs, "orig")
    gp = b / "data" / "provenance-graph.json"
    g = json.loads(gp.read_text(encoding="utf-8"))
    g["nodes"][0]["head_hash"] = "00" * 32
    gp.write_text(json.dumps(g), encoding="utf-8")
    _reseal_bag(b)
    assert "graph head does not match" in verify_provenance_bundle(str(b))[1]


def test_provenance_bag_lineage_guards_are_pinned(tmp_path):
    """A fork's lineage is certified only if the fork is sealed, and the root
    must be the bag's boundary (a self-fork is a cycle through the root).
    Without these an unfinished counterfactual, or a lineage cycle, certifies."""
    from bitexact_verifier import verify_provenance_bundle
    specs, _fa, _fb = _linked_forks()

    b = tmp_path / "g13"
    _write_prov_bag(b, specs, "orig")
    bf = b / "data" / "runs" / "fork-b.bundle.json"
    bundle = json.loads(bf.read_text(encoding="utf-8"))
    bundle["entries"] = [e for e in bundle["entries"]
                         if e.get("kind") != "run_end"]   # unseal the fork
    bundle["chain"]["head_hash"] = bundle["entries"][-1]["hash"]
    bf.write_text(json.dumps(bundle), encoding="utf-8")
    gp = b / "data" / "provenance-graph.json"
    g = json.loads(gp.read_text(encoding="utf-8"))
    for n in g["nodes"]:
        if n["run_id"] == "fork-b":
            n["head_hash"] = bundle["chain"]["head_hash"]
    gp.write_text(json.dumps(g), encoding="utf-8")
    _reseal_bag(b)
    assert "is not sealed" in verify_provenance_bundle(str(b))[1]

    b = tmp_path / "g14"
    self_fork = {"source_run": "orig", "at_step": 0,
                 "source_prev_hash": "0" * 64}
    _write_prov_bag(b, [("orig", self_fork)], "orig")
    assert "forked from in-bag run" in verify_provenance_bundle(str(b))[1]


def test_provenance_bag_attestation_binding_is_pinned(tmp_path):
    """Under a bundle-key demand the cross-run lineage must be signed (an
    attestation is required), and a present attestation must sign THE bag's
    graph, not merely name its runs. Without these an unsigned set of runs is
    certified under a key demand, or an attestation over a different graph
    passes."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)

    from bitexact_verifier import verify_provenance_bundle
    specs, _, _ = _linked_forks()

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    b = tmp_path / "g17"
    _write_prov_bag(b, specs, "orig")                 # no attestation
    _sign_bundles_in_bag(b, priv, pub)
    _reseal_bag(b)
    ok, err, _ = verify_provenance_bundle(str(b), trusted_bundle_keys=[pub])
    assert not ok and "no graph attestation" in err

    b = tmp_path / "g20"
    graph, _ = _write_prov_bag(b, specs, "orig")
    subjects = [{"name": n["run_id"], "digest": {"head": n["head_hash"]}}
                for n in graph["nodes"]]
    other_graph = dict(graph, root="a-different-root")
    stmt = {"_type": "https://in-toto.io/Statement/v1",
            "predicateType": "urn:aer:provenance-graph",
            "predicate": other_graph, "subject": subjects}
    b2 = tmp_path / "g20b"
    _write_prov_bag(b2, specs, "orig", attestation=_sign_attestation(stmt))
    assert "does not sign the provenance graph" in \
        verify_provenance_bundle(str(b2))[1]


# ---- the corpus the product ships, one fixture per form and tier ----
# Regenerated by verifier/testdata/make_fixtures.py - never edited by hand.

def test_golden_jsonl_bundle_streams_and_verifies(capsys):
    assert main([str(TESTDATA / "valid.bundle.jsonl")]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK: golden-run") and "(jsonl, streamed)" in out
    assert "sealed" in out and "observed" in out


def test_golden_accountable_redaction_verifies_at_the_recorder_tier(capsys):
    """A store redaction: the claim is on the chain and the recorder
    re-checkpointed the head, so recorder-key trust accepts it and the
    verdict does not ask for a signature the recorder already stood in for."""
    bundle = _load("valid-accountable-redaction.bundle.json")
    trust = _load("trust.json")
    recorder = [k["public_key"] for k in trust["recorder_keys"]]
    ok, err = verify_bundle(bundle, trusted_recorder_keys=recorder)
    assert ok, err
    assert any(e.get("kind") == "redaction" for e in bundle["entries"])
    assert main([str(TESTDATA / "valid-accountable-redaction.bundle.json"),
                 "--expect-recorder-key", recorder[0]]) == 0
    out = capsys.readouterr().out
    assert re.search(r"\b\d+ fields? redacted", out) and "demand a signed bundle" not in out


def test_golden_identity_on_behalf_of_verifies_with_its_authority_redacted():
    """A run that acted for a person under a consent, the consent's reference
    redacted on the chain: it verifies under the recorder's key, the party
    it acted for is readable, and the redacted authority is gone from the
    bytes while the commitment over it still holds."""
    bundle = _load("valid-identity-on-behalf-of.bundle.json")
    trust = _load("trust.json")
    recorder = [k["public_key"] for k in trust["recorder_keys"]]
    ok, err = verify_bundle(bundle, trusted_recorder_keys=recorder)
    assert ok, err
    bound = next(e for e in bundle["entries"] if e["kind"] == "identity")
    assert bound["prov"] == "asserted"
    assert bound["data"]["on_behalf_of"] == "user:7f3a9c"
    assert bound["data"]["on_behalf_of_type"] == "human"
    assert bound["data"]["interaction_mode"] == "interactive"
    assert "authority_ref" in bound["redacted"]
    assert "consent:88412" not in json.dumps(bundle)


def test_golden_anchored_signed_bundle_verifies_and_names_its_anchor(capsys):
    bundle = _load("valid-anchored-signed.bundle.json")
    ok, err = verify_bundle(bundle, expect_key=bundle["signature"]["public_key"])
    assert ok, err
    assert main([str(TESTDATA / "valid-anchored-signed.bundle.json")]) == 0
    out = capsys.readouterr().out
    assert "1 worm anchor" in out and "signed" in out


def test_golden_sha256_bundle_verifies():
    bundle = _load("valid-sha256.bundle.json")
    assert {e["alg"] for e in bundle["entries"]} == {"sha256"}
    ok, err = verify_bundle(bundle, expect_key=bundle["signature"]["public_key"])
    assert ok, err
    tampered = json.loads(json.dumps(bundle))
    tampered["entries"][1]["data"]["result"]["temp"] = -40
    assert verify_bundle(tampered)[0] is False


def test_golden_bag_verifies_offline_and_from_the_cli(capsys):
    from bitexact_verifier import verify_provenance_bundle
    trust = _load("trust.json")
    bag = TESTDATA / "valid.bag"
    ok, err, summary = verify_provenance_bundle(str(bag))
    assert ok, err
    assert summary["runs"] == 2 and summary["edges"] == 1
    ok, err, _ = verify_provenance_bundle(
        str(bag), expect_key=trust["bundle_keys"][0]["public_key"])
    assert ok, err
    assert main([str(bag), "--trust-file", str(TESTDATA / "trust.json")]) == 0
    assert "graph verified" in capsys.readouterr().out


def test_golden_adverse_decision_is_the_current_sample():
    """The seeded sample as `bitexact seed` records it today - ten steps, a
    committed decision record, and markers for the honest gaps - not the
    eight-step sample of an earlier build."""
    bundle = _load("adverse-decision.bundle.json")
    kinds = [e["kind"] for e in bundle["entries"]]
    assert len(kinds) == 10 and "decision_record" in kinds
    assert kinds[-1] == "run_end"


def test_each_exit_code_means_what_the_contract_says(tmp_path, capsys):
    """0 a bundle that verifies, 1 an input the verifier cannot use (a usage
    error included - never argparse's 2, which here means FAIL), 2 evidence
    that does not verify, 3 a verified run that declares gaps."""
    import pytest
    assert main([str(TESTDATA / "valid-signed.bundle.json")]) == 0
    for argv in (["--no-such-flag", "x"], [],
                 ["b.json", "--witness-threshold", "two"]):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == 1, argv
        assert "error:" in capsys.readouterr().err
    assert main([str(tmp_path / "absent.json")]) == 1
    assert capsys.readouterr().out.startswith("error: ")
    doc = _load("valid-signed.bundle.json")
    doc["entries"][0]["kind"] = "doctored"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    assert main([str(bad)]) == 2
    assert capsys.readouterr().out.startswith("FAIL: ")


def test_verifier_prints_via_attribution_never_as_proof(tmp_path, capsys):
    """A verified chain whose entries name a capture path (`via`) gets one
    more line, the per-path mix, worded as attribution and not proof, in
    the JSON and the streamed JSONL form alike. A `via` that is not a string
    counts as unlabeled and never crashes; a label carrying a control
    character is escaped by the verifier's one output path, so it cannot
    drive the terminal. A chain with no `via` prints no such line, and the
    line never changes the verdict."""
    bundle = _unsigned_base()
    for entry in bundle["entries"]:
        entry.pop("via", None)
    _reforge_entries(bundle)
    plain = tmp_path / "plain.bundle.json"
    plain.write_text(json.dumps(bundle), encoding="utf-8")
    assert main([str(plain)]) == 0
    assert "captured via" not in capsys.readouterr().out

    entries = bundle["entries"]
    assert len(entries) >= 4
    for entry in entries:
        entry["via"] = "proxy"
    # the last entry is the run_end seal, which the line never counts
    assert entries[-1]["kind"] == "run_end"
    entries[-2]["via"] = "relay:sdk-ts\x1b[31m"
    entries[-3]["via"] = 7
    _reforge_entries(bundle)
    assert verify_bundle(bundle) == (True, None)
    expected = (f"captured via proxy {len(entries) - 3}, "
                f"relay:sdk-ts\\x1b[31m 1, unlabeled 1 "
                f"(attribution, not proof)")

    path = tmp_path / "via.bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert main([str(path)]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("OK: ")
    assert expected in out.splitlines()
    assert "\x1b" not in out

    streamed = tmp_path / "via.bundle.jsonl"
    streamed.write_text(chr(10).join(_jsonl_lines(bundle)) + chr(10),
                        encoding="utf-8")
    assert main([str(streamed)]) == 0
    out = capsys.readouterr().out
    assert expected in out.splitlines()
    assert "\x1b" not in out

    del entries[0]["via"]
    _reforge_entries(bundle)
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert main([str(path)]) == 0
    line = next(text for text in capsys.readouterr().out.splitlines()
                if text.startswith("captured via "))
    proxied = len(entries) - 4
    assert "unlabeled 2" in line
    assert (f"proxy {proxied}" in line) if proxied else ("proxy" not in line)


def test_pack_and_provenance_verdicts_print_via_attribution(tmp_path, capsys):
    """An evidence pack and a provenance bag get the same attribution line a
    single bundle does, tallied over every entry of every run they hold, after
    the OK line; a label carrying a control character is escaped; a bag whose
    entries name no path prints no such line."""
    pack = _write_pack(tmp_path / "pack", [
        _pack_run("a", via="proxy"),
        _pack_run("b", via="relay:sdk-ts\x1b[31m"),
        _pack_run("c")])
    assert main([str(pack)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("OK: evidence pack - 3 runs verified")
    # each run's run_end seal is not counted
    assert ("captured via proxy 2, relay:sdk-ts\\x1b[31m 2, unlabeled 2 "
            "(attribution, not proof)") in lines
    assert not any("\x1b" in text for text in lines)

    plain = _write_pack(tmp_path / "plain", [_pack_run("a")])
    assert main([str(plain)]) == 0
    assert "captured via" not in capsys.readouterr().out

    bag = tmp_path / "bag"
    _write_prov_bag(bag, [("orig", None)], "orig", via="relay:sdk-ts")
    assert main([str(bag)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("OK: provenance bundle rooted at 'orig'")
    assert "captured via relay:sdk-ts 2 (attribution, not proof)" in lines

    specs, _, _ = _linked_forks()
    _write_prov_bag(tmp_path / "forks", specs, "orig")
    assert main([str(tmp_path / "forks")]) == 0
    assert "captured via" not in capsys.readouterr().out
