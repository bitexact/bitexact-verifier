"""Standalone verifier for BitExact evidence bundles.

Implements bundle-spec.md (aer-bundle): hash-chain verification
over salted data commitments - so redacted entries still verify -
plus optional ed25519 signature and external-anchor checking. Depends
only on the standard library, plus `cryptography` when a bundle is
signed or carries a WORM anchor, and `asn1crypto` to verify an RFC 3161
timestamp anchor.

SPDX-License-Identifier: Apache-2.0
"""

import argparse
import base64
import hashlib
import heapq
import hmac
import html
import json
import math
import re
import sys
from pathlib import Path
from typing import NamedTuple

# The release identity of this verifier. Kept in lockstep with
# verifier/pyproject.toml and verifier/CHECKSUMS.txt (a test pins all three):
# an auditor confirms the file they hold against the canonical digest for this
# version, obtained out-of-band. Not a trust root by itself - a doctored copy
# can claim any version, but its sha256 will not match that version's digest.
__version__ = "0.0.1a0"

class Trust(NamedTuple):
    """What a caller pins a verdict to, traveling as one value.

    These five move together through every whole-bundle path, so threading
    them one by one restated the same tuple in five signatures and at every
    call site - and a parameter dropped in that thread is a pin silently not
    applied, which is a false accept rather than a crash.

    Helpers that read a single field still take that field. Handing the whole
    set to a check that consults one of them would hide which input the check
    actually depends on.
    """

    expect_key: str | None = None
    expect_recorder_key: str | None = None
    trusted_bundle_keys: list | None = None
    trusted_recorder_keys: list | None = None
    expect_tsa: bytes | None = None
    # Transparency-log witnesses the caller trusts ({name: public key hex})
    # and how many of them must have cosigned the log checkpoint.
    expect_witnesses: dict | None = None
    witness_threshold: int = 1
    # Post-quantum pins. A key pinned with its ML-DSA half requires that half
    # on everything the key signed: `expect_recorder_pq_key` beside
    # --expect-recorder-key, `expect_pq_key` beside --expect-key - each only
    # with its Ed25519 pin, which is what makes the material required at all
    # - and `trusted_pq_keys` ({Ed25519 key: [ML-DSA keys]}) from a trust
    # file's `pq_public_key` entries. `require_pq` demands a PQ half
    # everywhere; it pins no key, so it is never said to.
    expect_recorder_pq_key: str | None = None
    expect_pq_key: str | None = None
    trusted_pq_keys: dict | None = None
    require_pq: bool = False
    # What the caller holds of the transparency log beyond the bundle:
    # log checkpoint notes, the log's leaves
    # from a run's head on (`log_tail`, as --log-tail reads it), and whether
    # the bundle is asked about as the run stood at its own log checkpoint
    # rather than as it stands now (`point_in_time`).
    log_checkpoints: tuple = ()
    log_tail: dict | None = None
    point_in_time: bool = False

    def pq_pins(self, role: str, classical) -> set:
        """The ML-DSA keys pinned for the Ed25519 key `classical` in `role`
        ("recorder" or "bundle"), lowercase; empty when none is."""
        pins = set()
        exact, classical_pin = (
            (self.expect_recorder_pq_key, self.expect_recorder_key)
            if role == "recorder" else (self.expect_pq_key, self.expect_key))
        if exact and _same_key(classical, classical_pin):
            pins.add(exact.lower())
        if isinstance(classical, str):
            pins |= {k.lower() for k in
                     (self.trusted_pq_keys or {}).get(classical.lower(), ())}
        return pins

    @property
    def recorder_pinned(self) -> bool:
        """Whether the caller pinned the recorder at all - by an exact key or
        by a trusted set. Asked at four points, and the answer must be the same
        at every one: it decides whether a run missing recorder material is a
        verdict or merely unattested."""
        return (self.expect_recorder_key is not None
                or self.trusted_recorder_keys is not None)

    @property
    def bundle_pinned(self) -> bool:
        """The same question for the bundle signature."""
        return (self.expect_key is not None
                or self.trusted_bundle_keys is not None)


FORMAT = "aer-bundle"
CANON_DIALECT = "aer-jcs"
GRAPH_FORMAT = "aer-provenance-graph"
GRAPH_PREDICATE_TYPE = "urn:aer:provenance-graph"
GENESIS = "0" * 64
_SURROGATES = re.compile("[\ud800-\udfff]")

# How deep a value may nest before it is refused. A constant in the format,
# not a tuning knob: otherwise the boundary is wherever the interpreter's
# stack runs out, and a recorder and a verifier with different recursion
# limits reach different verdicts about the same bytes. Must equal
# bitexact.jcs.MAX_DEPTH.
MAX_DEPTH = 128
# The audit kinds that may follow a run_end seal (bundle-spec: Entries).
AUDIT_KINDS = ("redaction", "repair", "hold", "hold_release")

# The kind vocabulary and the provenance class each kind may carry. A class
# is inside the entry hash, so relabeling re-chains - and on a keyless
# bundle re-chaining is free. Fixing the class per kind is what stops an
# `injected` counterfactual being presented as an observed `http_call`, or
# an operator's assertion as something the recorder saw.
PROV_BY_KIND = {
    "run_meta": ("observed",), "run_end": ("observed",),
    "fork": ("observed",), "http_call": ("observed",),
    "nondet": ("observed",),
    "tool_call": ("observed", "asserted"),
    "policy_check": ("observed", "asserted"),
    "identity": ("asserted",), "context": ("asserted",),
    "human_decision": ("asserted",), "decision_record": ("asserted",),
    "marker": ("asserted",), "model": ("asserted",),
    "redaction": ("asserted",), "repair": ("asserted",),
    "hold": ("asserted",), "hold_release": ("asserted",),
    "injected": ("synthetic",),
}
KINDS = tuple(PROV_BY_KIND)

# The range in which the integer rule is guaranteed to hold. The check itself
# is exact - an integer is accepted when the double it parses to reproduces
# its digits - because a flat threshold would refuse values every parser
# agrees on, and would make this canonicalizer emit output it could not
# re-read. Must equal bitexact.jcs.SAFE_INTEGER.
SAFE_INTEGER = 2 ** 53 - 1


def _is_int(value) -> bool:
    """A JSON integer: an int, never a boolean. Python's `True == 1` would
    let `true` pass every integer field compared with `==`, where a reader
    in a language that keeps the two apart refuses it. Every integer the
    spec names - an entry's `step`, a checkpoint's `seq` and `steps`, an
    anchor's `steps`, a seal's `data.steps`, a fork's `data.at_step`, a log
    proof's `index` and `size` - is held to this one test."""
    return isinstance(value, int) and not isinstance(value, bool)


def _same_json(a, b) -> bool:
    """Whether two parsed JSON values are the same value: equal canonical
    forms. Python's `==` calls `true` and `1` equal, a reader in another
    language does not; the canonical form keeps them apart."""
    return _canonical(a) == _canonical(b)

# Order of the ed25519 base point (RFC 8032 section 5.1).
_L = 2 ** 252 + 27742317777372353535851937790883648493
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_HEX128 = re.compile(r"[0-9a-fA-F]{128}")

# The 14 encodings of ed25519's eight small-order points, folded to 7 by
# masking the x sign bit - Table 6b of "Taming the many EdDSAs" (SSR'20,
# eprint.iacr.org/2020/1244), identical to libsodium's blacklist through
# 1.0.18. RFC 8032 accepts these, and against such a key one signature can
# authenticate two different chosen messages.
_SMALL_ORDER_Y = frozenset(bytes.fromhex(h) for h in (
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
))


def _reject_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def _reject_nonfinite(token):
    raise ValueError(f"non-finite JSON constant {token!r} is not allowed")


def _too_deep(value, limit):
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return True
        children = (node.values() if isinstance(node, dict)
                    else node if isinstance(node, list) else ())
        for child in children:
            if isinstance(child, (dict, list)):
                stack.append((child, depth + 1))
    return False


def _has_nonfinite(value):
    """Any non-finite float, however spelled. parse_constant fires only for the
    Infinity/-Infinity/NaN tokens; an overflow literal (1e999) parses to inf
    without it. Refused here to match the product loader on the same bytes."""
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, float) and not math.isfinite(node):
            return True
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def _loads(text):
    """Parse evidence, refusing objects that repeat a key and the non-finite
    constants Infinity/-Infinity/NaN.

    RFC 8785 section 3.1 forbids duplicate property names, but no canonicalizer can
    enforce it: json.loads has already collapsed the repeat - keeping the
    last - before canonicalization ever sees the object. Parsers disagree
    about which one wins, so a line carrying two spellings of a field reads
    one way here and another in the tool an auditor happens to use, and a
    clean verdict would put this verifier's name on bytes it never read.
    Enforcing it at the parse boundary is the only place it can be enforced.
    RFC 8785 section 3.2 forbids Infinity/NaN too; refusing them here matches the
    product loader and keeps a doctored non-finite out of every downstream.
    Nesting deeper than MAX_DEPTH is refused for the same reason, matching the
    product loader.
    """
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicates,
                           parse_constant=_reject_nonfinite)
    except RecursionError:
        # The scanner recurses per nesting level, and how far it gets
        # before exhausting the stack is a property of the interpreter,
        # not of the evidence: one stack raises here where another parses
        # the same document and lets the MAX_DEPTH check below refuse it.
        # Nesting is the only thing that recurses in a JSON document, so
        # this is that refusal arriving early. An auditor must read the
        # same reason on every host, not "malformed bundle:
        # RecursionError(...)".
        raise ValueError(
            f"nesting deeper than {MAX_DEPTH} levels is refused") from None
    if _has_nonfinite(value):  # the overflow-literal form parse_constant misses
        raise ValueError("non-finite number is not allowed")
    if _too_deep(value, MAX_DEPTH):
        raise ValueError(f"nesting deeper than {MAX_DEPTH} levels is refused")
    return value


# --- The post-quantum half (bundle-spec: Post-quantum signatures) -----------
#
# Beside its Ed25519 signature, an object may carry an ML-DSA (FIPS 204)
# signature over one construction - _pq_message - binding the Ed25519 key and
# a purpose. A present PQ half must verify; it is never ignored.
_PQ_ALGS = {"ML-DSA-65": (1952, 3309), "ML-DSA-87": (2592, 4627)}
_PQ_FIELDS = ("pq_alg", "pq_public_key", "pq_key_id", "pq_signature")
_LOWER_HEX = re.compile(r"[0-9a-f]+")
_MLDSA = []


def _mldsa():
    """The ML-DSA module of the installed `cryptography`, or None when there
    is no cryptography or its libcrypto has no ML-DSA. Probed once."""
    if not _MLDSA:
        try:
            from cryptography.exceptions import UnsupportedAlgorithm
            from cryptography.hazmat.primitives.asymmetric import mldsa
        except ImportError:
            _MLDSA.append(None)
            return None
        try:
            mldsa.MLDSA65PrivateKey.generate()
            _MLDSA.append(mldsa)
        except UnsupportedAlgorithm:
            _MLDSA.append(None)
    return _MLDSA[0]


def _pq_message(purpose: str, message: bytes, classical_public, alg: str,
                key_id: str) -> bytes:
    return _canonical({"aer_pq": purpose,
                       "classical_public_key": classical_public,
                       "pq_alg": alg, "pq_key_id": key_id,
                       "message_sha512": hashlib.sha512(message).hexdigest()})


def _pq_verify(alg, public_hex, data: bytes, signature_hex) -> bool:
    """Total: False for anything that does not verify, any spelling but
    lowercase hex of the exact size included."""
    module = _mldsa()
    try:
        sizes = _PQ_ALGS.get(alg) if isinstance(alg, str) else None
        if module is None or sizes is None:
            return False
        for value, size in ((public_hex, sizes[0]), (signature_hex, sizes[1])):
            if (not isinstance(value, str) or len(value) != 2 * size
                    or not _LOWER_HEX.fullmatch(value)):
                return False
        public_cls = getattr(module, alg.replace("-", "") + "PublicKey")
        public_cls.from_public_bytes(bytes.fromhex(public_hex)).verify(
            bytes.fromhex(signature_hex), data)
        return True
    except Exception:  # noqa: BLE001 - InvalidSignature, ValueError, TypeError
        return False


def _pq_half(obj, purpose: str, message: bytes, classical_public):
    """("absent"|"verified"|"unchecked", None), or (None, error)."""
    if not isinstance(obj, dict):
        return "absent", None
    present = [f for f in _PQ_FIELDS if f in obj]
    if not present:
        return "absent", None
    if len(present) != len(_PQ_FIELDS):
        return None, ("post-quantum signature is incomplete - missing "
                      + ", ".join(f for f in _PQ_FIELDS if f not in obj))
    alg, public = obj["pq_alg"], obj["pq_public_key"]
    if not isinstance(alg, str) or alg not in _PQ_ALGS:
        return None, f"unknown post-quantum algorithm {alg!r}"
    if (not isinstance(public, str) or len(public) != 2 * _PQ_ALGS[alg][0]
            or not _LOWER_HEX.fullmatch(public)):
        return None, "post-quantum public key is not lowercase hex of its size"
    if obj["pq_key_id"] != _key_id(public):
        return None, "pq_key_id does not derive from its pq_public_key"
    if _mldsa() is None:
        # The signature cannot be checked here, but its shape can: a
        # malformed one is refused, never read as merely unchecked.
        sig = obj["pq_signature"]
        if (not isinstance(sig, str) or len(sig) != 2 * _PQ_ALGS[alg][1]
                or not _LOWER_HEX.fullmatch(sig)):
            return None, ("post-quantum signature is not lowercase hex of "
                          "its size")
        return "unchecked", None
    body = _pq_message(purpose, message, classical_public, alg,
                       obj["pq_key_id"])
    if not _pq_verify(alg, public, body, obj["pq_signature"]):
        return None, "post-quantum signature invalid"
    return "verified", None


_NO_MLDSA = ("verifying post-quantum signatures needs ML-DSA, and this "
             "install of cryptography has none: it is built against a "
             "libcrypto without it (OpenSSL before 3.5, or LibreSSL) - "
             "pip install --force-reinstall --only-binary cryptography "
             "cryptography")


def _pq_rule(obj, purpose: str, message: bytes, trust, role: str):
    """Why an object's PQ half fails the caller's demands, or None: a present
    half must verify; a key pinned with a PQ half requires exactly that half
    on everything it signed; --require-pq requires one everywhere."""
    classical = obj.get("public_key") if isinstance(obj, dict) else None
    state, err = _pq_half(obj, purpose, message, classical)
    if err:
        return err
    pinned = trust.pq_pins(role, classical)
    if (pinned or trust.require_pq) and state == "unchecked":
        return _NO_MLDSA
    if pinned and state == "absent":
        return (f"signed by a {role} key pinned as hybrid, but carries no "
                f"post-quantum signature - stripped or forged")
    if pinned and obj["pq_public_key"] not in pinned:
        return "post-quantum signature is not by the pinned post-quantum key"
    if trust.require_pq and state == "absent":
        return ("carries no post-quantum signature and --require-pq was "
                "given")
    return None


def _is_small_order(raw: bytes) -> bool:
    """Compared with the sign bit cleared: each point has two encodings, and
    listing them one by one is how a blocklist ends up with holes."""
    return raw[:31] + bytes([raw[31] & 0x7F]) in _SMALL_ORDER_Y


def _canonical_scalar(s: bytes) -> bool:
    """0 <= S < L, per RFC 8032 section 5.1.7 and FIPS 186-5 section 7.7. Without it S and
    S + L both verify, so one signed statement has two byte spellings."""
    return int.from_bytes(s, "little") < _L


def _combine_surrogate_pairs(text: str) -> str:
    """Fold UTF-16 surrogate pairs into the astral character a JSON parser
    yields, so a value has one canonical form rather than two.

    `str.__str__` reads the true code points - identity for an exact str, a
    plain copy of the underlying data for a subclass. Every string sorted or
    emitted passes through here first, so an overridden encode, __iter__, or
    __hash__ cannot steer the pair scan, the sort key, or the collision check;
    the recorder and this verifier must read the same bytes off the value."""
    text = str.__str__(text)
    if not any(0xD800 <= ord(a) <= 0xDBFF and 0xDC00 <= ord(b) <= 0xDFFF
               for a, b in zip(text, text[1:])):
        return text
    return text.encode("utf-16", "surrogatepass").decode("utf-16",
                                                         "surrogatepass")


def _jcs_string(value: str) -> str:
    text = json.dumps(_combine_surrogate_pairs(value), ensure_ascii=False)
    return _SURROGATES.sub(lambda m: f"\\u{ord(m.group()):04x}", text)


def _es6_number(value: float) -> str:
    """ECMAScript Number::toString, per RFC 8785.

    Branches on the true digits, never on the value: float.__repr__ bypasses
    a subclass's __repr__ and comparing text keeps __eq__ out of it."""
    text = float.__repr__(value)
    if text in ("nan", "inf", "-inf"):
        raise ValueError("NaN and Infinity cannot be canonicalized")
    if text == "-0.0":
        # RFC 8785 errata 7920: the spec emits "0" for both zeros, so -0.0
        # and 0.0 would share one commitment, and a commitment covering two
        # values proves neither.
        raise ValueError(
            "negative zero cannot be canonicalized: it would share a "
            "commitment with positive zero (RFC 8785 errata 7920)")
    if text == "0.0":
        return "0"
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


def _jcs(value, out: list, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError(
            f"nesting deeper than {MAX_DEPTH} levels is refused")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_jcs_string(value))
    elif isinstance(value, int):
        # Digits are only safe to emit when they are exactly what the double
        # a JSON parser reads them back as would produce. int.__repr__ rather
        # than str so an int subclass cannot substitute its own text.
        digits = int.__repr__(value)
        parsed = float(digits)   # inf, not an error, past the double range
        if math.isinf(parsed) or _es6_number(parsed) != digits:
            raise ValueError(
                f"integer {digits} is outside the safe integer range: JSON "
                f"numbers are doubles, and a parser elsewhere reads these "
                f"digits back as a different value. Record it as a string "
                f"instead (RFC 8785 Appendix D).")
        out.append(digits)
    elif isinstance(value, float):
        out.append(_es6_number(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _jcs(item, out, depth + 1)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        # Keys and values are read through the unbound dict methods: a dict
        # subclass could otherwise answer __iter__, __len__, or __getitem__
        # with data its buffer does not hold, hiding a key or steering an
        # emitted value away from what the recorder stored.
        keys = list(dict.keys(value))
        # JSON object keys are strings. Coercing anything else would let two
        # different values collide on one commitment, and would disagree with
        # the writer that stored the data.
        for key in keys:
            if not isinstance(key, str):
                raise ValueError(
                    f"object keys must be strings; got {type(key).__name__}")
        # Two distinct Python keys can fold to one JSON key; emitting both
        # would write a duplicate that re-parses lossily.
        folded = {_combine_surrogate_pairs(k): k for k in keys}
        if len(folded) != len(keys):
            raise ValueError(
                "object keys collide once surrogate pairs are folded")
        ordered = sorted(folded, key=lambda k: k.encode("utf-16-be",
                                                        "surrogatepass"))
        for i, name in enumerate(ordered):
            if i:
                out.append(",")
            out.append(_jcs_string(name))
            out.append(":")
            _jcs(dict.__getitem__(value, folded[name]), out, depth + 1)
        out.append("}")
    else:
        raise TypeError(
            f"{type(value).__name__} cannot be canonicalized as JSON")


def _canonical(obj) -> bytes:
    """RFC 8785 canonical bytes."""
    out: list = []
    _jcs(obj, out)
    return "".join(out).encode("utf-8")


_HASH_ALGS = ("blake2b-256", "sha256")
SALT_BYTES = 16
RUN_PREDICATE_TYPE = "urn:aer:run"


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
    # Byte-identical to the product's commitment_paths, including its skip of
    # non-string keys: a dotted path has no meaning for one, and json object
    # keys are always strings, so real evidence never reaches the skip - but
    # the two path generators must not diverge on a hand-built dict either.
    paths = []
    for key, value in data.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, dict) and value:
            paths.extend(f"{_escape_key(key)}.{_escape_key(sub)}"
                         for sub in value if isinstance(sub, str))
        else:
            paths.append(_escape_key(key))
    return paths


_HEX32 = re.compile(r"[0-9a-f]{32}")


def _hex32(value) -> bool:
    return isinstance(value, str) and bool(_HEX32.fullmatch(value))


def _iso_date(value) -> bool:
    """A calendar date as YYYY-MM-DD, as a policy's revoked_keys names it."""
    import datetime as _dt
    if not (isinstance(value, str)
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value)):
        return False
    try:
        _dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _hash_only_salted(decl: dict) -> bool:
    """A hash-only field salted per field: a nonce, and the key it is under -
    or, with no usable key, None and the declared gap
    `capture_key_unavailable`, so a field that can never be opened is always
    counted as one. A keyed field declares no cause."""
    key_id = decl.get("key_id")
    return ("linkable" not in decl and _hex32(decl.get("nonce"))
            and ((key_id is None
                  and decl.get("cause") == "capture_key_unavailable")
                 or (_hex32(key_id) and "cause" not in decl)))


def _hash_only_linkable(decl: dict) -> bool:
    """A linkable hash-only field: no nonce, the one salt of its key, so an
    equal value commits equal under that key - which needs a key."""
    return (decl.get("linkable") is True and "nonce" not in decl
            and _hex32(decl.get("key_id")) and "cause" not in decl)


def _capture_problem(entry: dict):
    """(error or None, the paths declared committed but never stored) for an
    entry's `capture` declaration (bundle-spec: Capture controls). Every
    declared path is committed; a hash-only or withheld field holds no value,
    no salt and no redaction marker; a scrub names what it found."""
    capture = entry.get("capture")
    if capture is None:
        return None, set()
    if (not isinstance(capture, dict)
            or set(capture) != {"policy", "applied_by", "fields"}
            or not isinstance(capture["policy"], str)
            or not isinstance(capture["applied_by"], str)
            or not isinstance(capture["fields"], dict)
            or not capture["fields"]):
        return "capture declaration is malformed", set()
    data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
    commitments = entry.get("commitments")
    commitments = commitments if isinstance(commitments, dict) else {}
    salts = entry.get("salts") if isinstance(entry.get("salts"), dict) else {}
    marks = entry.get("redacted")
    redacted = set(m for m in marks if isinstance(m, str)) \
        if isinstance(marks, list) else set()
    held_none = set()
    for path, decl in capture["fields"].items():
        mode = decl.get("mode") if isinstance(decl, dict) else None
        if not isinstance(path, str) or path not in commitments:
            return f"capture declares {path!r}, which is not committed", set()
        if mode in ("hash-only", "withheld"):
            if _value_at(data, path)[0] or path in salts or path in redacted:
                return (f"path {path} is declared {mode} but holds a value, "
                        f"a salt or a redaction marker"), set()
            if mode == "hash-only" and not (
                    decl.get("alg") in _HASH_ALGS and (_hash_only_salted(decl)
                                                       or _hash_only_linkable(decl))):
                return f"path {path}: malformed hash-only declaration", set()
            if mode == "withheld" and not isinstance(decl.get("cause"), str):
                return f"path {path}: a withheld field names its cause", set()
            held_none.add(path)
        elif mode in ("scrub", "unscanned", "scrubbed-upstream"):
            found = decl.get("found")
            if mode == "scrub" and not (
                    isinstance(found, dict) and found and all(
                        isinstance(k, str) and type(v) is int and v > 0
                        for k, v in found.items())):
                return f"path {path}: a scrub names what it found", set()
        else:
            return f"path {path}: unknown capture mode {mode!r}", set()
        if "linkable" in decl and mode != "hash-only":
            return f"path {path}: only a hash-only field is linkable", set()
        if "by" in decl and not isinstance(decl["by"], str):
            return f"path {path}: an upstream claim names its tool as text", \
                set()
        if any(k in decl and not isinstance(decl[k], str)
               for k in ("applied_by", "policy")):
            return (f"path {path}: a field's own applier and policy are "
                    f"text"), set()
    return None, held_none


def _verify_entry_data(entry: dict):
    # Every entry carries `data` and `commitments`, empty when the step
    # recorded nothing: one spelling of an empty step, so no reader can take
    # an absent member for a different statement than an empty one. `salts`
    # may be absent - a step whose every path was redacted or never stored
    # needs none.
    data = entry.get("data")
    if not isinstance(data, dict):
        # `data` is not covered by the entry hash, so a tampered entry can
        # carry a data of any shape. A non-object is a verdict, not a crash:
        # the commitment walk below reads a field off it, and this must answer
        # the same way the product verifier does on the same file.
        return False, "entry data is not a JSON object"
    # salts/commitments/redacted, like data, can be tampered to any shape (the
    # first two are outside the hash, and the entry hash is recomputable); a
    # wrong type is a verdict, not a crash, matching the product verifier.
    salts = entry.get("salts", {})
    if not isinstance(salts, dict):
        return False, "entry salts is not a JSON object"
    commitments = entry.get("commitments")
    if not isinstance(commitments, dict):
        return False, "entry commitments is not a JSON object"
    redacted = entry.get("redacted", [])
    if not isinstance(redacted, list) \
            or any(not isinstance(p, str) for p in redacted):
        # a redaction marker is a list of step:path strings; a non-string
        # (e.g. unhashable) element is a verdict, not a TypeError out of set()
        return False, "entry redacted is not a JSON array of strings"
    if "redacted" in entry and not redacted:
        # absent until a path is redacted: [] would be a second spelling of
        # nothing redacted, addable outside the hash and the signed map
        return False, ("entry redacted is an empty list - absent until a "
                       "path is redacted")
    redacted = set(redacted)
    err, held_none = _capture_problem(entry)
    if err:
        return False, err
    # A marker names a path this entry committed. One that names anything else
    # claims a redaction that never had a value to remove, and would be
    # counted in the verdict's redaction total.
    phantom = sorted(redacted - set(commitments))
    if phantom:
        return False, (f"path {phantom[0]} is marked redacted but was never "
                       f"committed by this entry")
    alg = entry.get("alg", "blake2b-256")
    for path in commitments:
        present, value = _value_at(data, path)
        if path in redacted:
            if present:
                return False, (f"path {path} is marked redacted but its "
                               f"value is still present")
            if path in salts:
                # The salt is what would let a holder of the value re-derive
                # the commitment and confirm a guess. A redaction that keeps
                # it has not destroyed the field, whatever the marker says.
                return False, (f"path {path} is marked redacted but its salt "
                               f"is still present - the value is recoverable "
                               f"by anyone who can guess it")
            continue
        if path in held_none:
            continue                  # declared: committed, never stored
        if not present:
            return False, (f"path {path} missing without a redaction marker "
                           f"or a capture declaration")
        salt_hex = salts.get(path, "")
        # A non-string salt is malformed at the salt, in the words the
        # product verifier uses for the same bytes.
        if not isinstance(salt_hex, str):
            return False, f"malformed salt for path {path}"
        try:
            raw_salt = bytes.fromhex(salt_hex)
        except ValueError:
            return False, f"malformed salt for path {path}"
        if len(raw_salt) != SALT_BYTES:
            # Named as the salt: a 65-byte salt used to surface as BLAKE2b's
            # key limit, blamed on the value; an 8-byte one was accepted.
            return False, (f"salt for path {path} is {len(raw_salt)} bytes - "
                           f"a salt is {SALT_BYTES} bytes")
        try:
            commitment = _field_commitment(salt_hex, value, alg)
        except (ValueError, TypeError, RecursionError) as exc:
            # Name the real cause: pointing an investigator at the salt when
            # the value is the problem sends them to the wrong field.
            return False, f"path {path} cannot be canonicalized: {exc}"
        if commitment != commitments[path]:
            return False, (f"data hash mismatch at path {path} - value "
                           f"tampered or corrupted")
    # Top-level keys that have a committed descendant, precomputed once. The
    # husk check below asks this per empty-dict path; scanning all commitments
    # inside the loop is O(paths x commitments) - a hostile bundle with N empty
    # husks each over a redacted child stalls the verifier for O(N^2) with no
    # verdict (a valid bundle still passes, so it is a denial of verdict). A path
    # here never contains "." (guarded below), so its committed children are
    # exactly the commitments whose first dotted segment equals it.
    committed_top_parents = {c.split(".", 1)[0]
                             for c in commitments if "." in c}
    for path in _data_paths(data):
        if path not in commitments:
            husk = data.get(_unescape_key(path))
            if ("." not in path and isinstance(husk, dict) and not husk
                    and path in committed_top_parents):
                continue
            return False, f"uncommitted data at path {path}"
    return True, None


def verify_bundle(bundle: dict, expect_key: str | None = None,
                  expect_recorder_key: str | None = None,
                  trusted_bundle_keys: list | None = None,
                  trusted_recorder_keys: list | None = None,
                  expect_tsa: str | None = None,
                  expect_witnesses: dict | None = None,
                  witness_threshold: int = 1,
                  expect_recorder_pq_key: str | None = None,
                  expect_pq_key: str | None = None,
                  trusted_pq_keys: dict | None = None,
                  require_pq: bool = False,
                  log_checkpoints: tuple = (),
                  log_tail: dict | None = None,
                  point_in_time: bool = False):
    """Return (ok, error). The error names what failed and where.

    Total: hostile input of any shape is a failed verification, never an
    exception."""
    try:
        return _verify_bundle(bundle, Trust(
            expect_key, expect_recorder_key, trusted_bundle_keys,
            trusted_recorder_keys, expect_tsa, expect_witnesses,
            witness_threshold, expect_recorder_pq_key, expect_pq_key,
            trusted_pq_keys, require_pq, tuple(log_checkpoints), log_tail,
            point_in_time))
    except RuntimeError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"malformed bundle: {exc!r}"


def _json_kind(value) -> str:
    """The JSON kind of a parsed value, in JSON's own words."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    return type(value).__name__


def _container_shape(container):
    """The container fields every bundle form shares, checked by type before
    anything reads them, so a wrong shape is named by field - never surfaced
    as the Python exception the read would have raised."""
    if not isinstance(container.get("run_id"), str):
        return "bundle run_id is not a string"
    if not isinstance(container.get("chain"), dict):
        return "chain is not a JSON object"
    for name in ("checkpoints", "anchors"):
        if name in container and not isinstance(container[name], list):
            return f"{name} is not a JSON array"
        for j, item in enumerate(container.get(name) or []):
            if not isinstance(item, dict):
                return f"{name[:-1]} {j} is not a JSON object"
    signature = container.get("signature")
    if signature is not None and not isinstance(signature, dict):
        return "signature is not a JSON object"
    return None


def _same_key(a, b) -> bool:
    """Hex keys compare case-insensitively: a key pasted in upper case is
    the same key."""
    return isinstance(a, str) and isinstance(b, str) and a.lower() == b.lower()


def _key_in(key, keys) -> bool:
    return any(_same_key(key, k) for k in keys)


def _verify_bundle(bundle, trust):
    if not isinstance(bundle, dict):
        return False, (f"not a bundle: the document is {_json_kind(bundle)}, "
                       f"not an object")
    if bundle.get("format") != FORMAT:
        return False, ("the document carries no format field"
                       if bundle.get("format") is None else
                       f"unsupported format {bundle.get('format')!r}")
    err = _container_shape(bundle)
    if err:
        return False, err
    entries = bundle.get("entries", [])
    if not isinstance(entries, list):
        return False, "entries is not a JSON array"
    if not entries:
        return False, ("bundle carries no entries - an empty chain is not "
                       "evidence of a run")
    prev = GENESIS
    claims = []
    markers = {}
    seen = {"run_end": None, "fork": None}
    for i, entry in enumerate(entries):
        ok, err = _entry_check(entry, i, prev, bundle.get("run_id"))
        if not ok:
            return False, err
        prev = entry["hash"]
        err = _run_step(entry, i, seen)
        if err:
            return False, err
        if entry.get("kind") == "redaction":
            claims.extend((i, t) for t in _redaction_fields(entry))
        marks = entry.get("redacted")
        if isinstance(marks, list) and marks:
            markers[i] = marks

    head = entries[-1]["hash"] if entries else None
    if bundle.get("chain", {}).get("head_hash") != head:
        return False, "chain head_hash does not match the final entry"

    # One rule every reader shares - this API, the command line, every bag
    # and pack, and the product's own verify_run: a run that recorded what
    # its own stated standing says it must not is not evidence.
    err = (_standing_refusal(_run_capture([entries]))
           or _redaction_incomplete(claims, markers, len(entries)))
    if err:
        return False, err

    if trust.recorder_pinned:
        # Recorder tier: a redaction is accountable only if a head-covering
        # recorder checkpoint attests it. The claim entry is hash-covered and
        # advances the head, so require every marker to carry an on-chain
        # claim; the head-coverage check in _check_seals then rejects a forged
        # claim appended past the last checkpoint. This holds whether or not
        # the bundle carries a signature: a bundle signature is the EXPORTER's
        # attestation, and the exporter is exactly the party whose store
        # access the recorder tier exists to distrust, so it can never stand
        # in for the recorder's own material.
        err = _unclaimed_marker(claims, markers)
        if err:
            return False, err

    def hash_at(index: int):
        return entries[index].get("hash") if 0 <= index < len(entries) \
            else None

    return _check_seals(bundle, len(entries), hash_at, trust, markers,
                        sealed=seen["run_end"] is not None)


def _run_step(entry, i, seen):
    """The rules a run holds across its entries, applied as each streams
    past, `seen` carrying the step of the run's seal and of its fork entry
    (both None until met; updated here). Only the audit kinds may follow a
    seal, and a seal attests its own position + 1 as an integer; a run forks
    once, so a second fork entry is refused rather than one of the two read.
    The product's verify_run and verify_stream apply the same rule."""
    kind = entry.get("kind")
    if seen["run_end"] is not None and kind not in AUDIT_KINDS:
        return (f"step {seen['run_end']}: run_end seal is not final - only "
                f"redaction, repair, hold and hold_release audit entries may "
                f"follow a seal")
    if kind == "run_end":
        sealed = entry["data"].get("steps")
        if not _is_int(sealed) or sealed != i + 1:
            return (f"step {i}: run_end seal attests {sealed} steps but "
                    f"was sealed at {i + 1}")
        seen["run_end"] = i
    if kind == "fork":
        if seen["fork"] is not None:
            return (f"step {i}: a second fork entry - a run forks once, at "
                    f"step {seen['fork']}")
        seen["fork"] = i
    return None


def _redaction_fields(entry):
    """The `step:path` tokens a redaction entry claims - a list of strings.
    `data` is not covered by the entry hash, so `fields` may be any shape; a
    non-list, or a non-string element, is not a claim, and must not crash the
    claims walk - it stays a verdict, matching the product verifier."""
    data = entry.get("data")
    fields = data.get("fields") if isinstance(data, dict) else None
    return [t for t in fields if isinstance(t, str)] \
        if isinstance(fields, list) else []


def _redaction_incomplete(claims, markers, total):
    """Error if a recorded redaction claim was never applied to its
    target step - a bundle asserting 'we redacted X' where X is still
    present must FAIL. Mirrors the product's verify_run/verify_stream."""
    # Membership-test each step's marker list as a set built once. `path not in
    # list` per claim is O(len(marks)); a redaction entry claiming N paths over
    # one step whose marker list holds N paths made this O(N^2) - a valid bundle
    # then stalled the verifier with no verdict. A path is always a string, so
    # only string marks can match; filtering to those also keeps set() safe on
    # an unhashable element in a tampered marker list.
    mark_sets = {step: {m for m in marks if isinstance(m, str)}
                 for step, marks in markers.items() if isinstance(marks, list)}
    for red_step, token in claims:
        step_text, _, path = token.partition(":")
        # isascii() guards int(): a Unicode digit like "²" passes isdigit()
        # but raises in int(); a claim's step is always an ASCII-decimal str.
        # The length bound guards `int()`: CPython refuses to convert an
        # integer literal past 4300 digits. A blanket except upstream
        # turned that into 'malformed bundle', which is a verdict but
        # the wrong one - the bundle is well formed and this claim
        # simply names no step. A step is written one way, without a
        # leading zero: "01:x" names no step, in a run of any length, and
        # so cannot back a marker in _unclaimed_marker either.
        if not (step_text.isascii() and step_text.isdigit()) \
                or (len(step_text) > 1 and step_text[0] == "0") \
                or len(step_text) > len(str(total)) \
                or int(step_text) >= total:
            continue
        marks = mark_sets.get(int(step_text))
        if marks is None or path not in marks:
            return (f"step {red_step}: redaction of {token} recorded but "
                    f"not applied - the bundle's redaction claim is false")
    return None


def _unclaimed_marker(claims, markers):
    """Error if a redaction MARKER has no matching on-chain redaction CLAIM.
    Called only at the recorder tier (checkpoint-authenticated, no bundle
    signature). redact_in_place write-aheads a `redaction` claim naming
    `step:path` AND re-checkpoints the new head, so an accountable store
    redaction re-verifies while a keyless strip (marker, no claim - the head
    is unmoved, so the recorder checkpoint still validates) fails as an
    unaccountable withholding. The plain verdict keeps the export-redaction
    exemption (it asserts no authenticity) and the signature tier binds the
    marker set directly, so neither calls this - mirroring the product's
    verify_run/_unclaimed_marker for a stored run."""
    claimed = {token for _, token in claims}
    for step, paths in sorted(markers.items()):
        for path in paths:
            if f"{step}:{path}" not in claimed:
                return (f"step {step}: path {path} is marked redacted but no "
                        f"on-chain redaction claim records it - an "
                        f"unaccountable redaction is not recorder-authenticated")
    return None


_INSTANT = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]+)?(?:Z|[+-]([0-9]{2}):([0-9]{2}))")


def _iso_instant(value) -> bool:
    """An RFC 3339 date-time (bundle-spec: Entries, `ts`): YYYY-MM-DD, an
    upper-case T, HH:MM:SS, an optional fraction of one or more digits, then
    an upper-case Z or a +HH:MM / -HH:MM offset - a real calendar date, hour
    00-23, minute and second 00-59, offset hour 00-23 and minute 00-59. A
    grammar any language can implement, not one library's parser."""
    import datetime as _dt
    found = _INSTANT.fullmatch(value) if isinstance(value, str) else None
    if found is None:
        return False
    year, month, day, hour, minute, second, off_h, off_m = found.groups()
    try:
        _dt.datetime(int(year), int(month), int(day), int(hour), int(minute),
                     int(second))
    except ValueError:
        return False
    return off_h is None or (int(off_h) <= 23 and int(off_m) <= 59)


# A verified identity (bundle-spec.md, Verified identity): what a recorder
# that verifies who acts records of the person behind an act, from the
# OpenID Connect ID token it checked - the token's issuer and subject, the
# claim the deployment takes as the principal, and that principal. Never the
# token itself.
IDENTITY_FIELDS = ("issuer", "subject", "claim", "principal")
IDENTITY_CLAIMS = ("sub", "email")


def identity_problem(block, principal) -> "str | None":
    """Why `block` is not a verified identity of `principal`, or None: its
    four fields exactly, each non-empty text, a principal taken from `sub`
    or `email` - from `sub`, the subject itself - and the principal the
    record names."""
    if not isinstance(block, dict) or set(block) != set(IDENTITY_FIELDS):
        return (f"a verified identity holds exactly "
                f"{', '.join(IDENTITY_FIELDS)}")
    if not all(isinstance(block[k], str) and block[k]
               for k in IDENTITY_FIELDS):
        return "a verified identity's fields are non-empty text"
    if block["claim"] not in IDENTITY_CLAIMS:
        return (f"a verified identity's principal is taken from "
                f"{' or '.join(IDENTITY_CLAIMS)}, not {block['claim']!r}")
    if block["claim"] == "sub" and block["principal"] != block["subject"]:
        return ("a verified identity taken from sub has its subject as its "
                "principal")
    if block["principal"] != principal:
        return (f"the verified identity is {block['principal']!r}'s, and the "
                f"record names {principal!r}")
    return None


def audit_identity_problem(kind, data) -> "str | None":
    """Why an audit entry's verified identities do not stand, or None. A
    hold, a release or a redaction the recorder verified carries
    `verified_identity` for its `by`; a redaction approved under two-person
    control carries `requested_identity` for its `requested_by` too, and
    the two must be different people - one issuer's subject is one person,
    whatever names the records give it."""
    if not isinstance(data, dict):
        return None
    for field, who in (("verified_identity", "by"),
                       ("requested_identity", "requested_by")):
        if field in data:
            problem = identity_problem(data[field], data.get(who))
            if problem:
                return f"a {kind} entry's {field}: {problem}"
    asked, done = data.get("requested_identity"), data.get("verified_identity")
    if asked is None:
        return None
    if kind != "redaction":
        return f"a {kind} entry names no requester, so no requested_identity"
    if done is None:
        return ("a redaction names its requester's verified identity and not "
                "its approver's")
    if (asked["issuer"], asked["subject"]) == (done["issuer"],
                                               done["subject"]):
        return (f"a redaction's requester and approver are one verified "
                f"person ({asked['subject']!r} of {asked['issuer']}): "
                f"two-person control was not met")
    return None


def ledger_identity_problem(event: dict) -> "str | None":
    """Why a ledger event's verified identity does not name its `by`, or
    None (an event with none is not checked: its `by` is asserted)."""
    if "verified_identity" not in event:
        return None
    return identity_problem(event["verified_identity"], event.get("by"))


def _entry_rules(entry: dict):
    """The per-entry vocabulary rules: a known kind, the provenance class that kind may carry, a parseable
    timestamp, and an audit entry left whole, whose verified identities
    (audit_identity_problem) stand."""
    kind, prov = entry.get("kind"), entry.get("prov")
    if not isinstance(kind, str) or kind not in PROV_BY_KIND:
        return f"unknown entry kind {kind!r}"
    if prov not in PROV_BY_KIND[kind]:
        return (f"a {kind} entry cannot be {prov} - it is "
                f"{' or '.join(PROV_BY_KIND[kind])}")
    if not _iso_instant(entry.get("ts")):
        return f"ts is not an ISO 8601 instant with an offset ({entry.get('ts')!r})"
    if kind in AUDIT_KINDS and entry.get("redacted"):
        return (f"a {kind} audit entry cannot be redacted - the audit trail "
                f"is what a redaction is accountable to")
    if kind == "run_end" and entry.get("redacted"):
        return ("a run_end seal cannot be redacted - it commits the step "
                "count the run is verified against")
    if kind in AUDIT_KINDS:
        return audit_identity_problem(kind, entry.get("data"))
    return None


def _entry_check(entry: dict, i: int, prev: str, run_id):
    """One entry against its position, predecessor, and run identity."""
    if not isinstance(entry, dict):
        return False, f"step {i}: entry is not a JSON object"
    body = {k: v for k, v in entry.items()
            if k not in ("hash", "data", "salts", "redacted")}
    try:
        payload = _canonical(body)
    except (ValueError, TypeError, RecursionError) as exc:
        # A body no canonicalizer can hash names its step like any other
        # broken entry, in the words the product verifier uses.
        return False, f"step {i}: entry cannot be canonicalized: {exc}"
    if entry.get("alg") not in _HASH_ALGS:
        return False, f"step {i}: unsupported hash algorithm {entry.get('alg')!r}"
    if body.get("run_id") != run_id:
        return False, (f"step {i}: entry run_id {body.get('run_id')!r} "
                       f"does not match bundle run_id")
    if not _is_int(body.get("step")) or body.get("step") != i:
        return False, f"step {i}: step index mismatch"
    if body.get("prev") != prev:
        return False, f"step {i}: chain broken"
    if _hash_hex(entry.get("alg"), payload) != entry.get("hash"):
        return False, f"step {i}: hash mismatch - entry tampered or corrupted"
    if entry.get("prov") not in ("observed", "asserted", "synthetic"):
        return False, (f"step {i}: unknown or missing provenance "
                       f"{entry.get('prov')!r}")
    err = _entry_rules(entry)
    if err:
        return False, f"step {i}: {err}"
    ok, err = _verify_entry_data(entry)
    if not ok:
        return False, f"step {i}: {err}"
    return True, None


def _check_seals(container: dict, entries_len: int, hash_at, trust,
                 markers=None, sealed=False):
    """Checkpoint chain, external anchors, and bundle signature for both
    bundle forms."""
    checkpoints = container.get("checkpoints", [])
    worm_anchors = [a for a in container.get("anchors", [])
                    if a.get("type") == "worm"]
    if (trust.recorder_pinned
            and not checkpoints and not worm_anchors):
        return False, ("a recorder key was required but the bundle carries "
                       "no checkpoints or worm anchors for it to have signed")
    if (trust.require_pq and not checkpoints and not worm_anchors
            and container.get("signature") is None):
        return False, ("--require-pq was given but nothing in the bundle is "
                       "signed at all")
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
        if not _is_int(cp.get("seq")) or cp.get("seq") != i:
            return False, f"checkpoint {i}: sequence gap"
        if cp.get("prev_checkpoint") != prev_checkpoint:
            return False, f"checkpoint {i}: checkpoint chain broken"
        if (trust.expect_recorder_key is not None
                and not _same_key(cp.get("public_key"), trust.expect_recorder_key)):
            return False, (f"checkpoint {i}: not signed by the trusted "
                           f"recorder key")
        if (trust.trusted_recorder_keys is not None
                and not _key_in(cp.get("public_key"), trust.trusted_recorder_keys)):
            return False, (f"checkpoint {i}: not signed by a trusted "
                           f"recorder key")
        if cp.get("alg") not in _HASH_ALGS:
            # A checkpoint signed over a null or unknown algorithm attests a
            # chain link nobody can recompute unambiguously.
            return False, (f"checkpoint {i}: unsupported hash algorithm "
                           f"{cp.get('alg')!r}")
        if not _derived_key_id(cp):
            return False, (f"checkpoint {i}: key_id does not derive from its "
                           f"public_key")
        if not _ed25519_verify(cp.get("public_key", ""), _canonical(attested),
                               cp.get("signature", "")):
            return False, f"checkpoint {i}: signature invalid"
        err = _pq_rule(cp, "checkpoint", _canonical(attested), trust,
                       "recorder")
        if err:
            return False, f"checkpoint {i}: {err}"
        steps = cp.get("steps")
        # An integer-valued float `steps` indexes differently in a list than
        # in a dict, so the two bundle forms would split on it; refuse a
        # non-int, matching the product verifier and the anchor binding. An
        # absent one is refused too: it signs the same body as null.
        if not _is_int(steps):
            return False, f"checkpoint {i}: non-integer step count {steps!r}"
        if steps < 0:
            # A negative count binds no entry, so it would attest nothing and
            # pass; the product's verify_one_checkpoint refuses it alike.
            return False, f"checkpoint {i}: negative step count {steps}"
        if steps > entries_len:
            return False, (f"checkpoint {i}: attests {steps} steps but the "
                           f"bundle has {entries_len} - history removed "
                           f"below a signed checkpoint")
        if steps > 0 and hash_at(steps - 1) != cp.get("head_hash"):
            return False, (f"checkpoint {i}: attested head does not match "
                           f"the chain at step {steps - 1}")
        prev_checkpoint = _hash_hex(cp["alg"], _canonical(attested))
    err = _pq_downgrade(checkpoints, trust)
    if err:
        return False, err

    anchor_err = _verify_anchors(container, entries_len, hash_at, trust)
    if anchor_err is not None:
        return False, anchor_err

    if trust.recorder_pinned:
        # The recorder material must cover the HEAD, not merely exist: a
        # run_end's `steps` is not hash-covered, so a forged tail appended
        # past the last genuine checkpoint would otherwise ride on the
        # recorder's real prefix checkpoints (bundle-spec: the tail is not
        # guaranteed "by local files alone"). A legitimately sealed run gets a
        # final head-covering checkpoint on clean exit; an anchored head
        # covers it otherwise. A bundle signature does not: it is the
        # exporter's attestation, made by the very store-writer whose tail
        # this tier exists to distrust, so the demand is the same whether the
        # bundle is signed, unsigned, or signed by a key nobody pinned.
        if not any(m.get("steps") == entries_len
                   for m in (*checkpoints, *worm_anchors)):
            return False, ("a recorder key was required but no checkpoint "
                           "or worm anchor covers the bundle head - an "
                           "unsigned tail is not recorder-authenticated")
    if sealed and checkpoints and not any(
            cp.get("steps") == entries_len for cp in checkpoints):
        # Once a run is sealed, every append the recorder made - the seal and
        # each audit entry after it - minted a head-covering checkpoint. A
        # sealed bundle whose head no checkpoint covers therefore carries a
        # tail written without the key. The product refuses it on every path;
        # this tier refuses it too, whatever the bundle signature says.
        return False, ("sealed run has entries past its last recorder "
                       "checkpoint - the tail is not recorder-attested (no "
                       "checkpoint covers the head)")

    ok, err = _check_bundle_signature(container, trust, markers)
    if not ok:
        return ok, err
    # After the signature, so a signed bundle that was altered is named as
    # altered whatever else changed with it.
    log_err = _check_tlog(container.get("tlog"), checkpoints, trust)
    return (False, log_err) if log_err is not None else (True, None)


def _pq_downgrade(checkpoints, trust=None):
    """Once a checkpoint carries a post-quantum half, every later one must,
    pinned or not, and a recorder key keeps the PQ key it started with: a
    classical checkpoint after a hybrid one, or a new PQ key beside the same
    Ed25519 key, is what someone holding only the Ed25519 key would write.
    The one allowed change is a rotation the relying party vouches for: a
    new PQ key that `trust` pins for that recorder key (a trust file's
    `pq_public_key` entries, or --expect-recorder-pq-key). The product's
    manifest.pq_downgrade is the same rule."""
    first, by_key = None, {}
    for i, cp in enumerate(checkpoints):
        pq = cp.get("pq_public_key")
        if pq is None:
            if first is not None:
                return (f"checkpoint {i}: carries no post-quantum signature "
                        f"after checkpoint {first} did - a downgrade "
                        f"mid-chain")
            continue
        first = i if first is None else first
        classical = str(cp.get("public_key", "")).lower()
        if by_key.setdefault(classical, pq) != pq:
            if trust is None or str(pq).lower() not in trust.pq_pins(
                    "recorder", classical):
                return (f"checkpoint {i}: the post-quantum key changed beside "
                        f"the same recorder key - not the key its earlier "
                        f"checkpoints were signed with, and not a rotation "
                        f"the trust file lists")
            by_key[classical] = pq
    return None


def _check_bundle_signature(container: dict, trust, markers):
    """The exporter's signature over the bundle head and every set the
    bundle carries beside it."""
    signature = container.get("signature")
    if signature is None:
        if trust.bundle_pinned:
            # A pinned key on an unsigned bundle is most often the recorder's
            # key given where the exporter's belongs: name the way to pin it.
            cps = container.get("checkpoints")
            ids = sorted({cp["key_id"] for cp in cps if isinstance(cp, dict)
                          and isinstance(cp.get("key_id"), str)}) \
                if isinstance(cps, list) else []
            hint = (f"; its checkpoints are signed by recorder key id "
                    f"{', '.join(ids)} - to pin that recorder, pass its "
                    f"public key with --expect-recorder-key") if ids else ""
            return False, ("bundle is unsigned but a trusted key was "
                           "required - refusing to verify" + hint)
        return True, None
    if signature.get("algorithm") != "ed25519":
        return False, (f"unsupported signature algorithm "
                       f"{signature.get('algorithm')!r}")
    for field, shape in (("public_key", _HEX64), ("signature", _HEX128)):
        value = signature.get(field)
        if not isinstance(value, str) or not shape.fullmatch(value):
            return False, f"signature.{field} is not a hex string"
    # The signed body is one shape: it always names the signing time and
    # the key, so no reader has to decide what an absent one would have said.
    if not _derived_key_id(signature):
        return False, "signature key_id does not derive from its public_key"
    if not _iso_instant(signature.get("signed_at")):
        return False, ("signature.signed_at is not an ISO 8601 instant with "
                       "an offset")
    if (trust.expect_key is not None
            and not _same_key(signature["public_key"], trust.expect_key)):
        return False, "signature public_key is not the trusted key"
    if (trust.trusted_bundle_keys is not None
            and not _key_in(signature["public_key"], trust.trusted_bundle_keys)):
        return False, "signature public_key is not among the trusted keys"
    signed_body = {"format": container.get("format"),
                   "run_id": container.get("run_id"),
                   "chain": container.get("chain"),
                   "signed_at": signature["signed_at"],
                   "key_id": signature["key_id"]}
    if "checkpoints" in container:
        signed_body["checkpoints"] = container["checkpoints"]
    if "anchors" in container:
        signed_body["anchors"] = container["anchors"]
    if "tlog" in container:     # a log proof stripped after signing breaks it
        signed_body["tlog"] = container["tlog"]
    red = {str(i): sorted(m) for i, m in (markers or {}).items()
           if isinstance(m, list) and m}
    if red:  # bind the redaction set: a marker added after signing breaks this
        signed_body["redactions"] = red
    if not _ed25519_verify(signature["public_key"], _canonical(signed_body),
                           signature["signature"]):
        return False, "signature check failed - bundle altered after signing"
    err = _pq_rule(signature, "bundle", _canonical(signed_body), trust,
                   "bundle")
    if err:
        return False, f"bundle signature: {err}"
    return True, None


# -- the transparency log (bundle-spec: Transparency log) ---------------------
_DASH = "— "


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return _sha256(b"\x01" + left + right)


def _verify_inclusion(leaf: bytes, index: int, size: int, path: list,
                      root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2, step for step."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node(p, r)
            while not fn & 1 and fn != 0:
                fn, sn = fn >> 1, sn >> 1
        else:
            r = _node(r, p)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and r == root


def _note_key_id(name: str, kind: bytes, public_hex: str) -> bytes:
    return _sha256(name.encode("utf-8") + b"\n" + kind
                   + bytes.fromhex(public_hex))[:4]


_MLDSA44_SIZES = (1312, 2420)
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,19}")


def _note_number(text):
    """A C2SP note's tree size: ASCII decimal, no leading zero, below 2^64 -
    the range its uint64 encodings hold. None for anything else. `isdigit`
    is not this test: it admits non-ASCII digits, and `int` of a very long
    string raises."""
    if not isinstance(text, str) or not _DECIMAL.fullmatch(text):
        return None
    value = int(text)
    return value if value < 2 ** 64 else None


def _note_pq_key_id(name: str, alg: str, pq_public_hex: str) -> bytes:
    """signed-note type 0xff, then the identifier `aer-mldsa65-note`
    (for ML-DSA-65; and so on), then the raw ML-DSA key."""
    ident = f"aer-{alg.lower().replace('-', '')}-note".encode("ascii")
    return _sha256(name.encode("utf-8") + b"\n\xff" + ident
                   + bytes.fromhex(pq_public_hex))[:4]


def _cosigned_subtree(witness: str, stamp: int, origin: str, size: int,
                      root: bytes):
    """C2SP tlog-cosignature's CosignedSubtree for a checkpoint: the label,
    cosigner name, timestamp, origin, start 0, end size, root hash. None for
    a name or origin outside 1..255 bytes."""
    name, log = witness.encode("utf-8"), origin.encode("utf-8")
    if not (1 <= len(name) <= 255 and 1 <= len(log) <= 255):
        return None
    return (b"subtree/v1\n\x00" + bytes([len(name)]) + name
            + stamp.to_bytes(8, "big") + bytes([len(log)]) + log
            + (0).to_bytes(8, "big") + size.to_bytes(8, "big") + root)


def _mldsa44_verify(public_hex: str, message: bytes, signature: bytes) -> bool:
    module = _mldsa()
    if module is None:
        raise RuntimeError(_NO_MLDSA)
    try:
        module.MLDSA44PublicKey.from_public_bytes(
            bytes.fromhex(public_hex)).verify(signature, message)
        return True
    except Exception:  # noqa: BLE001 - InvalidSignature, ValueError
        return False


def _open_note(note: str, keys: dict, witnesses: dict, pq_keys=None):
    """(origin, size, root, note signers, cosigners, PQ note signers) of a
    checkpoint note (C2SP signed-note; cosignature/v1 lines from Ed25519
    `witnesses`, 0x06 ML-DSA-44 lines from ML-DSA-44 ones; 0xff ML-DSA lines
    from the signers `pq_keys` names as {name: (classical hex, alg, ML-DSA
    hex)}), or None if the note is not one."""
    split = note.rfind("\n\n")
    if split < 0:
        return None
    text, lines = note[:split + 1], note[split + 2:].splitlines()
    # c2sp.org/tlog-checkpoint: at least three non-empty lines - origin,
    # size, root - then any extension lines, opaque, optional and each
    # non-empty. `text` ends in the newline before the blank line, so the
    # last part is always the empty one after it.
    parts = text.split("\n")
    if (len(parts) < 4 or not all(parts[:-1])
            or _note_number(parts[1]) is None):
        return None
    try:
        root = base64.b64decode(parts[2], validate=True)
    except ValueError:
        return None
    if len(root) != 32:
        return None
    signers, cosigners, pq_signers = set(), set(), set()
    for line in lines:
        if not line.startswith(_DASH) or " " not in line[len(_DASH):]:
            continue
        name, _, blob_text = line[len(_DASH):].rpartition(" ")
        try:
            blob = base64.b64decode(blob_text, validate=True)
        except ValueError:
            continue
        if name in witnesses and len(witnesses[name]) == 2 * _MLDSA44_SIZES[0]:
            key = witnesses[name]
            stamp = int.from_bytes(blob[4:12], "big")
            message = _cosigned_subtree(name, stamp, parts[0], int(parts[1]),
                                        root)
            if (len(blob) == 12 + _MLDSA44_SIZES[1] and message is not None
                    and blob[:4] == _note_key_id(name, b"\x06", key)
                    and _mldsa44_verify(key, message, blob[12:])):
                cosigners.add(name)
        elif name in witnesses and len(blob) == 76:
            key = witnesses[name]
            stamp = int.from_bytes(blob[4:12], "big")
            message = f"cosignature/v1\ntime {stamp}\n{text}".encode("utf-8")
            if (blob[:4] == _note_key_id(name, b"\x04", key)
                    and _ed25519_verify(key, message, blob[12:].hex())):
                cosigners.add(name)
        elif name in keys and len(blob) == 68:
            key = keys[name]
            if (blob[:4] == _note_key_id(name, b"\x01", key)
                    and _ed25519_verify(key, text.encode("utf-8"),
                                        blob[4:].hex())):
                signers.add(name)
        elif name in (pq_keys or {}):
            # The line must be there on every host; its signature is checked
            # where the library has ML-DSA, and otherwise left unchecked as
            # every other post-quantum half is (_pq_half).
            classical, alg, pq_public = pq_keys[name]
            if (len(blob) == 4 + _PQ_ALGS[alg][1]
                    and blob[:4] == _note_pq_key_id(name, alg, pq_public)
                    and (_mldsa() is None or _pq_verify(
                        alg, pq_public, _pq_message(
                            "note", text.encode("utf-8"), classical, alg,
                            _key_id(pq_public)), blob[4:].hex()))):
                pq_signers.add(name)
    return parts[0], int(parts[1]), root, signers, cosigners, pq_signers


def _is_index(value) -> bool:
    return _is_int(value) and value >= 0


def _check_tlog(proof, checkpoints, trust):
    """The bundle's head checkpoint is in the deployment's transparency log:
    an inclusion proof into a log checkpoint the same recorder key signed,
    and - when the caller pinned witnesses - cosigned by enough of them;
    and it holds against the log checkpoints and log tail the caller gives
    (_log_history). None when it holds (or no proof is carried and none was
    required)."""
    return _tlog_verdict(proof, checkpoints, trust)[0]


def _tlog_verdict(proof, checkpoints, trust):
    """(why the bundle's log proof does not hold, or None; and when it
    holds, what the caller's log checkpoints and tail established -
    _log_history's facts)."""
    if proof is None:
        if trust.expect_witnesses:
            return ("witnesses were required but the bundle carries no "
                    "transparency-log proof"), None
        if trust.log_checkpoints or trust.log_tail is not None:
            return ("a log checkpoint or log tail was given but the bundle "
                    "carries no transparency-log proof to hold it against"), \
                None
        return None, None
    if not isinstance(proof, dict) or not checkpoints:
        return "tlog is not a proof of a checkpoint the bundle carries", None
    note, leaf, path = proof.get("note"), proof.get("leaf"), proof.get("proof")
    index, size = proof.get("index"), proof.get("size")
    if not (isinstance(note, str) and isinstance(leaf, str)
            and _is_index(index) and _is_index(size)
            and isinstance(path, list)
            and all(isinstance(p, str) for p in path)):
        return "tlog proof is malformed", None
    head = checkpoints[-1]
    attested = {"run_id": head.get("run_id"), "seq": head.get("seq"),
                "steps": head.get("steps"), "head_hash": head.get("head_hash"),
                "prev_checkpoint": head.get("prev_checkpoint"),
                "alg": head.get("alg"), "key_id": head.get("key_id")}
    if leaf.encode("utf-8") != _canonical(attested):
        return "tlog leaf is not the bundle's head checkpoint", None
    try:
        hashes = [base64.b64decode(p, validate=True) for p in path]
    except ValueError:
        return "tlog proof is malformed", None
    origin = note.split("\n", 1)[0]
    signing = _log_signers(origin, head, trust)
    for keys, pq_keys in signing:
        opened = _open_note(note, keys, trust.expect_witnesses or {}, pq_keys)
        if opened is None:
            return "tlog checkpoint is not a checkpoint note", None
        if origin in opened[3]:
            break
    else:
        return "tlog checkpoint is not signed by the recorder key", None
    _, note_size, root, signers, cosigners, pq_signers = opened
    if pq_keys and origin not in pq_signers:
        return ("tlog checkpoint carries no valid post-quantum signature by "
                "the recorder key its head checkpoint names"), None
    if note_size != size:
        return "tlog size does not match its checkpoint", None
    if not _verify_inclusion(_sha256(b"\x00" + leaf.encode("utf-8")), index,
                             size, hashes, root):
        return ("tlog inclusion proof does not hold - the head is not in the "
                "log"), None
    if trust.expect_witnesses and len(cosigners) < trust.witness_threshold:
        return (f"tlog checkpoint is cosigned by {len(cosigners)} of the "
                f"pinned witnesses; {trust.witness_threshold} required"), None
    return _log_history(head.get("run_id"), leaf, index, size, root, origin,
                        signing, trust)


def _log_signers(origin: str, head: dict, trust) -> list:
    """The keys a note of this log is accepted as signed by, in the order
    tried, each as ({origin: Ed25519 key}, {origin: its post-quantum half}
    or {}): the head checkpoint's own key - a hybrid head's key signs the
    note with its PQ half too, and a note without that line is one the
    Ed25519 key alone made - then each other recorder key a trust file
    pins, with the half pinned for it. A run recorded before a key rotation
    and exported after it sits in a log whose newer notes the next key
    signed: under a trust file that pins both keys (the overlap window), a
    note signed by any pinned recorder key is the deployment's; unpinned,
    only the run's own key, since any other signer would prove nothing."""
    public_hex = head.get("public_key")
    out = [({origin: public_hex},
            {origin: (public_hex, head["pq_alg"], head["pq_public_key"])}
            if head.get("pq_public_key") is not None else {})]
    for key in trust.trusted_recorder_keys or ():
        if _same_key(key, public_hex) or not isinstance(key, str):
            continue
        pins = trust.pq_pins("recorder", key)
        out.append(({origin: key},
                    {origin: (key, head.get("pq_alg") or "ML-DSA-65",
                              sorted(pins)[0])} if pins else {}))
    return out


def _split_view(origin: str, size: int) -> str:
    return (f"split view: log {origin} has two different roots at size "
            f"{size}, both signed by its key - it showed one history to one "
            f"reader and another to another")


def _merkle_root(hashes: list) -> bytes:
    """RFC 9162 Merkle tree hash of these leaf hashes (one or more)."""
    if len(hashes) == 1:
        return hashes[0]
    k = 1 << ((len(hashes) - 1).bit_length() - 1)
    return _node(_merkle_root(hashes[:k]), _merkle_root(hashes[k:]))


def _tail_root(size: int, start: int, left: list, tail: list) -> bytes:
    """The root of the log at `size` (> `start`) from `left`, the roots of
    the aligned perfect subtrees covering leaves 0 up to `start`, largest
    first, and `tail`, the hashes of the leaves from `start` on. Splits as
    RFC 9162 does: a part wholly before `start` is the next of `left`, a
    part from `start` on is hashed from the leaves."""
    blocks = iter(left)

    def node(lo: int, hi: int) -> bytes:
        if lo >= start:
            return _merkle_root(tail[lo - start:hi - start])
        if hi <= start:
            return next(blocks)
        k = 1 << ((hi - lo - 1).bit_length() - 1)
        return _node(node(lo, lo + k), node(lo + k, hi))
    return node(0, size)


def _log_tail_problem(tail) -> str | None:
    """Why a log tail (--log-tail) is not one, or None: {"from": the first
    leaf's index, "leaves": the leaves from there on, each one line of
    text, "left": base64 of the 32-byte roots before "from", one per set
    bit of it}."""
    if not (isinstance(tail, dict) and set(tail) == {"from", "leaves", "left"}
            and _is_index(tail["from"]) and isinstance(tail["leaves"], list)
            and tail["leaves"] and isinstance(tail["left"], list)
            and len(tail["left"]) == bin(tail["from"]).count("1")
            and all(isinstance(t, str) and "\n" not in t
                    for t in tail["leaves"])
            and all(isinstance(t, str) for t in tail["left"])
            and tail["from"] + len(tail["leaves"]) < 2 ** 64):
        return ('the log tail is not {"from", "leaves", "left"} - the first '
                'leaf index, the leaves from it, and one base64 root per set '
                'bit of the index')
    try:
        if any(len(base64.b64decode(t, validate=True)) != 32
               for t in tail["left"]):
            raise ValueError("a root is 32 bytes")
    except ValueError:
        return "the log tail's left roots are not base64 of 32 bytes each"
    return None


def _signed_by_log(text: str, origin: str, signing: list) -> bool:
    """Whether a note is signed by one of the log's keys (_log_signers),
    with its post-quantum half where that key has one pinned."""
    for keys, pq_keys in signing:
        opened = _open_note(text, keys, {}, pq_keys)
        if origin in opened[3] and (not pq_keys or origin in opened[5]):
            return True
    return False


def _log_history(run_id, leaf: str, index: int, size: int, root: bytes,
                 origin: str, signing: list, trust):
    """The bundle's log proof held against the log checkpoints and the log
    tail the caller gives. Returns (why it
    fails, or None; the facts it established: `held`, the checkpoints of
    this log counted; `latest`, the log size up to which the run's head is
    shown to be its latest; `later`, the latest later head of the run the
    tail holds, as (leaf, seq, steps, head_hash); `beyond`, asked about a
    point in time, the newest held size no tail reached - the log up to it
    was not searched for a later head).

    - Two roots of this log at one size, both signed by its key, are a
      split view: the bundle's own checkpoint and each held one.
    - The tail's leaves, with the roots before them, must give each held
      root it reaches: a root it does not give is a history the log forked.
    - Given a checkpoint later than the bundle's, the run's head must be
      shown to be its latest up to that checkpoint: a later leaf of
      the run in the tail fails the bundle, naming that head. Asked about
      a point in time, the bundle stands as the run stood at its own
      checkpoint, and the later head is named, not refused.

    A checkpoint of another log says nothing of this one and is passed
    over; one naming this log that its key did not sign fails, since it
    cannot be held against the bundle."""
    roots, held = {size: root}, 0
    for text in trust.log_checkpoints:
        opened = _open_note(text, {}, {}) if isinstance(text, str) else None
        if opened is None or opened[0] != origin:
            continue
        if not _signed_by_log(text, origin, signing):
            return (f"a held checkpoint of log {origin} (size {opened[1]}) is "
                    f"not signed by its key - it cannot be held against the "
                    f"bundle"), None
        held += 1
        if roots.setdefault(opened[1], opened[2]) != opened[2]:
            return _split_view(origin, opened[1]), None
    newest = max(roots)
    facts = {"held": held, "latest": None, "later": None,
             "beyond": newest if newest > size else None}
    behind = (f"the bundle cannot be shown to be run {run_id!r}'s latest "
              f"logged head")
    tail = trust.log_tail
    if tail is None:
        if newest > size and not trust.point_in_time:
            return (f"a checkpoint of log {origin} at size {newest} is held, "
                    f"later than the bundle's at {size}, but no log tail "
                    f"shows the leaves after the bundle's head: {behind}"), \
                None
        return None, facts
    problem = _log_tail_problem(tail)
    if problem:
        return problem, None
    start, leaves = tail["from"], tail["leaves"]
    end = start + len(leaves)
    if not (start <= index < end and leaves[index - start] == leaf):
        return (f"the log tail (leaves {start} to {end - 1}) does not hold "
                f"the bundle's head at leaf {index}"), None
    if end not in roots:
        return (f"the log tail ends at size {end}, and no checkpoint of log "
                f"{origin} at that size is held to check it against"), None
    left = [base64.b64decode(t) for t in tail["left"]]
    hashes = [_sha256(b"\x00" + t.encode("utf-8")) for t in leaves]
    if _tail_root(end, start, left, hashes) != roots[end]:
        return (f"the log tail's leaves do not give log {origin}'s root at "
                f"size {end} - they are not the log's leaves"), None
    for n, expected in sorted(roots.items()):
        if start < n < end and _tail_root(n, start, left, hashes) != expected:
            return (f"split view: log {origin}'s root at size {n} is not the "
                    f"one its leaves give at size {end} - the log was forked "
                    f"or rewritten between them"), None
    if end < newest and not trust.point_in_time:
        return (f"the log tail ends at size {end}, before the held checkpoint "
                f"of log {origin} at size {newest}: {behind}"), None
    for j in range(index + 1, end):
        try:
            doc = _loads(leaves[j - start])
        except ValueError:
            continue           # no run's checkpoint: it names no head
        if (isinstance(doc, dict) and doc.get("run_id") == run_id
                and leaves[j - start] != leaf):
            facts["later"] = (j, doc.get("seq"), doc.get("steps"),
                              doc.get("head_hash"))
    if facts["later"] is not None and not trust.point_in_time:
        return (f"the bundle's head is not run {run_id!r}'s latest logged "
                f"head: log {origin} holds a later one - "
                f"{_later_text(facts['later'])}"), None
    facts["latest"] = end
    facts["beyond"] = newest if newest > end else None
    return None, facts


def _later_text(later) -> str:
    j, seq, steps, head_hash = later
    return (f"leaf {j}, checkpoint {seq} at step {steps}, head {head_hash}")


def _history_note(facts, size) -> str:
    """The verdict's clause on what the caller's log checkpoints and tail
    established (_log_history), for a log proof that holds; none for one
    that does not (facts None)."""
    if facts is None:
        return ""
    note = (f", {_n(facts['held'], 'held log checkpoint')} of this log, no "
            f"two roots at one size" if facts["held"] else "")
    if facts["later"] is not None:
        note += (f", as the run stood at log size {size} (asked about that "
                 f"point in time): the log holds a later head of it - "
                 f"{_later_text(facts['later'])}")
    elif facts["latest"] is not None:
        note += (f", the run's latest logged head as of log size "
                 f"{facts['latest']}")
    if facts["beyond"] is not None:
        note += (f", as the run stood at log size {size}: the log up to the "
                 f"held checkpoint at size {facts['beyond']} was not searched "
                 f"for a later head (no log tail reaches it)")
    return note


def _log_note(proof, trust, checkpoints=()) -> str:
    """What a verified log proof established, scoped to what was pinned
    and to the log checkpoints and tail the caller gave."""
    if not isinstance(proof, dict):
        return ""
    history = ""
    if trust.log_checkpoints or trust.log_tail is not None:
        history = _history_note(_tlog_verdict(proof, checkpoints, trust)[1],
                                proof["size"])
    return _log_where(proof, trust) + history


def _log_where(proof, trust) -> str:
    """Where the proof puts the head in the log, and how many pinned
    witnesses cosigned the checkpoint it is proved into."""
    origin = proof["note"].split("\n", 1)[0]
    where = (f", in transparency log {origin} (leaf {proof['index']} of "
             f"{proof['size']})")
    if not trust.expect_witnesses:
        return where + (" - witnesses not pinned: pass --expect-witness to "
                        "know there is one history")
    opened = _open_note(proof["note"], {}, trust.expect_witnesses)
    pq = sum(len(k) != 64 for n, k in trust.expect_witnesses.items()
             if n in opened[4])
    classical = len(opened[4]) - pq
    kinds = [f"{pq} with ML-DSA-44, post-quantum"] if pq else []
    kinds += [f"{classical} with Ed25519 only"] if classical else []
    return (where + f", witnessed by {len(opened[4])} of "
            f"{len(trust.expect_witnesses)} pinned"
            + (f" ({'; '.join(kinds)})" if kinds else ""))


JSONL_FORMAT = "aer-bundle-jsonl"


def verify_jsonl(lines, expect_key: str | None = None,
                 expect_recorder_key: str | None = None,
                 trusted_bundle_keys: list | None = None,
                 trusted_recorder_keys: list | None = None,
                 expect_tsa: str | None = None,
                 expect_witnesses: dict | None = None,
                 witness_threshold: int = 1,
                 expect_recorder_pq_key: str | None = None,
                 expect_pq_key: str | None = None,
                 trusted_pq_keys: dict | None = None,
                 require_pq: bool = False,
                 log_checkpoints: tuple = (),
                 log_tail: dict | None = None,
                 point_in_time: bool = False):
    """Streaming verification of the JSONL bundle form.

    `lines` is any iterable of text lines: header first, then one entry
    per line. Entries are verified as they stream and never held
    together - the GB-scale path. Returns (ok, error, summary) where
    summary carries steps/signed/redacted counts. Total: hostile input
    is a failed verification, never an exception."""
    try:
        return _verify_jsonl(lines, Trust(
            expect_key, expect_recorder_key, trusted_bundle_keys,
            trusted_recorder_keys, expect_tsa, expect_witnesses,
            witness_threshold, expect_recorder_pq_key, expect_pq_key,
            trusted_pq_keys, require_pq, tuple(log_checkpoints), log_tail,
            point_in_time))
    except RuntimeError as exc:
        return False, str(exc), None
    except Exception as exc:
        return False, f"malformed bundle: {exc!r}", None


def _loads_line(number: int, text: str):
    """Parse one line of a JSONL bundle, naming the line on failure."""
    try:
        return _loads(text)
    except ValueError as exc:
        raise RuntimeError(f"line {number} is not JSON: {exc}") from None


def _verify_jsonl(lines, trust):
    stream = ((n, line) for n, line in enumerate(lines, 1) if line.strip())
    first = next(stream, None)
    if first is None:
        return False, "empty bundle", None
    header = _loads_line(*first)
    if not isinstance(header, dict):
        return False, "line 1 is not a JSON object", None
    if header.get("format") != JSONL_FORMAT:
        return False, ("the first line carries no format field"
                       if header.get("format") is None else
                       f"unsupported format {header.get('format')!r}"), None
    err = _container_shape(header)
    if err:
        return False, err, None
    run_id = header.get("run_id")
    checkpoints = header.get("checkpoints", [])
    # Only an integer `steps` names an entry hash to capture; any other value
    # is left for _check_seals and the anchor binding to refuse by name.
    needed = {m["steps"] - 1 for m in (*checkpoints, *header.get("anchors", []))
              if _is_int(m.get("steps")) and m["steps"] > 0}
    captured: dict[int, str] = {}
    markers: dict[int, list] = {}
    claims = []
    prev = GENESIS
    count = 0
    redacted = 0
    seen = {"run_end": None, "fork": None}
    mix = {"observed": 0, "asserted": 0, "synthetic": 0}
    injected = gaps = relayed = 0
    capture: dict = {}
    via: dict = {}
    relay_hosts: set = set()
    for i, (number, line) in enumerate(stream):
        entry = _loads_line(number, line)
        ok, err = _entry_check(entry, i, prev, run_id)
        if not ok:
            return False, err, None
        prev = entry["hash"]
        count = i + 1
        mix[entry["prov"]] += 1
        injected += entry.get("kind") == "injected"
        gaps += _gaps(entry)
        _capture_counts(entry, capture)
        _via_tally(entry, via)
        host = _relay_peer(entry)
        if host is not None:
            relayed += 1
            relay_hosts.add(host)
        err = _run_step(entry, i, seen)
        if err:
            return False, err, None
        if i in needed:
            captured[i] = prev
        marks = entry.get("redacted")
        if isinstance(marks, list) and marks:
            markers[i] = marks
        redacted += len(marks) if isinstance(marks, list) else (1 if marks
                                                                else 0)
        if entry.get("kind") == "redaction":
            claims.extend((i, t) for t in _redaction_fields(entry))
    if not count:
        return False, ("bundle carries no entries - an empty chain is not "
                       "evidence of a run"), None
    head = prev
    if header.get("chain", {}).get("head_hash") != head:
        return False, "chain head_hash does not match the final entry", None
    err = (_standing_refusal(capture)
           or _redaction_incomplete(claims, markers, count))
    if err:
        return False, err, None
    if trust.recorder_pinned:
        # Recorder tier (see _verify_bundle): every marker must carry an
        # on-chain claim, else the strip is not recorder-authenticated - and a
        # bundle signature, being the exporter's, never stands in for that.
        err = _unclaimed_marker(claims, markers)
        if err:
            return False, err, None
    ok, err = _check_seals(header, count, captured.get, trust, markers,
                           sealed=seen["run_end"] is not None)
    if not ok:
        return False, err, None
    summary = {"steps": count, "signed": "signature" in header,
               "redacted": redacted, "sealed": seen["run_end"] is not None,
               "mix": mix, "injected": injected, "gaps": gaps,
               "capture": capture, "via": via,
               "relayed": relayed, "relay_hosts": len(relay_hosts)}
    return True, None, summary


def _key_id(public_hex: str) -> str:
    """BLAKE2b-64 of the raw public key - the key_id the product mints."""
    return hashlib.blake2b(bytes.fromhex(public_hex), digest_size=8).hexdigest()


def _derived_key_id(record: dict) -> bool:
    """Whether the record's key_id is the id of the key beside it. A trust
    file and a runbook name keys by id; an id that derives from nothing
    names nothing. Checked after the signature, so the key is known good."""
    public = record.get("public_key")
    if not isinstance(public, str) or not _HEX64.fullmatch(public):
        return False
    return record.get("key_id") == _key_id(public)


def _ed25519_verify(public_hex: str, data: bytes, signature_hex: str) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)
    except ImportError:
        raise RuntimeError(
            "verifying signatures requires the 'cryptography' package - "
            "pip install cryptography") from None

    try:
        if not isinstance(public_hex, str) or not _HEX64.fullmatch(
                public_hex):
            return False
        if not isinstance(signature_hex, str) or not _HEX128.fullmatch(
                signature_hex):
            return False
        raw = bytes.fromhex(public_hex)
        # Against a small-order key a zero signature verifies every message,
        # so "signed" would not mean anyone held a private key.
        if _is_small_order(raw):
            return False
        signature = bytes.fromhex(signature_hex)
        if not _canonical_scalar(signature[32:]):
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(signature, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --- External anchors ----------------------------------------------------
#
# A worm anchor is a recorder-signed head attestation exported to an
# immutable store; an rfc3161 anchor is a timestamp-authority token over
# the head. Both bind {steps, head_hash}: the verifier checks the anchor's
# own integrity and that the bundle still carries that head at that step,
# so truncation below an externally held anchor fails. Mirrors the
# product's bitexact/anchor.py; the golden anchor vectors keep them in
# lockstep.

_WORM_ATTESTED = ("type", "run_id", "steps", "head_hash", "alg", "key_id",
                  "anchored_at")
_IMPRINT_ALG = "sha256"


def _anchor_binding(anchor, run_id, entries_len, hash_at):
    if anchor.get("run_id") != run_id:
        return "anchor run_id does not match the bundle"
    steps = anchor.get("steps")
    if not _is_int(steps) or steps < 0:
        return "anchor has a non-integer step count"
    if steps > entries_len:
        return (f"anchor attests {steps} steps but the bundle has "
                f"{entries_len} - truncated below an externally anchored "
                f"head")
    if steps > 0 and hash_at(steps - 1) != anchor.get("head_hash"):
        return ("anchor head does not match the bundle chain at the "
                "anchored step")
    return None


def _verify_worm_anchor(anchor, trust):
    public = anchor.get("public_key", "")
    if (trust.expect_recorder_key is not None
            and not _same_key(public, trust.expect_recorder_key)):
        return "worm anchor not signed by the trusted recorder key"
    if (trust.trusted_recorder_keys is not None
            and not _key_in(public, trust.trusted_recorder_keys)):
        return "worm anchor not signed by a trusted recorder key"
    # As a checkpoint's: a head attested under no algorithm, or an unknown
    # one, names nothing a reader can recompute.
    if anchor.get("alg") not in _HASH_ALGS:
        return (f"worm anchor alg {anchor.get('alg')!r} is not a supported "
                f"hash algorithm")
    attested = {k: anchor.get(k) for k in _WORM_ATTESTED}
    # The certificate that asked the recorder for the anchor, when it did,
    # is signed with the rest.
    if "submitted_by" in anchor:
        attested["submitted_by"] = anchor["submitted_by"]
    if not _ed25519_verify(public, _canonical(attested),
                           anchor.get("signature", "")):
        return "worm anchor signature invalid"
    if not _derived_key_id(anchor):
        return "worm anchor key_id does not derive from its public_key"
    err = _pq_rule(anchor, "worm-anchor", _canonical(attested), trust,
                   "recorder")
    return f"worm anchor {err}" if err else None


def _verify_anchors(container, entries_len, hash_at, trust):
    run_id = container.get("run_id")
    for i, anchor in enumerate(container.get("anchors", [])):
        kind = anchor.get("type")
        if kind == "worm":
            err = _verify_worm_anchor(anchor, trust)
        elif kind == "rfc3161":
            err = _verify_rfc3161_anchor(anchor, trust.expect_tsa)
        else:
            err = f"unknown anchor type {kind!r}"
        if err is None:
            err = _anchor_binding(anchor, run_id, entries_len, hash_at)
        if err is not None:
            return f"anchor {i}: {err}"
    return None


def _hash_alg_refusal(anchor) -> str:
    """Why an rfc3161 anchor's `hash_alg` is refused, word for word the
    product's: the field is required, and sha256 is the only algorithm
    defined for the message imprint."""
    declared = (f"declares hash_alg {anchor['hash_alg']!r}"
                if "hash_alg" in anchor else "declares no hash_alg")
    return (f"rfc3161 anchor {declared} - it must declare sha256, the only "
            f"algorithm defined for the message imprint")


def _verify_rfc3161_anchor(anchor, expect_tsa):
    """The token is read first, then the anchor's own declaration -
    `hash_alg`, required and always sha256 - then the token's content."""
    try:
        token = base64.b64decode(anchor.get("token", ""), validate=True)
    except Exception:
        return "rfc3161 anchor token is not valid base64"
    if anchor.get("hash_alg") != _IMPRINT_ALG:
        return _hash_alg_refusal(anchor)
    return _verify_rfc3161_token(token, anchor.get("head_hash", ""), expect_tsa,
                                 anchor.get("nonce"))


def _verify_rfc3161_token(token_der, head_hash_hex, expect_tsa, nonce=None):
    try:
        from asn1crypto import cms
        import asn1crypto.tsp  # noqa: F401 - registers the tst_info type
    except ImportError:
        raise RuntimeError(
            "verifying RFC 3161 anchors requires 'asn1crypto' - "
            "pip install asn1crypto")
    try:
        return _rfc3161_checks(cms, token_der, head_hash_hex, expect_tsa, nonce)
    except Exception as exc:
        return f"malformed timestamp token: {exc!r}"


def _rfc3161_checks(cms, token_der, head_hash_hex, expect_tsa, nonce=None):
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID

    info = cms.ContentInfo.load(token_der)
    if info['content_type'].native != 'signed_data':
        return "timestamp token is not CMS SignedData"
    signed = info['content']
    eci = signed['encap_content_info']
    if eci['content_type'].native != 'tst_info':
        return "timestamp token content is not a TSTInfo"
    tst = eci['content'].parsed
    imprint = tst['message_imprint']
    if imprint['hash_algorithm']['algorithm'].native != _IMPRINT_ALG:
        return "unexpected imprint algorithm"
    if imprint['hashed_message'].native != hashlib.sha256(
            bytes.fromhex(head_hash_hex)).digest():
        return ("timestamp imprint does not match the head - the token is "
                "for a different head hash")
    if nonce is not None and tst['nonce'].native != nonce:
        return ("timestamp nonce does not match the anchor's - the token "
                "answers a different request")
    signer_infos = signed['signer_infos']
    if len(signer_infos) != 1:
        return f"expected exactly one signer, found {len(signer_infos)}"
    signer = signer_infos[0]
    signer_cert = _find_signer_cert(signed, signer)
    if signer_cert is None:
        return "signer certificate is not present in the token"
    cert = x509.load_der_x509_certificate(signer_cert.dump())

    signed_attrs = signer['signed_attrs']
    if signed_attrs is None or len(signed_attrs) == 0:
        return "timestamp token has no signed attributes to verify"
    digest_name = signer['digest_algorithm']['algorithm'].native
    hash_cls = {"sha256": hashes.SHA256, "sha384": hashes.SHA384,
                "sha512": hashes.SHA512}.get(digest_name)
    if hash_cls is None:
        return f"unsupported digest algorithm {digest_name!r}"
    attrs = {a['type'].native: a for a in signed_attrs}
    message_digest = attrs.get('message_digest')
    if message_digest is None:
        return "signed attributes are missing the message-digest"
    if message_digest['values'][0].native != hashlib.new(
            digest_name, eci['content'].contents).digest():
        return "signed message-digest does not match the TSTInfo"
    content_type = attrs.get('content_type')
    if content_type is None or content_type['values'][0].native != 'tst_info':
        return "signed content-type attribute is not tst_info"
    signed_bytes = b'\x31' + signed_attrs.dump()[1:]
    sig_name = signer['signature_algorithm']['algorithm'].native
    signature = signer['signature'].native
    public_key = cert.public_key()
    try:
        if sig_name in ('rsassa_pkcs1v15', 'sha256_rsa', 'sha384_rsa',
                        'sha512_rsa'):
            if not isinstance(public_key, rsa.RSAPublicKey):
                return "signature algorithm does not match the key"
            public_key.verify(signature, signed_bytes, padding.PKCS1v15(),
                              hash_cls())
        elif sig_name in ('sha256_ecdsa', 'sha384_ecdsa', 'sha512_ecdsa'):
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return "signature algorithm does not match the key"
            public_key.verify(signature, signed_bytes, ec.ECDSA(hash_cls()))
        elif sig_name in _MLDSA_OIDS:
            # RFC 9882: pure ML-DSA, empty context, over the DER of the
            # signed attributes - a post-quantum timestamp authority.
            module = _mldsa()
            if module is None:
                return _NO_MLDSA
            expected = getattr(module, _MLDSA_OIDS[sig_name].replace("-", "")
                               + "PublicKey")
            if not isinstance(public_key, expected):
                return "signature algorithm does not match the key"
            public_key.verify(signature, signed_bytes)
        else:
            return f"unsupported signature algorithm {sig_name!r}"
    except InvalidSignature:
        return "timestamp signature does not verify"

    try:
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value
        has_timestamping = ExtendedKeyUsageOID.TIME_STAMPING in eku
    except x509.ExtensionNotFound:
        has_timestamping = False
    if not has_timestamping:
        return "signer certificate lacks the timeStamping extended key usage"

    if expect_tsa is not None:
        pinned = _load_cert(expect_tsa)
        if pinned is None:
            return "the pinned TSA certificate could not be parsed"
        if cert.fingerprint(hashes.SHA256()) != pinned.fingerprint(
                hashes.SHA256()):
            try:
                cert.verify_directly_issued_by(pinned)
            except (InvalidSignature, ValueError, TypeError):
                return ("signer certificate is neither the trusted TSA "
                        "certificate nor directly issued by it")
    return None


# id-ml-dsa-44/65/87 (RFC 9881), which asn1crypto reports as dotted OIDs.
_MLDSA_OIDS = {"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
               "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
               "2.16.840.1.101.3.4.3.19": "ML-DSA-87"}


_CLASSICAL_TSA = ("classical TSA signature (RSA/ECDSA) - its time claim is "
                  "not resistant to a quantum forger")


def _tsa_suite(anchor, expect_tsa=None) -> str:
    """How a verified RFC 3161 anchor's token is signed, in the verdict's
    words: its time claim is only as quantum-safe as the weakest signature
    it rests on. An ML-DSA token is post-quantum only when the pin rests on
    ML-DSA too - the pinned certificate is the TSA's own, or is itself an
    ML-DSA certificate; under a classical issuing CA, a forger who recovers
    the CA's key issues an ML-DSA TSA of their own."""
    try:
        from asn1crypto import cms
        import asn1crypto.tsp  # noqa: F401 - registers the tst_info type
        info = cms.ContentInfo.load(base64.b64decode(anchor.get("token", "")))
        signed = info['content']
        name = signed['signer_infos'][0]['signature_algorithm'][
            'algorithm'].native
    except Exception:  # noqa: BLE001 - already verified; naming is advisory
        return _CLASSICAL_TSA
    if name not in _MLDSA_OIDS:
        return _CLASSICAL_TSA
    alg = _MLDSA_OIDS[name]
    if expect_tsa is None:
        return (f"{alg} TSA signature, TSA not pinned - pass --expect-tsa "
                f"with its certificate")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    pinned = _load_cert(expect_tsa)
    leaf = _find_signer_cert(signed, signed['signer_infos'][0])
    leaf_fp = x509.load_der_x509_certificate(leaf.dump()).fingerprint(
        hashes.SHA256())
    if leaf_fp == pinned.fingerprint(hashes.SHA256()) or type(
            pinned.public_key()).__name__.startswith("MLDSA"):
        return f"{alg} TSA signature (post-quantum)"
    return (f"{alg} TSA signature under a classical issuing certificate - its "
            f"time claim rests on that certificate's classical signature")


def _find_signer_cert(signed, signer):
    certs = signed['certificates']
    if not certs:
        return None
    sid = signer['sid']
    for choice in certs:
        cert = choice.chosen
        if sid.name == 'issuer_and_serial_number':
            ias = sid.chosen
            if (cert.issuer == ias['issuer']
                    and cert.serial_number == ias['serial_number'].native):
                return cert
        elif sid.name == 'subject_key_identifier':
            if cert.key_identifier == sid.chosen.native:
                return cert
    return None


def _load_cert(material):
    from cryptography import x509
    if isinstance(material, str):
        material = material.encode()
    try:
        return x509.load_pem_x509_certificate(material)
    except ValueError:
        try:
            return x509.load_der_x509_certificate(material)
        except ValueError:
            return None


DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    return (b"DSSEv1 " + str(len(payload_type)).encode() + b" "
            + payload_type.encode() + b" " + str(len(payload)).encode()
            + b" " + payload)


def verify_envelope(envelope: dict, expect_key=None,
                    expect_recorder_key=None, trusted_bundle_keys=None,
                    trusted_recorder_keys=None, expect_tsa=None,
                    expect_witnesses=None, witness_threshold=1,
                    expect_recorder_pq_key=None, expect_pq_key=None,
                    trusted_pq_keys=None, require_pq=False,
                    log_checkpoints=(), log_tail=None, point_in_time=False):
    """Verify a DSSE envelope carrying an in-toto statement whose
    predicate is a bundle; returns (ok, error, bundle_or_none).

    Total: hostile input of any shape is a failed verification, never an
    exception."""
    try:
        return _verify_envelope(envelope, Trust(
            expect_key, expect_recorder_key, trusted_bundle_keys,
            trusted_recorder_keys, expect_tsa, expect_witnesses,
            witness_threshold, expect_recorder_pq_key, expect_pq_key,
            trusted_pq_keys, require_pq, tuple(log_checkpoints), log_tail,
            point_in_time))
    except RuntimeError as exc:
        return False, str(exc), None
    except Exception as exc:
        return False, f"malformed envelope: {exc!r}", None


def _dsse_accepted_payload(envelope, trust):
    """The signed payload bytes of a DSSE envelope, if a signature by an
    acceptable key verifies over it. Returns (payload, None) or (None, error).
    Shared by the run-bundle envelope and the provenance graph attestation so
    the key-acceptance rule cannot drift between them."""
    payload, _entry, err = _dsse_accepted(envelope, trust)
    return payload, err


def _dsse_accepted(envelope, trust):
    """(payload, the signature entry accepted, None) or (None, None, error).
    The entry whose Ed25519 signature is accepted carries its post-quantum
    half, if any, in the same entry, and that half must stand; the entry is
    returned so a verdict describes the signature it accepted and no other
    entry, which nothing checked."""
    expect_key, trusted_bundle_keys = trust.expect_key, trust.trusted_bundle_keys
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        return (None, None,
                f"unsupported payloadType {envelope.get('payloadType')!r}")
    try:
        payload = base64.b64decode(envelope.get("payload", ""), validate=True)
    except Exception:
        return None, None, "payload is not valid base64"
    pae = _dsse_pae(DSSE_PAYLOAD_TYPE, payload)
    for entry in envelope.get("signatures") or []:
        try:
            sig_hex = base64.b64decode(entry.get("sig", ""),
                                       validate=True).hex()
        except Exception:
            continue
        public = entry.get("public_key", "")
        if expect_key is not None and not _same_key(public, expect_key):
            continue
        if (trusted_bundle_keys is not None
                and not _key_in(public, trusted_bundle_keys)):
            continue
        if _ed25519_verify(public, pae, sig_hex):
            keyid = entry.get("keyid")
            if keyid is not None and keyid != _key_id(public):
                return None, None, ("signature keyid does not match its "
                                    "public_key")
            err = _pq_rule(entry, "dsse", pae, trust, "bundle")
            if err:
                return None, None, f"signature: {err}"
            return payload, entry, None
    return None, None, ("signature verification failed - no acceptable "
                        "signature over the payload")


def _verify_envelope(envelope, trust):
    payload, err = _dsse_accepted_payload(envelope, trust)
    if err:
        return False, f"envelope {err}", None
    try:
        statement = _loads(payload)
    except ValueError:
        return False, "envelope payload is not JSON", None
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        return False, f"unsupported statement type {statement.get('_type')!r}", None
    if statement.get("predicateType") != RUN_PREDICATE_TYPE:
        return False, (f"unsupported predicateType "
                       f"{statement.get('predicateType')!r} - a run envelope "
                       f"states {RUN_PREDICATE_TYPE}"), None
    bundle = statement.get("predicate") or {}
    subjects = statement.get("subject") or [{}]
    if subjects[0].get("name") != bundle.get("run_id"):
        return False, "statement subject does not name the bundle run", None
    if (subjects[0].get("digest", {}).get("head")
            != bundle.get("chain", {}).get("head_hash")):
        return False, "statement subject digest does not pin the chain head", None
    ok, err = verify_bundle(bundle, **trust._asdict())
    if not ok:
        return False, err, None
    return True, None, bundle


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_provenance_bundle(bag_dir, expect_key=None, expect_recorder_key=None,
                             trusted_bundle_keys=None, trusted_recorder_keys=None,
                             expect_tsa=None, expect_witnesses=None,
                             witness_threshold=1, expect_recorder_pq_key=None,
                             expect_pq_key=None, trusted_pq_keys=None,
                             require_pq=False, log_checkpoints=(),
                             log_tail=None, point_in_time=False):
    """Verify a BagIt provenance bag: bag integrity, each member run's bundle,
    and every fork edge (its prefix hash re-derived from the parent's own
    verified entries in the bag), then the reading view against the bag it
    describes (_with_view). Returns (ok, error, summary_or_none); `ok` is
    None when no verdict was reached because a file of the bag could not be
    read (the command line's exit 1, never FAIL).

    Total: hostile input of any shape is a failed verification, never an
    exception."""
    try:
        return _with_view(Path(bag_dir), _verify_provenance_bundle(
            bag_dir, Trust(
                expect_key, expect_recorder_key, trusted_bundle_keys,
                trusted_recorder_keys, expect_tsa, expect_witnesses,
                witness_threshold, expect_recorder_pq_key, expect_pq_key,
                trusted_pq_keys, require_pq, tuple(log_checkpoints),
                log_tail, point_in_time)))
    except RuntimeError as exc:
        return False, str(exc), None
    except OSError as exc:
        # The bag's own shape is checked first (_check_bag: every file a
        # plain file inside it, every manifest name one of its files), so a
        # read that fails here is the host's - a permission, a device - and
        # says nothing about the evidence.
        name = getattr(exc, "filename", None)
        return None, (f"cannot read {Path(name).name}: {exc.strerror}"
                      if name else f"cannot read the bag: {exc.strerror}"), None
    except Exception as exc:
        return False, f"malformed provenance bundle: {exc!r}", None


def _read_manifest(path: Path) -> dict:
    listed = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            digest, sep, rel = line.partition("  ")
            if not sep or not rel or not _HEX64.fullmatch(digest):
                raise RuntimeError(f"{path.name} line {n} is malformed - "
                                   f"expected '<sha256>  <path>'")
            listed[rel] = digest
    return listed


def _bag_files(bag: Path):
    """{path relative to the bag, as POSIX: Path} of every file in the bag,
    or the error naming the first entry that is a link or reaches outside
    it. Every later read is of one of these, so no read leaves the bag."""
    root = bag.resolve()
    files = {}
    for p in sorted(bag.rglob("*"), key=lambda q: q.as_posix().encode()):
        rel = p.relative_to(bag).as_posix()
        if p.is_symlink() or p.is_junction() \
                or not p.resolve().is_relative_to(root):
            return None, f"{rel} is a link - a bag holds only its own files"
        if p.is_file():
            files[rel] = p
    return files, None


def _bag_name(rel: str) -> bool:
    """A manifest path this profile reads literally: relative POSIX segments,
    none empty, `.` or `..`, and no character RFC 8493 would have encoded
    (`%`, CR, LF) or that names a drive or a Windows separator (`:`, `\\`)."""
    return (not rel.startswith("/")
            and not any(c in rel for c in "%\r\n:\\")
            and all(part not in ("", ".", "..") for part in rel.split("/")))


def _check_bag(bag: Path) -> str | None:
    """Why `bag` is not an intact BagIt bag, or None: its declaration, and
    every payload and tag file against its manifests - none added, none
    removed, none changed, none read from outside the bag - and the payload
    count and size bag-info.txt declares."""
    files, err = _bag_files(bag)
    if err:
        return err
    decl = files.get("bagit.txt")
    if decl is None or not decl.read_text(
            encoding="utf-8").startswith("BagIt-Version:"):
        return "not a BagIt bag - missing or malformed bagit.txt"
    if "manifest-sha256.txt" not in files:
        return "missing manifest-sha256.txt"
    listed = _read_manifest(files["manifest-sha256.txt"])
    payload = {rel for rel in files if rel.startswith("data/")}
    for rel in listed:
        if not (_bag_name(rel) and rel.startswith("data/")):
            return (f"manifest-sha256.txt names {rel!r}, which is not a "
                    f"payload file of this bag")
    if set(listed) != payload:
        return ("bag payload does not match manifest-sha256.txt - "
                "files were added or removed")
    for rel, digest in listed.items():
        if _sha256_file(files[rel]) != digest:
            return f"payload file {rel} fails its sha256 checksum"
    if "tagmanifest-sha256.txt" not in files:
        return "missing tagmanifest-sha256.txt"
    for name, digest in _read_manifest(files["tagmanifest-sha256.txt"]).items():
        if not (_bag_name(name) and name in files
                and not name.startswith("data/")):
            return (f"tagmanifest-sha256.txt names {name!r}, which is not a "
                    f"tag file of this bag")
        if _sha256_file(files[name]) != digest:
            return f"tag file {name} fails its sha256 checksum"
    return _oxum_problem(files, payload)


def _oxum_problem(files: dict, payload: set) -> str | None:
    """Why bag-info.txt's Payload-Oxum, when it declares one, is not the
    payload's octet count and file count (RFC 8493 section 2.2.2), or None."""
    info = files.get("bag-info.txt")
    if info is None:
        return None
    declared = next((line.partition(":")[2].strip() for line in
                     info.read_text(encoding="utf-8").splitlines()
                     if line.startswith("Payload-Oxum:")), None)
    if declared is None:
        return None
    octets = sum(files[rel].stat().st_size for rel in payload)
    actual = f"{octets}.{len(payload)}"
    if declared != actual:
        return (f"bag-info.txt Payload-Oxum {declared} is not the payload's "
                f"{actual}")
    return None


def _ledger_problem(events) -> str | None:
    """Why a hash-chained ledger (case custody, workflow governance) does not
    re-walk, or None. Each event links to the one before and its hash covers
    its own body - the product's HashChainLedger rule. A walk proves the
    events present, never that none followed: the tail is anchored by the
    recorder's signed ledger heads (_heads_problem)."""
    if not isinstance(events, list):
        return "is not a list of events"
    prev = GENESIS
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            return f"event {i} is not an object"
        # The product's writer always names its hash algorithm, so an event
        # that names none is not one it wrote.
        if "alg" not in e:
            return f"event {i}: names no hash algorithm"
        # The hash covers the event's fields and, when the recorder wrote
        # it for a peer, the certificate that asked (`submitted_by`) and the
        # person it verified (`verified_identity`) - the product's
        # ledger_body.
        body = {k: e.get(k)
                for k in ("ts", "kind", "by", "data", "prev", "alg")}
        for added in ("submitted_by", "verified_identity"):
            if added in e:
                body[added] = e[added]
        if e.get("prev") != prev:
            return f"event {i}: chain broken"
        if e["alg"] not in _HASH_ALGS or _hash_hex(
                e["alg"], _canonical(body)) != e.get("hash"):
            return f"event {i}: hash mismatch"
        problem = ledger_identity_problem(e)
        if problem:
            return f"event {i}: {problem}"
        prev = e["hash"]
    return None


def _refusal_problem(name: str, events: list, trust):
    """Why a refusal ledger (data/refusals/<run id>.jsonl) holds something
    other than the product's refusals, or None - and how many of its events
    a recorder key signed, counting only a key the caller pinned when the
    recorder is pinned. A signature that is present must verify. An unsigned
    refusal still counts: it can only add an execution that left no
    evidence, never excuse one, so it is reported, not failed."""
    pinned = ([] if trust.expect_recorder_key is None
              else [trust.expect_recorder_key])
    pinned += list(trust.trusted_recorder_keys or [])
    signed = 0
    for i, e in enumerate(events):
        data = e.get("data")
        if (e.get("kind") != "refused" or not isinstance(data, dict)
                or not isinstance(data.get("cause"), str)):
            return f"event {i} is not a refusal", 0
        if data.get("run_id") not in (None, name):
            return f"event {i} names another run than its ledger", 0
        if "sig" not in e:
            continue
        err = _event_signature_problem(e, i, trust)
        if err:
            return err, 0
        if not trust.recorder_pinned or _key_in(e["public_key"], pinned):
            signed += 1
    return None, signed


def _event_signature_problem(e: dict, i: int, trust):
    """Why a signed ledger event's signature does not stand, or None: its
    Ed25519 signature over the body its hash covers, by the key it carries
    with the key id that key derives, and its post-quantum half under the
    caller's pins (_pq_rule). Every ledger a bag carries is held to it, so a
    signature present on any event is checked, never ignored."""
    body = {k: v for k, v in e.items()
            if k not in ("sig", "public_key", "key_id", *_PQ_FIELDS)}
    if not (_ed25519_verify(e.get("public_key"), _canonical(body),
                            e.get("sig")) and _derived_key_id(e)):
        return f"event {i}: signature does not verify"
    err = _pq_rule(e, "ledger", _canonical(body), trust, "recorder")
    return f"event {i}: {err}" if err else None


def _verify_pack(bag: Path, trust):
    """An evidence pack that is not a provenance bag - a case, workflow or
    selection pack: every run bundle under data/runs/, every ledger the
    pack carries (`*.jsonl`, or `*.ledger.json` holding `events`), and the
    refusals of executions that left no run (`data/refusals/*.jsonl`)."""
    data = bag / "data"
    bundles = _byte_order((data / "runs").glob("*.bundle.json"), data)
    refusal_dir = data / "refusals"
    if not bundles and not any(refusal_dir.glob("*.jsonl")):
        return False, ("the pack holds no run bundles under data/runs/ - "
                       "nothing to verify is not evidence"), None
    # Signed only when there is a bundle to have signed: a pack of refusals
    # alone carries no bundle signature to report.
    gaps, unsealed, anchors, signed = 0, [], [], bool(bundles)
    sealed_by, capture, via, logged = [], {}, {}, []
    for path in bundles:
        bundle = _loads(path.read_text(encoding="utf-8"))
        ok, err = verify_bundle(bundle, **trust._asdict())
        if not ok:
            return False, f"run {path.name[:-len('.bundle.json')]!r}: {err}", \
                None
        sealed_by.append(_signed_parts(bundle))
        logged += _run_log_note(bundle, trust)
        entries = bundle.get("entries", [])
        gaps += sum(_gaps(e) for e in entries)
        for e in entries:
            _capture_counts(e, capture)
            _via_tally(e, via)
        if not any(e.get("kind") == "run_end" for e in entries):
            unsealed.append(bundle.get("run_id"))
        anchors.extend(bundle.get("anchors") or [])
        signed &= bool(bundle.get("signature"))
    problem, walked = _verify_ledgers(bag, trust)
    if problem:
        return False, problem, None
    return True, None, {"pack": True, "runs": len(bundles),
                        **walked, "gaps": gaps + walked["refusals"],
                        "unsealed": unsealed, "anchors": anchors,
                        "signed": signed, "capture": capture, "via": via,
                        "signatures": _signature_facts(sealed_by, trust),
                        "log": logged}


def _run_log_note(bundle, trust) -> list:
    """A bag verdict's clause on one run's log history (_history_note):
    one item when the caller gave log checkpoints or a log tail and they
    established anything of the run, else none."""
    if not (trust.log_checkpoints or trust.log_tail is not None):
        return []
    facts = _tlog_verdict(bundle.get("tlog"), bundle.get("checkpoints") or [],
                          trust)[1]
    note = _history_note(facts, bundle["tlog"]["size"]) if facts else ""
    return [f", run {bundle.get('run_id')!r}{note}"] if note else []


def _byte_order(paths, base: Path) -> list:
    """`paths` in the order of the UTF-8 bytes of each one's POSIX path under
    `base`: one order on every host. A `pathlib` sort compares by component,
    and on Windows folds case, so a list a recorder signed on one host would
    be out of order on another."""
    return sorted(paths, key=lambda p: p.relative_to(base).as_posix()
                  .encode("utf-8"))


def _ledger_files(data: Path) -> list:
    """The ledger files a bag's verification walks, in byte order
    (_byte_order): `*.jsonl`, or `*.ledger.json`, anywhere under data/ but
    the vendored verifier's own directory, data/verification/."""
    return _byte_order((p for p in data.rglob("*")
                        if p.is_file()
                        and p.relative_to(data).parts[0] != "verification"
                        and (p.suffix == ".jsonl"
                             or p.name.endswith(".ledger.json"))), data)


def _ledger_events(path: Path):
    """The events a ledger file holds: one per line of a `.jsonl`, or the
    `events` of a `*.ledger.json`."""
    text = path.read_text(encoding="utf-8")
    return (_loads(text).get("events") if path.suffix == ".json"
            else [_loads(line) for line in text.splitlines() if line.strip()])


HEADS_FILE = "ledger-heads.json"
HEADS_FORMAT = "aer-ledger-heads"


def ledger_heads(bag) -> "dict | None":
    """The statement the recorder signs over a bag's ledgers, unsigned: each
    ledger file's path, event count and head hash, and each run bundle's run
    id, step count and head hash. The runs bind the heads to this pack, so an
    older ledger cannot ride into a newer pack with the head an older pack
    signed for it. `problem` is what the recorder's own verification of the
    ledger in its store found when it signed (None when it verified). None
    for a provenance bag that carries no ledger. The recorder and this
    verifier build it with this one function, so they cannot disagree about
    what a head is. Read after the ledgers and runs it names have verified."""
    bag = Path(bag)
    data = bag / "data"
    ledgers = []
    for path in _ledger_files(data):
        events = _ledger_events(path)
        ledgers.append({"path": path.relative_to(bag).as_posix(),
                        "events": len(events),
                        "head_hash": events[-1]["hash"] if events else None,
                        "problem": None})
    if not ledgers and (data / "provenance-graph.json").is_file():
        return None
    runs = []
    for path in _byte_order((data / "runs").glob("*.bundle.json"), data):
        bundle = _loads(path.read_text(encoding="utf-8"))
        runs.append({"run_id": bundle["run_id"],
                     "steps": len(bundle["entries"]),
                     "head_hash": bundle["entries"][-1]["hash"]})
    return {"format": HEADS_FORMAT, "ledgers": ledgers, "runs": runs}


def _heads_problem(bag: Path, trust):
    """Why the bag's ledgers do not end exactly at the heads the recorder
    signed (data/ledger-heads.json), or None. A walk cannot see a dropped
    tail; the signed head can. Its signature is checked as a checkpoint's
    is - Ed25519 by the key it carries with the key id that key derives,
    that key a pinned recorder key when one is pinned, and the post-quantum
    half under purpose `ledger-heads` by the caller's pins (_pq_rule). One
    form: a pack, or a bag that carries a ledger, without the statement
    fails."""
    want = ledger_heads(bag)
    if want is None:
        return None
    path = bag / "data" / HEADS_FILE
    if not path.is_file():
        return (f"the pack carries no signed ledger heads (data/{HEADS_FILE})"
                f" - nothing anchors its ledgers' newest events")
    doc = _loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("format") != HEADS_FORMAT:
        return f"data/{HEADS_FILE} is not an {HEADS_FORMAT} statement"
    attested = {k: doc.get(k) for k in ("format", "ledgers", "runs",
                                        "key_id")}
    # The certificate that asked the recorder to sign, when a keyless pack
    # writer did, is signed with the rest.
    if "submitted_by" in doc:
        attested["submitted_by"] = doc["submitted_by"]
    key = doc.get("public_key")
    if ((trust.expect_recorder_key is not None
         and not _same_key(key, trust.expect_recorder_key))
            or (trust.trusted_recorder_keys is not None
                and not _key_in(key, trust.trusted_recorder_keys))):
        return "the ledger heads are not signed by the pinned recorder key"
    if not (_ed25519_verify(key, _canonical(attested), doc.get("signature"))
            and _derived_key_id(doc)):
        return "the ledger heads' signature does not verify"
    err = _pq_rule(doc, "ledger-heads", _canonical(attested), trust,
                   "recorder")
    if err:
        return f"the ledger heads: {err}"
    signed = ({h.get("path"): h for h in attested["ledgers"]
               if isinstance(h, dict)}
              if isinstance(attested["ledgers"], list) else {})
    for head in want["ledgers"]:
        got = signed.pop(head["path"], None)
        if isinstance(got, dict) and got.get("problem") is not None:
            return (f"ledger {head['path']} failed the recorder's own "
                    f"verification when it signed its head: {got['problem']}")
        if not _same_json(got, head):
            at = (f"{_n(got.get('events'), 'event')} (head "
                  f"{got.get('head_hash')})" if isinstance(got, dict)
                  else "none")
            return (f"ledger {head['path']} ends at "
                    f"{_n(head['events'], 'event')} (head {head['head_hash']})"
                    f", not at the head the recorder signed: {at}")
    if signed:
        return (f"the recorder signed a head for a ledger the pack does not "
                f"carry ({next(iter(signed))!r}) - removed from it")
    if not _same_json(attested["ledgers"], want["ledgers"]):
        return ("the ledger heads do not list the bag's ledgers once each, "
                "in order - they are listed by the UTF-8 bytes of their "
                "paths")
    if not _same_json(attested["runs"], want["runs"]):
        return ("the ledger heads were signed for another set of runs than "
                "the pack holds - its ledgers and their heads are not this "
                "pack's")
    return None


def _verify_ledgers(bag: Path, trust):
    """Every ledger a bag carries - `*.jsonl`, or `*.ledger.json` holding
    `events`, outside data/verification/ - chain-walked, every signature an
    event carries checked (_event_signature_problem), and each
    data/refusals/*.jsonl checked as the refusals of executions that left
    no run: the set the reading view shows (_view_refusals, _view_ledgers),
    so the page never shows a ledger the verdict did not walk. Then every
    one must end at the head the recorder signed (_heads_problem). Returns
    (problem, None) or (None, {"ledgers", "anchored", "refusals",
    "refusals_signed"}), `anchored` naming each ledger that is not a
    refusal ledger with its event count."""
    data = bag / "data"
    ledgers = refusals = refusals_signed = 0
    anchored = []
    for path in _ledger_files(data):
        rel = path.relative_to(bag).as_posix()
        events = _ledger_events(path)
        problem = _ledger_problem(events)
        if not problem and path.parent == data / "refusals":
            problem, n = _refusal_problem(path.stem, events, trust)
            refusals += len(events)
            refusals_signed += n
        elif not problem:
            problem = next((err for err in (
                _event_signature_problem(e, i, trust)
                for i, e in enumerate(events) if "sig" in e) if err), None)
            ledgers += 1
            anchored.append((rel, len(events)))
        if problem:
            return f"ledger {rel} {problem}", None
    problem = _heads_problem(bag, trust)
    if problem:
        return problem, None
    return None, {"ledgers": ledgers, "anchored": anchored,
                  "refusals": refusals, "refusals_signed": refusals_signed}


def _signed_parts(bundle: dict) -> dict:
    """The parts of a verified bundle its verdict's signature-suite line is
    read from, kept without its entries."""
    return {k: bundle[k] for k in ("checkpoints", "anchors", "signature")
            if k in bundle}


def _verify_provenance_bundle(bag_dir, trust):
    bag = Path(bag_dir)
    problem = _check_bag(bag)
    if problem:
        return False, problem, None
    data = bag / "data"
    graph_path = data / "provenance-graph.json"
    if not graph_path.is_file():
        return _verify_pack(bag, trust)
    graph = _loads(graph_path.read_text(encoding="utf-8"))
    if not isinstance(graph, dict):
        return False, "provenance-graph.json is not a JSON object", None
    if graph.get("format") != GRAPH_FORMAT:
        return False, (f"unsupported provenance graph format "
                       f"{graph.get('format')!r}"), None

    # The reading view shows every data/runs/*.bundle.json, so the graph must
    # name exactly those: a bundle it does not name would be shown unverified,
    # and one it names elsewhere would be verified but never shown. Checked
    # before any is read, so a node's path is never followed out of runs/.
    named = {node["bundle"] for node in graph.get("nodes", [])}
    held = {p.relative_to(data).as_posix()
            for p in _view_files(data / "runs", "*.bundle.json")}
    if held - named:
        unlisted = "data/" + min(held - named)
        return False, (f"{unlisted!r} is a run bundle the provenance graph "
                       f"does not name - the bag carries a run its graph does "
                       f"not vouch for"), None
    if named - held:
        misplaced = "data/" + min(named - held)
        return False, (f"graph node bundle {misplaced!r} is not a file under "
                       f"data/runs/ - every run the graph names must be held "
                       f"there"), None

    verified = {}
    anchors = []   # any member run's anchors, for the RFC 3161 time-trust caveat
    containers = []
    logged = []
    for node in graph.get("nodes", []):
        rid = node.get("run_id")
        bundle = _loads((data / node["bundle"]).read_text(encoding="utf-8"))
        ok, err = verify_bundle(
            bundle, **trust._asdict())
        if not ok:
            return False, f"run {rid!r}: {err}", None
        # The graph is unsigned on a plain bag, so the name it gives a node -
        # and the root name the verdict prints - is attacker-writable. The
        # bundle's own run_id is inside the hash chain. They must agree, or a
        # doctorer can relabel whose evidence this is.
        if bundle.get("run_id") != rid:
            return False, (f"graph node {rid!r} points at a bundle for run "
                           f"{bundle.get('run_id')!r} - the graph renames the "
                           f"evidence it carries"), None
        entries = bundle.get("entries", [])
        head = entries[-1]["hash"] if entries else None
        if node.get("head_hash") != head:
            return False, (f"run {rid!r}: graph head does not match the "
                           f"bundle chain head"), None
        verified[rid] = entries
        anchors.extend(bundle.get("anchors") or [])
        containers.append(_signed_parts(bundle))
        logged += _run_log_note(bundle, trust)

    err, walked = _verify_ledgers(bag, trust)
    if err:
        return False, err, None

    err = _check_edges(graph, verified)
    if err:
        return False, err, None
    err = _check_listing(bag, graph, verified)
    if err:
        return False, err, None

    att = data / "attestations" / "provenance.dsse.json"
    signed = att.is_file()
    if trust.bundle_pinned and not signed:
        return False, ("provenance bundle carries no graph attestation but a "
                       "signing key was required"), None
    if signed:
        err = _verify_graph_attestation(
            _loads(att.read_text(encoding="utf-8")), graph, verified, trust)
        if err:
            return False, err, None
    # The fork-edge count printed on the OK verdict is DERIVED from the verified
    # node set, never read from the graph's `edges` array - on an unsigned bag
    # that array is attacker-writable, so a doctorer could otherwise print "N
    # runs, 0 fork edges". _check_edges proves the bag is one tree rooted at
    # `root`, so the in-bag edge count is nodes - 1 - precise whether the root is
    # an original or a fork whose source lies outside the bag (counting committed
    # fork entries would over-count that boundary fork).
    fork_edges = max(0, len(verified) - 1)
    # The root's own seal, so a caller who demanded --require-sealed gets the
    # same answer from a bag as from the run on its own. Every other member is
    # a fork, and _check_edges already requires those to be sealed.
    root_sealed = any(e.get("kind") == "run_end"
                      for e in verified.get(graph.get("root"), []))
    return True, None, {"runs": len(verified), "edges": fork_edges,
                        "root": graph.get("root"), "signed": signed,
                        "anchors": anchors, "sealed": root_sealed,
                        "signatures": _signature_facts(containers, trust),
                        **walked,
                        "gaps": walked["refusals"] + sum(
                            _gaps(e) for run in verified.values()
                            for e in run),
                        "capture": _run_capture(verified.values()),
                        "via": _run_via(verified.values()), "log": logged}


def _run_capture(runs) -> dict:
    counts: dict = {}
    for run in runs:
        for e in run:
            _capture_counts(e, counts)
    return counts


def _run_via(runs) -> dict:
    """The capture-path tally (_via_tally) over every entry of every run."""
    counts: dict = {}
    for run in runs:
        for e in run:
            _via_tally(e, counts)
    return counts


# --- The reading view (data/view.html) ----------------------------------------
#
# A page anyone can open offline, showing the runs a bag holds as readable
# steps. It proves nothing and says so first. It cannot tell a different story
# from the bundles: it is a pure function of the bag's own files, rendered by
# this function only - the product writes it by loading this file - and a bag
# whose page differs from what render_view makes of the bag fails
# (_with_view). No script, no external reference, no form, no link out of the
# page; one hash-locked stylesheet; every recorded value through _view_text.

VIEW_FILE = "view.html"
VIEW_FORMAT = "aer-view"
# A rendered value longer than this many code points is cut, and the page
# stops rendering step data once it holds this many: both deterministic, so a
# page rendered again from the same bag matches it byte for byte.
VIEW_VALUE_LIMIT = 16 * 1024
VIEW_PAGE_LIMIT = 64 * 1024 * 1024
VIEW_MISMATCH = (f"data/{VIEW_FILE} does not match the runs it describes - it "
                 f"shows something the bundles do not say. Read the bundles, "
                 f"not the view.")
VIEW_NOTICE = (
    "This page is a reading aid, not a verification result. It was generated "
    "from the bundles in this pack when the pack was made, and it does not say "
    "whether they are intact or who signed them. To verify, run the BitExact "
    "verifier on the pack's root - python data/verification/"
    "bitexact_verifier.py . when the pack carries it (verify-procedure.md has "
    "the steps). That command also renders this page again and fails the pack "
    "if the page differs from the bundles. If this page and "
    "data/runs/*.bundle.json ever disagree, the bundles are the record.")
# What each step is, in the inspector's words: app.js KIND_LABEL, pinned equal
# by a test. A kind it does not name is shown by its recorded name.
VIEW_KIND_LABEL = {
    "http_call": "Model call", "tool_call": "Tool call", "model": "Model call",
    "human_decision": "Human decision", "decision_record": "Decision record",
    "context": "Input context", "identity": "Who and what ran",
    "run_meta": "Run started", "run_end": "Run sealed",
    "policy_check": "Policy check", "injected": "Replaced response",
    "redaction": "Redaction", "fork": "Fork point",
    "hold": "Legal hold placed", "hold_release": "Legal hold released",
    "repair": "Repair", "nondet": "Clock or random value"}
# How a step's recorded data is split for a reader, as the inspector's step
# tabs split it (app.js STEP_PAYLOAD): label and data key.
_VIEW_PAYLOAD = {"http_call": (("Request", "request"), ("Response", "response")),
                 "tool_call": (("Arguments", "args"), ("Result", "result"))}
# Bidirectional and invisible controls, and every C0 and C1 control but tab
# and newline: shown as a visible token, so recorded text can neither reorder
# nor hide what the page shows.
_VIEW_HIDDEN = re.compile("[" + "".join(
    f"{chr(low)}-{chr(high)}" for low, high in (
        (0x00, 0x08), (0x0B, 0x1F), (0x7F, 0x9F), (0x061C, 0x061C),
        (0x200B, 0x200F), (0x202A, 0x202E), (0x2066, 0x2069),
        (0xFEFF, 0xFEFF))) + "]")
# The brackets a hidden character's token is shown between.
_VIEW_TOKEN = (chr(0x27E8), chr(0x27E9))
_VIEW_STYLE = (
    ":root{color-scheme:light dark;--fg:#1d2228;--bg:#fbfaf7;--muted:#5b6470;"
    "--line:#c9ced6;--box:#f1efe9}"
    "@media (prefers-color-scheme:dark){:root{--fg:#e6e3dc;--bg:#15181c;"
    "--muted:#a3abb6;--line:#3a4049;--box:#1e2227}}"
    "body{margin:0;background:var(--bg);color:var(--fg);"
    "font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif}"
    "header.notice{position:sticky;top:0;z-index:1;background:var(--bg);"
    "border-bottom:3px double var(--fg);padding:8px 16px;font-weight:600}"
    "main{max-width:1100px;margin:0 auto;padding:0 16px 48px}"
    "table{border-collapse:collapse;width:100%;margin:8px 0 16px}"
    "th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;"
    "vertical-align:top;overflow-wrap:anywhere}"
    "tr.gap td{border:2px solid var(--fg)}"
    ".gap-mark{font-weight:700;border:1px solid var(--fg);padding:0 4px}"
    "pre.recorded{background:var(--box);border:1px solid var(--line);"
    "padding:8px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:40em;"
    "overflow:auto;font:13px/1.4 ui-monospace,Consolas,monospace}"
    ".label,small{color:var(--muted)}"
    "details{border-top:1px solid var(--line);padding:4px 0}"
    "@media print{header.notice{position:static}"
    "pre.recorded{max-height:none}}")


def _view_str(value) -> str:
    """A recorded value as text: a string as it is, anything else as JSON."""
    return value if isinstance(value, str) else json.dumps(
        value, ensure_ascii=False)


def _view_text(value) -> str:
    """The one escape every value on the page passes through: lone
    surrogates as \\uXXXX text, bidirectional, invisible and control
    characters as a visible token, then HTML-escaped with quotes. A value
    past VIEW_VALUE_LIMIT code points is cut there and says so in plain
    text, so no recorded value outruns the limit wherever it is shown;
    `_view_cut` names the step and file for a value whose place it knows."""
    text = _view_str(value)
    if len(text) > VIEW_VALUE_LIMIT:
        text = (f"{text[:VIEW_VALUE_LIMIT]} - Shortened in this view; the "
                f"full value is in data/runs/.")
    text = _SURROGATES.sub(lambda m: f"\\u{ord(m.group()):04x}", text)
    text = _VIEW_HIDDEN.sub(lambda m: f"{_VIEW_TOKEN[0]}U+{ord(m.group()):04X}"
                                      f"{_VIEW_TOKEN[1]}", text)
    return html.escape(text, quote=True)


def _view_cut(text: str, where: str) -> str:
    """`text` escaped; past VIEW_VALUE_LIMIT code points, cut there and
    followed by where the whole value is."""
    if len(text) <= VIEW_VALUE_LIMIT:
        return _view_text(text)
    return (f"{_view_text(text[:VIEW_VALUE_LIMIT])}<small> Shortened in this "
            f"view; the full value is {_view_text(where)}.</small>")


def _view_block(value, where: str) -> str:
    """A recorded value in its bordered block, as the JSON the bundle holds."""
    return (f'<pre class="recorded">'
            f'{_view_cut(json.dumps(value, ensure_ascii=False, indent=1), where)}'
            f'</pre>')


def _view_files(directory: Path, pattern: str) -> list:
    """The files `pattern` names in `directory`, ordered by name - the same
    order on every host."""
    return sorted((p for p in directory.glob(pattern) if p.is_file()),
                  key=lambda p: p.name)


def _view_load(path: Path):
    """(value, None), or (None, why) for a file that is not JSON this
    verifier reads."""
    try:
        return _loads(path.read_bytes().decode("utf-8", "replace")), None
    except ValueError as exc:
        return None, str(exc)


def _view_entries(bundle) -> list:
    entries = bundle.get("entries") if isinstance(bundle, dict) else None
    return entries if isinstance(entries, list) else []


def _view_data(entry) -> dict:
    data = entry.get("data") if isinstance(entry, dict) else None
    return data if isinstance(data, dict) else {}


def _view_gap(entry):
    """The gap a marker declares, or None."""
    if not (isinstance(entry, dict) and entry.get("kind") == "marker"):
        return None
    gap = _view_data(entry).get("gap")
    return gap if isinstance(gap, dict) else None


def _view_kind(entry) -> str:
    """What a step is, in the inspector's words (app.js kindLabel)."""
    if not isinstance(entry, dict):
        return "An entry that is not a JSON object"
    gap = _view_gap(entry)
    if gap is not None:
        return f"Capture gap: {_view_str(gap.get('cause'))}"
    kind = entry.get("kind")
    if kind == "marker":
        return "Out-of-band note"
    label = VIEW_KIND_LABEL.get(kind) if isinstance(kind, str) else None
    return label or _view_str(kind)


def _view_run_id(name: str, bundle) -> str:
    if isinstance(bundle, dict) and "run_id" in bundle:
        return _view_str(bundle["run_id"])
    return name[:-len(".bundle.json")]


def _view_first(entries, kind: str) -> dict:
    """The data of the run's first entry of `kind`, or {}."""
    return next((_view_data(e) for e in entries
                 if isinstance(e, dict) and e.get("kind") == kind), {})


# The identity rule every BitExact reader reports a run's identity by
# (bitexact.identity.fold), restated here because this file imports nothing
# of the package. tests/test_identity_readers.py holds the two equal.
_VIEW_IDENTITY_FIELDS = ("principal", "agent_id", "delegation_from", "scope",
                         "policy_version", "prompt_pack_version",
                         "model_version", "workflow", "workflow_version",
                         "environment", "code", "workflow_instance",
                         "on_behalf_of", "on_behalf_of_type", "authority_ref",
                         "interaction_mode")
_VIEW_IDENTITY_ENUMS = {
    "on_behalf_of_type": ("human", "organization", "service", "agent"),
    "interaction_mode": ("interactive", "autonomous")}
# The party acted for, its type and its authority: one statement, replaced
# together.
_VIEW_PARTY = ("on_behalf_of", "on_behalf_of_type", "authority_ref")
_VIEW_SOURCE_BLOCK = "aer_source"
_VIEW_REPORTED_BY = "reported_by"
_VIEW_DIGEST = "workflow_digest"
_VIEW_SESSION = {"interactive": "yes — interactive",
                 "autonomous": "no — autonomous"}


def _view_identity_order(key: str):
    return (_VIEW_IDENTITY_FIELDS.index(key) if key in _VIEW_IDENTITY_FIELDS
            else len(_VIEW_IDENTITY_FIELDS), key)


def _view_identity_refused(key: str, value) -> bool:
    """Whether the write rule refuses `value` for the identity field `key`."""
    if key == "scope":
        return not (isinstance(value, list)
                    and all(isinstance(s, str) for s in value))
    return (not isinstance(value, str)
            or (key in ("on_behalf_of", "authority_ref") and not value)
            or (key in _VIEW_IDENTITY_ENUMS
                and value not in _VIEW_IDENTITY_ENUMS[key]))


def _view_identity_fold(entries) -> dict:
    """The run's identity, by the rule every reader uses: `opened` (what the
    first identity entry said), `current` (each field from its latest
    statement; a new party replaces its type and authority; a redacted or
    refused latest statement reads as absent, never as an older value),
    `changes` ({step, field, before, after} for each field changed after
    opening), `withheld` (redacted) and `invalid` (refused) fields. The
    recorder's source block and the adapter's reporter are no part of it.
    Total on any entry shape."""
    opened = None
    current: dict = {}
    hidden: set = set()
    invalid: set = set()
    changes: list = []
    for entry in entries:
        if not (isinstance(entry, dict) and entry.get("kind") == "identity"
                and isinstance(entry.get("data"), dict)):
            continue
        own = (_VIEW_SOURCE_BLOCK, _VIEW_REPORTED_BY)
        data = {k: v for k, v in entry["data"].items() if k not in own}
        redacted = entry.get("redacted")
        redacted = ({r for r in redacted if isinstance(r, str)
                     and r not in own
                     and not r.startswith(tuple(o + "." for o in own))}
                    if isinstance(redacted, list) else set())
        stated, refused = {}, set()
        for key, value in data.items():
            if key in redacted or key == _VIEW_DIGEST:
                continue
            if key not in _VIEW_IDENTITY_FIELDS:
                stated[key] = value
            elif value is not None:
                if _view_identity_refused(key, value):
                    refused.add(key)
                else:
                    stated[key] = value
        # A party held back - redacted, or kept as a digest only - still
        # stands beside its type and authority, and still replaces them.
        capture = entry.get("capture")
        fields = capture.get("fields") if isinstance(capture, dict) else None
        party = fields.get("on_behalf_of") if isinstance(fields, dict) else None
        party_held = ("on_behalf_of" in redacted
                      or (isinstance(party, dict)
                          and party.get("mode") == "hash-only"))
        if "on_behalf_of" not in stated and not party_held:
            for key in _VIEW_PARTY[1:]:
                if key in stated:
                    del stated[key]
                    refused.add(key)
        if _VIEW_DIGEST in data and _VIEW_DIGEST not in redacted:
            stated[_VIEW_DIGEST] = data[_VIEW_DIGEST]
        after = dict(current)
        if "on_behalf_of" in data or party_held:
            for key in _VIEW_PARTY:
                after.pop(key, None)
                hidden.discard(key)
                invalid.discard(key)
        after.update(stated)
        hidden -= set(stated)
        invalid -= set(stated)
        for key in refused:
            after.pop(key, None)
            hidden.discard(key)
            invalid.add(key)
        for key in redacted:
            after.pop(key, None)
            invalid.discard(key)
            hidden.add(key)
        if opened is None:
            opened = dict(stated)
        else:
            changes += [{"step": entry.get("step"), "field": key,
                         "before": current.get(key), "after": after.get(key)}
                        for key in sorted(set(current) | set(after),
                                          key=_view_identity_order)
                        if current.get(key) != after.get(key)]
        current = after
    return {"opened": opened or {}, "current": current, "changes": changes,
            "withheld": sorted(hidden, key=_view_identity_order),
            "invalid": sorted(invalid, key=_view_identity_order)}


def _view_gap_causes(entries) -> str:
    """The capture gaps a run declares, by cause - each marker's, and each
    capture field's (the gaps _gaps counts)."""
    causes: dict = {}
    for e in entries:
        gap = _view_gap(e)
        named = [gap.get("cause")] if gap is not None else []
        capture = e.get("capture") if isinstance(e, dict) else None
        fields = capture.get("fields") if isinstance(capture, dict) else None
        named += [d["cause"] for d in (fields.values() if isinstance(
            fields, dict) else ()) if isinstance(d, dict) and "cause" in d]
        for cause in map(_view_str, named):
            causes[cause] = causes.get(cause, 0) + 1
    return ", ".join(f"{c} {n}" for c, n in sorted(causes.items())) or "none"


def _view_table(heads, rows) -> list:
    return ["<table><thead><tr>" + "".join(f"<th>{h}</th>" for h in heads)
            + "</tr></thead><tbody>", *rows, "</tbody></table>"]


def _view_row(cells, cls: str = "") -> str:
    return (f'<tr class="{cls}">' if cls else "<tr>") + "".join(
        f"<td>{c}</td>" for c in cells) + "</tr>"


def _view_summary(runs, data: Path) -> list:
    """The pack at a glance: a row per run, its forks, the executions
    refused at open, and the other ledgers it carries - counted as
    recorded."""
    out = ["<section>", "<h2>This pack</h2>"]
    rows, forks = [], []
    for i, (name, bundle, _) in enumerate(runs, 1):
        entries = _view_entries(bundle)
        ident = _view_identity_fold(entries)["current"]
        carried =[len(bundle[k]) if isinstance(bundle, dict)
                   and isinstance(bundle.get(k), list) else 0
                   for k in ("checkpoints", "anchors")]
        ended = any(isinstance(e, dict) and e.get("kind") == "run_end"
                    for e in entries)
        rows.append(_view_row([
            f'<a href="#run-{i}">{_view_text(_view_run_id(name, bundle))}</a>',
            str(len(entries)), "yes" if ended else "no",
            *(_view_text(ident.get(k, "-"))
              for k in ("workflow", "workflow_version", "environment")),
            _view_text(_view_gap_causes(entries)), *map(str, carried)]))
        for e in entries:
            if isinstance(e, dict) and e.get("kind") == "fork":
                fork = _view_data(e)
                forks.append(
                    f"<li><code>{_view_text(_view_run_id(name, bundle))}"
                    f"</code> forked from <code>"
                    f"{_view_text(fork.get('source_run'))}</code> at step "
                    f"{_view_text(fork.get('at_step'))} (as its fork entry "
                    f"records)</li>")
    out += _view_table(["Run", "Entries", "Has a run_end entry", "Workflow",
                        "Version", "Environment", "Declared capture gaps",
                        "Checkpoints carried", "Anchors carried"], rows)
    out.append("<p>Counted from the bundles as recorded. Checkpoints and "
               "anchors are carried here; the verifier checks them.</p>")
    if forks:
        out += ["<h3>Forks</h3>", "<ul>", *forks, "</ul>"]
    out += _view_refusals(data) + _view_ledgers(data)
    return out + ["</section>"]


def _view_refusals(data: Path) -> list:
    """Executions refused at open (data/refusals/*.jsonl), by run id and
    cause."""
    rows = []
    for path in _view_files(data / "refusals", "*.jsonl"):
        causes: dict = {}
        for line in path.read_bytes().decode("utf-8", "replace").splitlines():
            if not line.strip():
                continue
            try:
                event = _loads(line)
            except ValueError:
                cause = "(a line this page cannot read)"
            else:
                refused = event.get("data") if isinstance(event, dict) else None
                cause = (_view_str(refused.get("cause"))
                         if isinstance(refused, dict)
                         else "(an event that is not a refusal)")
            causes[cause] = causes.get(cause, 0) + 1
        rows += [_view_row([_view_text(path.stem), _view_text(c), str(n)])
                 for c, n in sorted(causes.items())]
    if not rows:
        return []
    return ["<h3>Executions refused at open</h3>",
            *_view_table(["Run id", "Cause", "Executions"], rows)]


def _view_ledgers(data: Path) -> list:
    """The other hash-chained ledgers the pack carries, by name and event
    count as the pack holds them."""
    rows = []
    for path in (p for p in _ledger_files(data)
                 if p.parent != data / "refusals"):
        if path.suffix == ".jsonl":
            count = str(sum(1 for line in path.read_bytes().decode(
                "utf-8", "replace").splitlines() if line.strip()))
        else:
            doc, _ = _view_load(path)
            events = doc.get("events") if isinstance(doc, dict) else None
            count = str(len(events)) if isinstance(events, list) else "-"
        rows.append(_view_row([
            f"<code>data/{_view_text(path.relative_to(data).as_posix())}</code>",
            count]))
    if not rows:
        return []
    return ["<h3>Ledgers</h3>", *_view_table(["Ledger", "Events"], rows)]


def _view_identity(entries, name: str) -> list:
    """The run's identity as every reader reports it (_view_identity_fold):
    each field from its latest statement, for whom it acted and whether a
    person was in the session, and, after a rebinding, what it opened with
    and each change."""
    out = ["<h3>Who and what ran</h3>"]
    folded = _view_identity_fold(entries)
    if not any(folded.values()):
        return out + ["<p>The run records no identity fields.</p>"]
    ident = folded["current"]

    def shown(value, field: str) -> str:
        if value is None:
            return "not stated"
        return "<code>" + _view_cut(_view_str(value), f"the identity entry, "
                                    f"{field}, in data/runs/{name}") + "</code>"

    out.append("<p>The run's identity, each field as its latest identity "
               "entry states it: the deployer's statement, recorded as "
               "stated; no key binds it to a person.</p>")
    facts = []
    if ident.get("on_behalf_of") is not None:
        kind = ident.get("on_behalf_of_type")
        facts.append(f"<li>On behalf of: "
                     f"{shown(ident['on_behalf_of'], 'on_behalf_of')}"
                     + (f" ({_view_text(kind)})" if kind is not None else "")
                     + " - the deployer's statement</li>")
    mode = ident.get("interaction_mode")
    if mode is not None:
        facts.append(f"<li>Person in session: "
                     f"{_view_text(_VIEW_SESSION[mode])} - the deployer's "
                     f"statement, not a finding on solely automated "
                     f"decisions</li>")
    if facts:
        out += ["<ul>", *facts, "</ul>"]
    if ident:
        out += _view_table(["Field", "Value"], [
            _view_row([_view_text(k), shown(v, k)]) for k, v in ident.items()])
    if folded["withheld"]:
        out.append("<p>Withheld - redacted: " + ", ".join(
            f"<code>{_view_text(k)}</code>" for k in folded["withheld"])
            + ".</p>")
    if folded["invalid"]:
        out.append("<p>Not read: " + ", ".join(
            f"<code>{_view_text(k)}</code>" for k in folded["invalid"])
            + " - the deployer's statement of each is not an identity "
              "value the write rule accepts, so it is not read as the run's "
              "identity.</p>")
    if folded["changes"]:
        out.append("<p>Identity at open: " + ("; ".join(
            f"{_view_text(k)} {shown(v, k)}"
            for k, v in folded["opened"].items()) or "nothing stated")
            + " (the deployer's statement).</p>")
        out += ["<ul>", *(
            f"<li>Changed at step {_view_text(c['step'])}: "
            f"{_view_text(c['field'])} from {shown(c['before'], c['field'])} "
            f"to {shown(c['after'], c['field'])} (both the deployer's "
            f"statements)</li>" for c in folded["changes"]), "</ul>"]
    return out


def _view_capture(entries, policies: dict, name: str) -> list:
    """The capture controls of a run: the policy it opened under and the
    document of it the pack carries, each field a control touched with its
    declared outcome, the counts and the scope sentence a verdict prints."""
    out = ["<h3>Capture controls</h3>"]
    label = _view_first(entries, "run_meta").get("capture_policy")
    if label is None:
        out.append("<p>The run names no capture policy.</p>")
    elif label == "off":
        out.append("<p>The run opened with no capture policy in force "
                   "(capture_policy: off).</p>")
    else:
        file = (f"capture-policy-{label.replace(':', '-')}.json"
                if isinstance(label, str) else None)
        out.append(f"<p>The run opened under capture policy <code>"
                   f"{_view_text(label)}</code>. " + (
                       f"The pack carries the producer's file "
                       f"<code>data/{_view_text(file)}</code> as its "
                       f"document, shown under Capture policies below; the "
                       f"verifier does not check it against the run."
                       if file in policies else
                       "This pack carries no copy of its document.") + "</p>")
    rows, counts = [], {}
    for e in entries:
        _capture_counts(e, counts)
        capture = e.get("capture") if isinstance(e, dict) else None
        fields = capture.get("fields") if isinstance(capture, dict) else None
        for path, decl in (fields.items() if isinstance(fields, dict) else ()):
            step = _view_str(e.get("step"))
            rows.append(_view_row([
                _view_text(step), f"<code>{_view_text(path)}</code>",
                _view_text(decl.get("mode") if isinstance(decl, dict)
                           else None),
                "<code>" + _view_cut(_view_str(decl), f"step {step}, capture "
                                     f"{path}, in data/runs/{name}")
                + "</code>"]))
    if rows:
        out.append("<p>Each field a capture control touched: its outcome and "
                   "its declaration, as the entry records them.</p>")
        out += _view_table(["Step", "Field", "Outcome",
                            "Declaration (as recorded)"], rows)
    else:
        out.append("<p>No entry of this run declares a capture outcome.</p>")
    note = _capture_note(counts)
    if note:
        out.append(f"<p>Counted from the declarations: "
                   f"{_view_text(note[2:])}.</p>")
        scope = _capture_scope_text(counts)
        if scope:
            out.append(f"<p>{_view_text(scope)}</p>")
    return out


# The display name of each adapter that writes `data.reported_by` on the
# asserted entries it reports. A reporter not listed here is shown by the
# name it recorded. The pack's workpaper and the viewer read this table.
REPORTERS = {
    "auditant": "Auditant",
    "claude-agent-sdk": "Claude Agent SDK",
    "openai-agents": "OpenAI Agents SDK",
    "adk": "Google ADK",
    "otel": "OpenTelemetry",
    "langchain": "LangChain",
    "llamaindex": "LlamaIndex",
    "vapi": "Vapi",
}


def _view_causal(entries):
    """(the entries' positions in causal order, the positions caught in a
    cycle), or None for a run no source wrote into, whose chain order is
    the order it happened in. bitexact.causal.causal_steps, restated here
    because this file imports nothing of the package (a test holds the two
    equal): a topological sort over each source's own seq and the
    `caused_by` links in each entry's source block, ready entries taken by
    their clock (an entry with none sorts with the entry before it) and
    then by chain position; a cycle, which only a source misstating its
    causes can make, leaves its entries to the end, in chain order."""
    blocks = []
    for e in entries:
        block = _view_data(e).get(_VIEW_SOURCE_BLOCK)
        blocks.append(block if isinstance(block, dict) else None)
    if not any(b is not None and isinstance(b.get("source_id"), str)
               for b in blocks):
        return None
    n = len(blocks)
    keys, edges, indegree = [], [[] for _ in range(n)], [0] * n
    by_id, per_source, local, last = {}, {}, [], (0, 0)
    for i, block in enumerate(blocks):
        hlc = block.get("hlc") if block else None
        stamp = (tuple(hlc) if isinstance(hlc, list) and len(hlc) == 2
                 and all(type(v) is int for v in hlc) else None)
        if stamp is not None:
            last = stamp
        keys.append((stamp or last, i))
        source = block.get("source_id") if block else None
        if isinstance(source, str) and type(block.get("seq")) is int:
            per_source.setdefault(source, []).append((block["seq"], i))
            if isinstance(block.get("id"), str):
                by_id.setdefault(block["id"], i)
        else:
            local.append(i)

    def edge(a: int, b: int) -> None:
        edges[a].append(b)
        indegree[b] += 1

    for chain in [sorted(s) for s in per_source.values()] + [
            [(0, i) for i in local]]:
        for (_, a), (_, b) in zip(chain, chain[1:]):
            edge(a, b)
    for i, block in enumerate(blocks):
        parents = block.get("caused_by") if block else None
        for parent in parents if isinstance(parents, list) else ():
            j = by_id.get(parent) if isinstance(parent, str) else None
            if j is not None and j != i:
                edge(j, i)
    ready = [keys[i] for i in range(n) if indegree[i] == 0]
    heapq.heapify(ready)
    order = []
    while ready:
        _, i = heapq.heappop(ready)
        order.append(i)
        for j in edges[i]:
            indegree[j] -= 1
            if indegree[j] == 0:
                heapq.heappush(ready, keys[j])
    cycle = sorted(set(range(n)) - set(order))
    return order + cycle, cycle


def _view_step_of(entry):
    return entry.get("step") if isinstance(entry, dict) else None


def _view_order(entries, causal, recorded) -> list:
    """What the step table's order is, for a run recorded from more than
    one host (_view_causal), and the steps a cycle left to the end; and
    whether the bundle's own `causal_order` field gives that order."""
    order, cycle = causal
    out = ["<p>Listed in causal order: this run was recorded from more than "
           "one host. Each step comes after the steps its own source sent "
           "before it and the steps it names as its cause, ties broken by "
           "its clock and then by its place in the chain - all read from "
           "the source blocks inside each entry's hash, which the hosts "
           "assert. The step numbers are the chain's; the bundle's entries, "
           "and Steps in full below, stay in chain order.</p>"]
    looped = [_view_step_of(entries[i]) for i in cycle]
    if looped:
        out.append("<p>Steps " + ", ".join(_view_text(s) for s in looped)
                   + " are caught in a cycle of causes - which only a source "
                     "misstating its causes can make - and are listed last, "
                     "in chain order.</p>")
    derived = {"steps": [_view_step_of(entries[i]) for i in order],
               "cycle": looped}
    if recorded != derived:
        out.append("<p>The bundle's own causal_order field does not give "
                   "this order - it is informational, outside the entries' "
                   "hashes; this page shows the order the entries give.</p>")
    return out


def _view_steps(entries, name: str, recorded=None) -> list:
    """The step table: one row per step, in causal order for a run
    recorded from more than one host (_view_order says so), else in chain
    order. `recorded` is the bundle's own `causal_order` field."""
    lead = []
    causal = _view_causal(entries)
    if causal is not None:
        lead = _view_order(entries, causal, recorded)
        entries = [entries[i] for i in causal[0]]
    rows = []
    for e in entries:
        entry = e if isinstance(e, dict) else {}
        data = _view_data(e)
        gap = _view_gap(e)
        step = _view_str(entry.get("step", "-"))

        def cell(value, path):
            return _view_cut(_view_str(value),
                             f"step {step}, {path}, in data/runs/{name}")
        what = (f'<span class="gap-mark">Capture gap</span>: '
                f'{cell(gap.get("cause"), "data.gap.cause")}'
                if gap is not None else cell(_view_kind(e), "kind"))
        if gap is None and entry.get("kind") == "policy_check" \
                and "outcome" in data:
            outcome = data["outcome"]
            what += ": " + (_view_text("held for human approval")
                            if outcome == "held"
                            else cell(outcome, "data.outcome"))
        prov = cell(entry.get("prov", "-"), "prov")
        reporter = data.get("reported_by")
        if isinstance(reporter, str):
            prov += (", reported by "
                     f"{cell(REPORTERS.get(reporter, reporter), 'data.reported_by')}")
        who = data.get("actor")
        who = (cell(who, "data.actor") if isinstance(who, str)
               else _view_text("-"))
        # An act the recorder wrote for a peer names the certificate that
        # asked for it, inside the entry's hash.
        peer = data.get("submitted_by")
        if isinstance(peer, str):
            who += (f", submitted by certificate "
                    f"{cell(peer, 'data.submitted_by')}")
        # A person the recorder verified through single sign-on, named by
        # the issuer's subject (bundle-spec.md, Verified identity).
        for field, said in (("verified_identity", "verified"),
                            ("requested_identity", "requester verified")):
            block = data.get(field)
            if isinstance(block, dict) and isinstance(
                    block.get("subject"), str) and isinstance(
                    block.get("issuer"), str):
                who += (f", {said} as "
                        f"{cell(block['subject'], f'data.{field}.subject')}"
                        f" at {cell(block['issuer'], f'data.{field}.issuer')}")
        digest = entry.get("hash")
        rows.append(_view_row([
            _view_text(entry.get("step", "-")), cell(entry.get("ts", "-"), "ts"),
            what, prov, who,
            _view_text("-" if digest is None else _view_str(digest)[:12])],
            "gap" if gap is not None else ""))
    return ["<h3>Steps</h3>", *lead, *_view_table(
        ["Step", "Time (as recorded)", "What", "Provenance", "Who",
         "Entry hash"], rows)]


def _view_held(decl) -> str:
    """What a field's capture declaration says the bundle holds of it, in
    the words the step shows beside its data."""
    mode = decl.get("mode") if isinstance(decl, dict) else None
    if mode == "hash-only":
        return "hash only - value never held"
    if mode == "scrub":
        found = decl.get("found")
        return "scrubbed before capture: " + (
            ", ".join(sorted(str(k) for k in found))
            if isinstance(found, dict) and found else "-")
    if mode == "unscanned":
        return "kept, not scanned"
    if mode == "scrubbed-upstream":
        return "claimed cleaned upstream (asserted, not checked)"
    cause = decl.get("cause") if isinstance(decl, dict) else None
    return "not held: " + _view_str(mode) + (
        "" if cause is None else f" ({_view_str(cause)})")


def _view_step(entry, name: str) -> str:
    """One step's recorded content, split the way the inspector's step tabs
    split it, and the fields withheld from it."""
    if not isinstance(entry, dict):
        return (f"<details><summary>{_view_text(_view_kind(entry))}</summary>"
                f"{_view_block(entry, f'data/runs/{name}')}</details>")
    step = _view_str(entry.get("step"))
    parts = [f"<details><summary>Step {_view_text(step)} - "
             f"{_view_text(_view_kind(entry))}</summary>"]
    marks = entry.get("redacted")
    if marks:
        parts.append("<ul>" + "".join(
            f"<li><code>{_view_text(p)}</code>: withheld - redacted</li>"
            for p in (marks if isinstance(marks, list) else [marks]))
            + "</ul>")
    capture = entry.get("capture")
    fields = capture.get("fields") if isinstance(capture, dict) else None
    if isinstance(fields, dict) and fields:
        parts.append("<ul>" + "".join(
            f"<li><code>{_view_text(p)}</code>: {_view_text(_view_held(d))}"
            f"</li>" for p, d in fields.items()) + "</ul>")
    parts.append('<p class="label">Recorded content (as the bundle holds '
                 'it)</p>')
    data = entry.get("data")
    if isinstance(data, dict):
        kind = entry.get("kind")
        split = _VIEW_PAYLOAD.get(kind, ()) if isinstance(kind, str) else ()
        rest = dict(data)
        for label, key in split:
            if key in rest:
                parts.append(f'<p class="label">{label}</p>' + _view_block(
                    rest.pop(key), f"step {step}, {key}, in data/runs/{name}"))
        if rest or not split:
            parts.append('<p class="label">Recorded data</p>' + _view_block(
                rest, f"step {step}, data, in data/runs/{name}"))
    else:
        parts.append(_view_block(data, f"step {step}, data, in data/runs/"
                                       f"{name}"))
    return "".join(parts) + "</details>"


def _view_run(i: int, name: str, bundle, problem, policies: dict,
              budget: list) -> list:
    out = [f'<section id="run-{i}">', f"<h2>Run {i}</h2>",
           f"<p>Run id <code>{_view_text(_view_run_id(name, bundle))}</code>, "
           f"file <code>data/runs/{_view_text(name)}</code></p>"]
    if problem is not None or not isinstance(bundle, dict):
        return out + [f"<p>This file is not a bundle this page can read: "
                      f"{_view_text(problem or 'it is not a JSON object')}"
                      f".</p>", "</section>"]
    entries = _view_entries(bundle)
    out += _view_identity(entries, name)
    out += _view_capture(entries, policies, name)
    out += _view_steps(entries, name, bundle.get("causal_order"))
    out.append("<h3>Steps in full</h3>")
    # The page's size is counted in UTF-8 bytes, every section of it.
    budget[0] -= sum(len(p.encode("utf-8")) for p in out)
    for entry in entries:
        if budget[0] <= 0:
            step = entry.get("step") if isinstance(entry, dict) else None
            out.append(f"<p>Step data is not shown from step "
                       f"{_view_text(step)} of this run on: this page "
                       f"reached its size limit. The bundle holds it.</p>")
            break
        part = _view_step(entry, name)
        budget[0] -= len(part.encode("utf-8"))
        out.append(part)
    return out + ["</section>"]


def _view_policies(policies: dict) -> list:
    out = ["<section>", "<h2>Capture policies</h2>"]
    if not policies:
        out.append("<p>This pack carries no capture policy document.</p>")
    for name, path in policies.items():
        value, problem = _view_load(path)
        out.append(f"<p>File <code>data/{_view_text(name)}</code>, the "
                   f"producer's document as the pack holds it:</p>")
        if problem is None:
            out.append(_view_block(value, f"data/{name}"))
        else:
            out.append(f"<p>It is not JSON this page can read "
                       f"({_view_text(problem)}); its text:</p>"
                       f'<pre class="recorded">'
                       f'{_view_cut(path.read_bytes().decode("utf-8", "replace"), f"data/{name}")}'
                       f"</pre>")
    return out + ["</section>"]


def render_view(bag, identifier) -> bytes:
    """The reading view of a bag: a script-free page showing the runs it
    holds as readable steps, from the bag's own files only - its run
    bundles, refusals, ledgers and capture policies - and `identifier`,
    bag-info's External-Identifier. Pure and total: the same bag gives the
    same bytes on any host, which is what lets a verifier render it again
    and refuse a page that differs."""
    data = Path(bag) / "data"
    runs = [(p.name, *_view_load(p))
            for p in _view_files(data / "runs", "*.bundle.json")]
    policies = {p.name: p for p in _view_files(data, "capture-policy-*.json")}
    shown = _view_text("-" if identifier is None else identifier)
    body = [f'<header class="notice"><p>{_view_text(VIEW_NOTICE)}</p>'
            f"</header>", "<main>", "<h1>Reading view</h1>",
            f"<p>Pack <code>{shown}</code></p>"]
    body += _view_summary(runs, data)
    budget = [VIEW_PAGE_LIMIT - sum(len(p.encode("utf-8")) for p in body)]
    for i, (name, bundle, problem) in enumerate(runs, 1):
        body += _view_run(i, name, bundle, problem, policies, budget)
    body += _view_policies(policies)
    style = base64.b64encode(hashlib.sha256(
        _VIEW_STYLE.encode("utf-8")).digest()).decode("ascii")
    head = [
        "<!doctype html>", '<html lang="en"><head>', '<meta charset="utf-8">',
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src "
        f"'none'; script-src 'none'; style-src 'sha256-{style}'; img-src "
        f"'none'; font-src 'none'; connect-src 'none'; media-src 'none'; "
        f"object-src 'none'; frame-src 'none'; base-uri 'none'; form-action "
        f"'none'\">",
        '<meta name="referrer" content="no-referrer">',
        f'<meta name="aer-view" content="{VIEW_FORMAT}">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Reading view - {shown}</title>",
        f"<style>{_VIEW_STYLE}</style>", "</head><body>"]
    return ("\n".join(head + body + ["</main>", "</body></html>"])
            + "\n").encode("utf-8")


def _bag_identifier(bag: Path):
    """bag-info.txt's External-Identifier, or None."""
    info = bag / "bag-info.txt"
    text = (info.read_bytes().decode("utf-8", "replace")
            if info.is_file() else "")
    return next((line.partition(":")[2].strip() for line in text.splitlines()
                 if line.startswith("External-Identifier:")), None)


def _with_view(bag: Path, verdict):
    """A verified bag's reading view, rendered again from the bag and
    compared byte for byte. A readable page beside signed data is a forgery
    channel unless it is bound to what was verified, so a page that differs
    fails the bag. A bag with no page has nothing to compare."""
    view = bag / "data" / VIEW_FILE
    if verdict[0] and view.is_file() and view.read_bytes() != render_view(
            bag, _bag_identifier(bag)):
        return False, VIEW_MISMATCH, None
    return verdict


def _view_note(bag) -> str:
    """The OK line's clause on a verified bag's reading view: present means
    it was compared and matched (_with_view)."""
    return (", view matches the bundles"
            if (Path(bag) / "data" / VIEW_FILE).is_file() else "")


UNCHECKED = ("not checked against the runs (the producer's own statements, "
             "sealed against later change only): ")


def _unchecked_out(bag) -> None:
    """After a verified bag's OK line, every payload file the verdict does
    not stand behind, by path: each file under data/ that is not a run
    bundle, a ledger or refusal (_ledger_files), the signed ledger heads
    where they are checked, the provenance graph or its attestation on a
    provenance bag, or the reading view (_with_view). The
    bag's checksums prove only that these did not change after bagging."""
    data = Path(bag) / "data"
    walked = {*(data / "runs").glob("*.bundle.json"), *_ledger_files(data),
              data / VIEW_FILE}
    if ledger_heads(bag) is not None:
        walked.add(data / HEADS_FILE)       # checked by _heads_problem
    if (data / "provenance-graph.json").is_file():
        walked |= {data / "provenance-graph.json",
                   data / "attestations" / "provenance.dsse.json"}
    rest = sorted(p.relative_to(data.parent).as_posix()
                  for p in data.rglob("*") if p.is_file() and p not in walked)
    if rest:
        _out(UNCHECKED + ", ".join(rest))


def _check_listing(bag, graph, verified):
    """What the bag SAYS about itself must be what its runs prove: bag-info's
    External-Identifier is the root, each node's role follows from its own
    fork entry, and the edge list is exactly the fork relationships the
    bundles commit to - no more, no fewer."""
    root = graph.get("root")
    info = (bag / "bag-info.txt").read_text(encoding="utf-8")
    declared = next((line.partition(":")[2].strip() for line in info.splitlines()
                     if line.startswith("External-Identifier:")), None)
    if declared != root:
        return (f"bag-info.txt External-Identifier {declared!r} is not the "
                f"graph root {root!r}")
    # Edges compare as canonical JSON, never as Python values: `true` in the
    # listing is not the fork entry's `1`.
    derived, forks = set(), set()
    for child, entries in verified.items():
        fork = next((e for e in entries if e.get("kind") == "fork"), None)
        data = (fork or {}).get("data") or {}
        if fork is not None and data.get("source_run") in verified:
            forks.add(child)
            derived.add(_canonical([child, data.get("source_run"),
                                    data.get("at_step"),
                                    data.get("source_prev_hash")]))
    for node in graph.get("nodes", []):
        rid = node.get("run_id")
        expected = "fork" if rid in forks else "original"
        if node.get("role") != expected:
            return (f"graph node {rid!r} declares role {node.get('role')!r} "
                    f"but its fork entry makes it {expected!r}")
    listed = set()
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            return "graph edges carry a non-object edge"
        listed.add(_canonical([edge.get("child"), edge.get("source_run"),
                               edge.get("at_step"),
                               edge.get("source_prev_hash")]))
    if listed != derived:
        return ("graph edges do not match the fork entries the bundles "
                "commit to")
    return None


def _check_edges(graph, verified):
    """Derive the fork tree from each run's *committed* fork entry - the
    authority, signed inside its own bundle - never from the graph's edge
    listing, which the bag cannot be trusted to state honestly. Each fork's
    committed prefix hash must match its source's verified entries, and the
    whole set must be one tree rooted at `root` with no cycles."""
    root = graph.get("root")
    if root not in verified:
        return f"graph root {root!r} not present in the bag"
    parents = {}
    for child in sorted(verified):
        fork = next((e for e in verified[child]
                     if e.get("kind") == "fork"), None)
        if fork is None:
            continue  # an original: the boundary of this bag
        data = fork.get("data") or {}
        source, at = data.get("source_run"), data.get("at_step")
        if source not in verified:
            continue  # source is outside this bag; child is a boundary root
        parent = verified[source]
        if not _is_int(at) or not 0 <= at <= len(parent):
            return (f"fork of {child!r} points at step {at} outside source "
                    f"{source!r}")
        expected = parent[at - 1]["hash"] if at else GENESIS
        if data.get("source_prev_hash") != expected:
            return (f"fork of {child!r} prefix hash does not match {source!r} "
                    f"at step {at} - the source was rewritten after forking")
        if not any(e.get("kind") == "run_end" for e in verified[child]):
            # A fork's at_step/injected_steps claim is only fulfilled once the
            # fork sealed - the recorder withholds run_end from a fork that did
            # not replay its full prefix or whose injection never fired. An
            # unsealed fork orphan (left by a swallowing caller like fork_matrix,
            # and recorder-signed by mid-run checkpoints) must not have its
            # lineage certified: it is an unfinished counterfactual whose
            # declared prefix may never have been replayed.
            return (f"fork {child!r} is not sealed - an unfinished fork cannot "
                    f"have its provenance certified")
        parents[child] = source

    # The root must be the bag's boundary - a source-less node. If the root
    # itself carries an in-bag fork source, lineage cycles through it, and the
    # walk below is blind to that: it stops the instant it reaches root and
    # never inspects root's own parent, so a self-fork (R<-R) or a mutual fork
    # (R<->S) would certify as "no cycles". Reject it here.
    if root in parents:
        return (f"graph root {root!r} is forked from in-bag run "
                f"{parents[root]!r} - a lineage cycle through the root")

    # Memoize nodes already proven to reach the root, so each run's ancestry is
    # walked once across the whole bag, not re-walked to the root every time. A
    # valid linear fork chain of D runs otherwise costs O(D^2) node visits and
    # stalls the verifier with no verdict. `seen` is a set so the per-walk cycle
    # test stays O(1). A cyclic node never enters `connected` - the walk returns
    # before the update - so memoization cannot hide a cycle.
    connected = {root}
    for rid in verified:
        seen, cur = set(), rid
        while cur not in connected:
            if cur in seen:
                return f"fork ancestry cycles at {cur!r}"
            seen.add(cur)
            if cur not in parents:
                return f"run {cur!r} is not connected to the root {root!r}"
            cur = parents[cur]
        # The walk reached a node already known to reach the root, so every node
        # on this path does too - remember them so later walks stop early.
        connected |= seen
    return None


def _verify_graph_attestation(envelope, graph, verified, trust):
    """Verify the signed graph attestation binds exactly this graph and pins
    each run's verified head. Returns an error string, or None on success."""
    payload, err = _dsse_accepted_payload(envelope, trust)
    if err:
        return f"attestation {err}"
    statement = _loads(payload)
    # Held as the run envelope is (_verify_envelope): an in-toto Statement,
    # its predicate exactly the graph, and one subject for each run.
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        return (f"attestation: unsupported statement type "
                f"{statement.get('_type')!r}")
    if statement.get("predicateType") != GRAPH_PREDICATE_TYPE:
        return f"attestation is not a provenance graph ({statement.get('predicateType')!r})"
    if not _same_json(statement.get("predicate"), graph):
        return "attestation does not sign the provenance graph in the bag"
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        subjects = []
    for subject in subjects:
        name = subject.get("name")
        entries = verified.get(name)
        if entries is None:
            return f"attestation names a run {name!r} not present in the bag"
        head = entries[-1]["hash"] if entries else None
        if subject.get("digest", {}).get("head") != head:
            return f"attestation head for {name!r} does not match its verified chain"
    if sorted(s.get("name") for s in subjects) != sorted(verified):
        return ("attestation subjects do not name each run in the bag "
                "exactly once")
    return None


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
                # A pin that is not a key can never match, so it would fail
                # closed - but silently, as a key mismatch. Refused here.
                if not (isinstance(k["public_key"], str)
                        and _HEX64.fullmatch(k["public_key"])):
                    return (f"trust file {name} entry's public_key is not an "
                            f"Ed25519 public key in hex")
                pq = k.get("pq_public_key")
                if pq is not None and not _pq_key_shape(pq):
                    return (f"trust file {name} entry's pq_public_key is not "
                            f"an ML-DSA-65 or ML-DSA-87 public key in hex")
    return None


def _pq_key_shape(value) -> bool:
    """Whether `value` is hex of an ML-DSA-65 or -87 public key's size."""
    return (isinstance(value, str) and _LOWER_HEX.fullmatch(value.lower())
            is not None and len(value) in {2 * s for s, _ in _PQ_ALGS.values()})


def _trusted_pq(trust_doc: dict) -> dict | None:
    """{Ed25519 key: [ML-DSA keys]} from a trust file's entries, or None."""
    out = {}
    for name in ("bundle_keys", "recorder_keys"):
        for k in trust_doc.get(name, ()):
            if k.get("pq_public_key"):
                out.setdefault(k["public_key"].lower(), []).append(
                    k["pq_public_key"].lower())
    return out or None


def _tsa_caveat(anchors, expect_tsa):
    """A note when a verified bundle carries RFC 3161 anchors but the TSA
    was not pinned - the timestamp's attested time is then unverified."""
    if expect_tsa is None and any(a.get("type") == "rfc3161"
                                  for a in anchors or []):
        return (" (RFC 3161 timestamps not pinned - pass --expect-tsa to "
                "trust the time)")
    return ""


def _date_passed(text) -> bool:
    """Whether a YYYY-MM-DD date is before today (UTC); an unparseable one
    is not judged."""
    import datetime as _dt
    try:
        expires = _dt.date.fromisoformat(str(text))
    except (TypeError, ValueError):
        return False
    return expires < _dt.datetime.now(_dt.timezone.utc).date()


def _short_key(public_hex: str) -> str:
    return (public_hex[:12] + "...") if public_hex else "?"


def license_provenance(container: dict, vendor_key_hex: str,
                       vendor_pq_hex: str | None = None) -> str:
    """Advisory, non-verdict report on the license a bundle was produced under.

    It NEVER affects the integrity verdict - the caller prints it only after a
    run has already verified. It walks the chain vendor -> licensed recorder
    key(s) -> the run's own recorder signature, so a leaked license (which names
    another deployment's recorder key) cannot be replayed, and a forged license
    would need the vendor's signing key. Returns one human-readable line.

    Total: license_cert is outside the integrity signature, so it is
    adversary-controlled even on a bundle that verifies. Any malformed shape
    becomes an advisory note here, never an exception - which, raised after the
    OK verdict was printed, would let this unsigned field flip the exit code.
    """
    try:
        return _license_provenance(container, vendor_key_hex, vendor_pq_hex)
    except Exception as exc:
        return ("license: unverifiable - malformed license material "
                f"({type(exc).__name__})")


def _license_provenance(container: dict, vendor_key_hex: str,
                        vendor_pq_hex: str | None = None) -> str:
    cert = container.get("license_cert")
    if not isinstance(cert, dict):
        return "license: none - no vendor license cert in this bundle"
    signature = cert.get("signature")
    body = {k: v for k, v in cert.items()
            if k != "signature" and k not in _PQ_FIELDS}
    if not (isinstance(signature, str)
            and _ed25519_verify(vendor_key_hex, _canonical(body), signature)):
        return "license: INVALID - the vendor signature does not verify"
    state, err = _pq_half(cert, "license", _canonical(body), vendor_key_hex)
    if err:
        return f"license: INVALID - the vendor's {err}"
    # Under a hybrid vendor pin the post-quantum half is required, as the
    # product requires it (license._pq_problem): absent is stripped or
    # forged, and unchecked proves nothing the pin asked for.
    if vendor_pq_hex and state == "absent":
        return ("license: INVALID - the vendor key is pinned as hybrid, but "
                "the license carries no post-quantum signature - stripped or "
                "forged")
    if vendor_pq_hex and state == "unchecked":
        return f"license: INVALID - {_NO_MLDSA}"
    if (state == "verified" and vendor_pq_hex
            and cert["pq_public_key"] != vendor_pq_hex.lower()):
        return ("license: INVALID - its post-quantum signature is not by the "
                "vendor's post-quantum key")
    if state == "verified" and not vendor_pq_hex:
        state = "unpinned"
    detail = (f"license {cert.get('license_id')} for {cert.get('licensee')!r}, "
              f"expires {cert.get('expires')}")
    if _date_passed(cert.get("expires")):
        # Advisory like the rest of this report: a lapsed license says
        # nothing about the integrity of what was recorded under it.
        detail += " - EXPIRED"
    if cert.get("scope"):
        detail += f", scope {cert['scope']}"
    detail += {"verified": (f" - vendor signature OK (Ed25519 + "
                            f"{cert.get('pq_alg')}, the vendor's pinned "
                            f"post-quantum key)"),
               "unpinned": (f" - vendor signature OK (Ed25519 + "
                            f"{cert.get('pq_alg')}; its post-quantum key not "
                            f"pinned - pass --vendor-pq-key)"),
               "unchecked": (" - vendor signature OK (Ed25519; its "
                             "post-quantum half not checked: library)")
               }.get(state, " - vendor signature OK (Ed25519 only)")

    licensed = set(cert.get("recorder_keys") or [])
    run_keys = set()
    for cp in container.get("checkpoints") or []:
        if cp.get("public_key"):
            run_keys.add(cp["public_key"])
    for anchor in container.get("anchors") or []:
        if anchor.get("type") == "worm" and anchor.get("public_key"):
            run_keys.add(anchor["public_key"])

    if not licensed:
        return detail + "; NOTE: license names no recorder key - not bound to a run"
    if not run_keys:
        return (detail + "; WARNING: run is not recorder-signed - the "
                "license cannot be bound to it")
    bound = run_keys & licensed
    if bound:
        return detail + f"; recorder key {_short_key(sorted(bound)[0])} is licensed (bound)"
    return (detail + "; WARNING: the run's recorder key is NOT covered by this "
            "license (possible license replay)")


_CONTROL_ESCAPES = {c: f"\\x{c:02x}" for c in (*range(0x20), 0x7f)}


def _out(msg: str) -> None:
    """Print a verdict message total on any content. A run_id, path, label or
    error is attacker-controlled and unvalidated offline, and stdout under
    Windows/CI is often a legacy code page (cp1252); a lone surrogate OR any
    non-Latin character (CJK, emoji) would otherwise crash the encode and flip
    a valid bundle to FAIL. Escape every non-ASCII byte so the write cannot
    fail on any locale codec, and every control character so a value cannot
    break the line or drive the terminal."""
    sys.stdout.write(str(msg).encode("ascii", "backslashreplace").decode()
                     .translate(_CONTROL_ESCAPES) + "\n")


class _VersionAction(argparse.Action):
    """Print the release + spec identity verbatim, then exit. Unlike argparse's
    built-in `version` action, this does not reflow the text to the terminal
    width - which would split a token like `aer-provenance-graph`
    across a line."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0,
                         default=argparse.SUPPRESS,
                         help="print the version and spec identity, then exit",
                         **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print(f"bitexact-verifier {__version__}")
        print(f"format {FORMAT}, canonicalization {CANON_DIALECT}, "
              f"MAX_DEPTH {MAX_DEPTH}, SAFE_INTEGER {SAFE_INTEGER}")
        parser.exit()


# The exit-code contract, word for word the BitExact CLI's (a test in the
# product holds the two equal), so a CI gate built on either tool reads a
# code the same way.
EXIT_CODES = {
    0: "OK - the evidence verifies, or the command did what it was asked",
    1: ("operational error - a usage error, a missing run or file, input "
        "that cannot be read, or a license refusal: no verdict was reached"),
    2: ("FAIL - the evidence does not verify, or a check it requires cannot "
        "run on this install (a library is missing)"),
    3: ("verified, with declared capture gaps - an intact record of an "
        "incomplete capture"),
}
EXIT_OK, EXIT_ERROR, EXIT_FAIL, EXIT_GAPS = 0, 1, 2, 3


class _Parser(argparse.ArgumentParser):
    """argparse, with a usage error exiting 1 - an operational error under
    the exit-code contract - rather than argparse's 2, which is FAIL."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def _error(message: str) -> int:
    """An operational error: the verifier could not reach a verdict."""
    _out(f"error: {message}")
    return EXIT_ERROR


def _fail(message: str) -> int:
    """The verdict that the evidence does not verify."""
    _out(f"FAIL: {message}")
    return EXIT_FAIL


def _epilog() -> str:
    import textwrap
    return "exit codes:\n" + "\n".join(
        line for code, text in EXIT_CODES.items()
        for line in textwrap.wrap(text, 76, initial_indent=f"  {code}  ",
                                  subsequent_indent="     "))


def main(argv=None) -> int:
    parser = _Parser(
        prog="bitexact-verifier",
        description="Verify a BitExact evidence bundle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_epilog())
    parser.add_argument("--version", action=_VersionAction)
    parser.add_argument("bundle", help="path to a bundle file (json/jsonl/"
                        "dsse) or a provenance-bag directory")
    parser.add_argument("--expect-key",
                        help="require this ed25519 public key (hex)")
    parser.add_argument("--expect-recorder-key",
                        help="require every checkpoint to be signed by this "
                             "ed25519 public key (hex)")
    parser.add_argument("--trust-file",
                        help="JSON file with bundle_keys/recorder_keys "
                             "lists of {key_id, public_key} entries")
    parser.add_argument("--expect-tsa",
                        help="require every RFC 3161 anchor to be from this "
                             "TSA certificate (PEM/DER file)")
    parser.add_argument("--vendor-key",
                        help="BitExact vendor ed25519 public key (hex); prints "
                             "an advisory license-provenance report - it never "
                             "affects the integrity verdict")
    parser.add_argument("--vendor-pq-key", metavar="HEX",
                        help="the vendor key's post-quantum (ML-DSA) half; "
                             "the license report then says whether that key "
                             "signed the license")
    parser.add_argument("--allow-gaps", action="store_true",
                        help="exit 0 for a bundle that verifies but declares "
                             "capture gaps (default: exit 3 - an intact chain "
                             "of an incomplete capture is not a complete "
                             "record)")
    parser.add_argument("--revoked-capture-key", action="append",
                        metavar="ID=YYYY-MM-DD",
                        help="a capture key id (32 hex) known to be in other "
                             "hands from that date; repeatable. The verdict "
                             "names the hash-only fields committed under it "
                             "as guessable by whoever holds it since then")
    parser.add_argument("--require-sealed", action="store_true",
                        help="fail a bundle whose run is not sealed (an "
                             "unfinished run's end is not attested)")
    parser.add_argument("--expect-witness", action="append",
                        metavar="NAME=KEY",
                        help="a transparency-log witness you trust and its "
                             "ed25519 public key (hex); repeatable. The "
                             "bundle must then prove its head is in a log "
                             "checkpoint this witness cosigned")
    parser.add_argument("--witness-threshold", type=int, default=1,
                        metavar="N",
                        help="how many of the pinned witnesses must have "
                             "cosigned (default 1)")
    parser.add_argument("--log-checkpoint", action="append", metavar="FILE",
                        help="a checkpoint note of the transparency log you "
                             "hold - from a witness, or kept earlier; "
                             "repeatable. Two roots at one size fail as a "
                             "split view, and given one later than the "
                             "bundle's, its head must be shown to be the "
                             "run's latest (--log-tail)")
    parser.add_argument("--log-tail", metavar="FILE",
                        help="the log's leaves from the bundle's head on, as "
                             "`bitexact log tail` writes them, ending at the "
                             "size of a checkpoint you hold")
    parser.add_argument("--point-in-time", action="store_true",
                        help="verify the bundle as the run stood at its own "
                             "log checkpoint: a later head of the run is "
                             "named, not refused")
    parser.add_argument("--expect-recorder-pq-key", metavar="HEX|FILE",
                        help="require every recorder checkpoint, anchor and "
                             "ledger signature to carry a post-quantum "
                             "(ML-DSA) signature by this key - a forger "
                             "holding only the Ed25519 key then fails")
    parser.add_argument("--expect-pq-key", metavar="HEX|FILE",
                        help="require the bundle signature to carry a "
                             "post-quantum signature by this ML-DSA key")
    parser.add_argument("--require-pq", action="store_true",
                        help="fail anything signed without a post-quantum "
                             "half, whatever key signed it")
    parser.add_argument("--render-view", metavar="OUT",
                        help="after a bag directory verifies (exit 0 or 3), "
                             "write its reading view to OUT: your own "
                             "rendering of the verified bag, not part of it. "
                             "Nothing is written when the bag does not verify")
    args = parser.parse_args(argv)
    if args.render_view and not Path(args.bundle).is_dir():
        return _error("--render-view renders a bag directory (an evidence "
                      "pack or a provenance bag), not a single bundle file")
    try:
        code = _verify_cli(args)
        if args.render_view and code in (EXIT_OK, EXIT_GAPS):
            # Rendered only from a bag that has just verified, so the page
            # shows evidence the verdict above stands behind.
            bag = Path(args.bundle)
            try:
                Path(args.render_view).write_bytes(
                    render_view(bag, _bag_identifier(bag)))
            except OSError as exc:
                return _error(f"cannot write {args.render_view} "
                              f"({exc.strerror})")
            _out(f"reading view written to {args.render_view} - your own "
                 f"rendering of the verified bag, not part of it")
        return code
    except Exception as exc:  # noqa: BLE001 - totality: the reference CLI
        # renders a verdict and exits nonzero on any input, never a traceback,
        # even where glue code (dispatch, indexing) touches a hostile shape
        # before a verify call. Mirrors the product's blanket verify boundary.
        return _fail(f"{type(exc).__name__}: {exc}")


def _verify_cli(args) -> int:
    # The pins and the trust file are the auditor's own inputs: one that
    # cannot be read or makes no sense is an operational error (exit 1),
    # never a verdict on the evidence.
    expect_tsa = None
    if args.expect_tsa:
        try:
            with open(args.expect_tsa, "rb") as f:
                expect_tsa = f.read()
        except OSError as exc:
            return _error(f"no such file: {args.expect_tsa} ({exc.strerror})")

    trusted_bundle_keys = trusted_recorder_keys = trusted_pq = None
    pq_pins = {}
    for flag in ("expect_recorder_pq_key", "expect_pq_key"):
        given = getattr(args, flag)
        if given is None:
            continue
        value = given
        if not _pq_key_shape(given):
            try:
                with open(given, encoding="utf-8") as f:
                    value = f.read().strip()
            except OSError:
                value = None
        if not _pq_key_shape(value):
            return _error(f"--{flag.replace('_', '-')} takes an ML-DSA-65 or "
                          f"ML-DSA-87 public key in hex, or a file holding "
                          f"one")
        pq_pins[flag] = value.lower()
    for pq_flag, classical_flag in (("expect_recorder_pq_key",
                                     "expect_recorder_key"),
                                    ("expect_pq_key", "expect_key")):
        # A post-quantum half pins the key it is the half of: alone it would
        # require nothing of a bundle that carries no material at all.
        if pq_flag in pq_pins and not getattr(args, classical_flag):
            return _error(f"--{pq_flag.replace('_', '-')} pins the "
                          f"post-quantum half of the key "
                          f"--{classical_flag.replace('_', '-')} names - give "
                          f"both")
    if args.trust_file:
        try:
            with open(args.trust_file, encoding="utf-8") as f:
                raw = f.read()  # decode inside the guard: bad UTF-8 is
            trust_doc = _loads(raw)  # a ValueError like bad JSON
        except OSError as exc:
            return _error(f"no such file: {args.trust_file} ({exc.strerror})")
        except ValueError as exc:
            return _error(f"trust file is not valid JSON: {exc}")
        problem = _validate_trust(trust_doc)
        if problem:
            return _error(problem)
        if "bundle_keys" in trust_doc:
            trusted_bundle_keys = [k["public_key"]
                                   for k in trust_doc["bundle_keys"]]
        if "recorder_keys" in trust_doc:
            trusted_recorder_keys = [k["public_key"]
                                     for k in trust_doc["recorder_keys"]]
        trusted_pq = _trusted_pq(trust_doc)

    args.revoked_capture = {}
    for spec in args.revoked_capture_key or ():
        key_id, sep, since = spec.partition("=")
        if not (sep and _hex32(key_id) and _iso_date(since)):
            return _error(f"--revoked-capture-key takes ID=YYYY-MM-DD with a "
                          f"32-hex capture key id, got {spec[:120]!r}")
        args.revoked_capture[key_id] = since

    witnesses = {}
    for spec in args.expect_witness or ():
        name, sep, key = spec.rpartition("=")
        if not sep or not name or not (
                _HEX64.fullmatch(key) or (
                    len(key) == 2 * _MLDSA44_SIZES[0]
                    and _LOWER_HEX.fullmatch(key.lower()))):
            return _error(f"--expect-witness takes NAME=KEY with a 64-hex "
                          f"ed25519 or an ML-DSA-44 public key, got "
                          f"{spec[:120]!r}")
        witnesses[name] = key.lower() if len(key) > 64 else key
    if witnesses and not 1 <= args.witness_threshold <= len(witnesses):
        return _error(f"--witness-threshold must be between 1 and the "
                      f"{_n(len(witnesses), 'pinned witness', 'pinned witnesses')}")

    held = []
    for path in args.log_checkpoint or ():
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError) as exc:
            return _error(f"cannot read {path} ({exc})")
        if _open_note(text, {}, {}) is None:
            return _error(f"--log-checkpoint {path} is not a checkpoint note")
        held.append(text)
    tail = None
    if args.log_tail:
        try:
            with open(args.log_tail, encoding="utf-8") as f:
                tail = _loads(f.read())
        except OSError as exc:
            return _error(f"no such file: {args.log_tail} ({exc.strerror})")
        except ValueError as exc:
            return _error(f"--log-tail {args.log_tail} is not JSON: {exc}")
        problem = _log_tail_problem(tail)
        if problem:
            return _error(f"--log-tail {args.log_tail}: {problem}")

    if not Path(args.bundle).exists():
        return _error(f"no such file: {args.bundle}")
    # Built once. Four dispatch paths repeated the same five keywords, and a
    # pin left out of one of them is a check that silently does not run on
    # that form while the other three still enforce it.
    pins = Trust(args.expect_key, args.expect_recorder_key,
                 trusted_bundle_keys, trusted_recorder_keys, expect_tsa,
                 witnesses or None, args.witness_threshold,
                 pq_pins.get("expect_recorder_pq_key"),
                 pq_pins.get("expect_pq_key"), trusted_pq, args.require_pq,
                 tuple(held), tail, args.point_in_time)
    recorder_attested = pins.recorder_pinned
    if Path(args.bundle).is_dir():
        ok, err, summary = verify_provenance_bundle(
            args.bundle, **pins._asdict())
        if ok is None:
            return _error(err)
        if ok and summary.get("pack"):
            return _pack_verdict(summary, args, pins, expect_tsa)
        if ok and args.require_sealed and not summary.get("sealed"):
            return _fail(f"the bundle rooted at {summary['root']!r} is "
                         f"unsealed - its end is not attested and "
                         f"--require-sealed was given")
        if ok:
            signed = _signed_word(summary["signed"], pins)
            # Same time-trust caveat the single-bundle path prints: an unpinned
            # RFC 3161 anchor's attested time is untrusted until --expect-tsa.
            note = _tsa_caveat(summary.get("anchors"), expect_tsa)
            note += _suite_note(summary["signatures"], pins)
            note += _capture_note(summary["capture"], args.revoked_capture)
            note += _gap_note(summary["gaps"] - summary["refusals"])
            note += _refusal_note(summary, pins)
            note += "".join(summary["log"])
            note += _view_note(args.bundle)
            _out(f"OK: provenance bundle rooted at {summary['root']!r} - "
                  f"{_n(summary['runs'], 'run')}, "
                  f"{_n(summary['edges'], 'fork edge')}, graph verified"
                  f"{_ledger_note(summary, pins)}, {signed}"
                  f"{_attested(recorder_attested)}{note}")
            _capture_scope(summary["capture"])
            _standing_out(summary["capture"])
            _via_out(summary["via"])
            _unchecked_out(args.bundle)
            if args.vendor_key:
                # The same license report the single-bundle form prints: an
                # auditor handed a pack asks the same question of it. Read
                # from the bag that has just verified, so the line describes
                # evidence the verdict above already stands behind.
                root = _bag_root_bundle(Path(args.bundle), summary["root"])
                if root is not None:
                    _out(license_provenance(root, args.vendor_key,
                                            args.vendor_pq_key))
            return _complete(summary["gaps"], args)
        return _fail(err)

    # A file that exists but cannot be opened is the host's problem, not the
    # evidence's: no verdict, exit 1, as for a file that does not exist.
    try:
        f = open(args.bundle, encoding="utf-8")
    except OSError as exc:
        return _error(f"cannot read {args.bundle} ({exc.strerror})")
    # From here every problem is in the bundle itself - bytes that are not
    # JSON included - so each is a verdict on the evidence: FAIL, exit 2.
    with f:
        try:
            # The header is the first NON-BLANK line: the spec says blank
            # lines between records are skipped, and that has to include the
            # ones before the header.
            first = f.readline()
            while first and not first.strip():
                first = f.readline()
        except UnicodeDecodeError as exc:  # hostile bytes are a verdict
            return _fail(f"bundle is not valid JSON: {exc}")
        try:
            first_doc = _loads(first)
        except ValueError:
            first_doc = None
        if (isinstance(first_doc, dict)
                and first_doc.get("format") == JSONL_FORMAT):
            def _lines():
                yield first
                yield from f
            ok, err, summary = verify_jsonl(
                _lines(), **pins._asdict())
            if ok and args.require_sealed and not summary["sealed"]:
                return _fail("bundle is unsealed - its end is not attested "
                             "and --require-sealed was given")
            if ok:
                signed = _signed_word(summary["signed"], pins)
                note = _redaction_note(summary["redacted"], summary["signed"],
                                       recorder_attested)
                note += _anchor_note(first_doc.get("anchors"))
                note += _tsa_caveat(first_doc.get("anchors"), expect_tsa)
                note += _log_note(first_doc.get("tlog"), pins,
                                  first_doc.get("checkpoints") or [])
                note += _suite_note(_signature_facts([first_doc], pins), pins)
                note += _capture_note(summary["capture"], args.revoked_capture)
                note += _gap_note(summary["gaps"])
                _out(f"OK: {first_doc.get('run_id')} - "
                      f"{summary['steps']} steps"
                      f"{_mix_text(summary['mix'], summary['injected'], summary['relayed'], summary['relay_hosts'])}, "
                      f"chain verified, "
                      f"{_seal_word(summary['sealed'])}, {signed}"
                      f"{_attested(recorder_attested)}{note} (jsonl, streamed)")
                _capture_scope(summary["capture"])
                _standing_out(summary["capture"])
                _via_out(summary["via"])
                if args.vendor_key:
                    _out(license_provenance(first_doc, args.vendor_key,
                                            args.vendor_pq_key))
                return _complete(summary["gaps"], args)
            return _fail(err)
        f.seek(0)
        try:
            bundle = _loads(f.read())
        except ValueError as exc:
            return _fail(f"bundle is not valid JSON: {exc}")
    envelope_signatures = []
    if isinstance(bundle, dict) and "payloadType" in bundle:
        ok, err, inner = verify_envelope(
            bundle, **pins._asdict())
        if ok:
            envelope_signatures = [_dsse_accepted(bundle, pins)[1]]
        bundle = inner or {}
    else:
        ok, err = verify_bundle(
            bundle, **pins._asdict())
    if ok:
        entries = bundle.get("entries", [])
        n = len(entries)
        sealed = any(isinstance(e, dict) and e.get("kind") == "run_end"
                     for e in entries)
        if args.require_sealed and not sealed:
            return _fail("bundle is unsealed - its end is not attested and "
                         "--require-sealed was given")
        signed = _signed_word(bool(bundle.get("signature")), pins)
        marks = [e.get("redacted") for e in entries]
        redacted = sum(len(r) if isinstance(r, list) else 1
                       for r in marks if r)
        note = _redaction_note(redacted, bool(bundle.get("signature")),
                               recorder_attested)
        note += _anchor_note(bundle.get("anchors"))
        note += _tsa_caveat(bundle.get("anchors"), expect_tsa)
        note += _log_note(bundle.get("tlog"), pins,
                          bundle.get("checkpoints") or [])
        note += _suite_note(_signature_facts([bundle], pins,
                                             envelope_signatures), pins)
        gaps = sum(_gaps(e) for e in entries)
        captured = _run_capture([entries])
        note += _capture_note(captured, args.revoked_capture)
        note += _gap_note(gaps)
        mix = {"observed": 0, "asserted": 0, "synthetic": 0}
        for e in entries:
            mix[e.get("prov")] += 1
        injected = sum(e.get("kind") == "injected" for e in entries)
        hosts = [h for h in map(_relay_peer, entries) if h is not None]
        _out(f"OK: {bundle.get('run_id')} - {n} steps"
              f"{_mix_text(mix, injected, len(hosts), len(set(hosts)))}, "
              f"chain verified, {_seal_word(sealed)}, {signed}"
              f"{_attested(recorder_attested)}{note}")
        _capture_scope(captured)
        _standing_out(captured)
        via: dict = {}
        for e in entries:
            _via_tally(e, via)
        _via_out(via)
        if args.vendor_key:
            _out(license_provenance(bundle, args.vendor_key,
                                    args.vendor_pq_key))
        return _complete(gaps, args)
    return _fail(err)


def _signature_facts(containers, trust, extra=()) -> dict:
    """What the signatures a verdict stands on are made of, object by
    object: how many signed objects; how many carry a post-quantum half, how
    many of those are by a key the caller pinned, how many are not in each
    role ("recorder": checkpoints and WORM anchors; "bundle": the bundle
    signature and the accepted DSSE entry), how many could not be checked (no
    ML-DSA in the library), and of which sets; and how its RFC 3161 tokens
    are signed. `containers` are verified bundles (or JSONL headers); `extra`
    other objects the verdict accepted (the DSSE entry whose signature was
    accepted) - never objects nothing checked."""
    objects, tsa = [(o, "bundle") for o in extra], set()
    for c in containers:
        cps = [cp for cp in c.get("checkpoints") or [] if isinstance(cp, dict)]
        anchors = [a for a in c.get("anchors") or [] if isinstance(a, dict)]
        objects += [(o, "recorder") for o in
                    cps + [a for a in anchors if a.get("type") == "worm"]]
        if isinstance(c.get("signature"), dict):
            objects.append((c["signature"], "bundle"))
        tsa |= {_tsa_suite(a, trust.expect_tsa) for a in anchors
                if a.get("type") == "rfc3161"}
    hybrid = [(o, role) for o, role in objects
              if o.get("pq_public_key") is not None]
    unpinned = [role for o, role in hybrid if o["pq_public_key"] not in
                trust.pq_pins(role, o.get("public_key"))]
    return {"objects": len(objects), "hybrid": len(hybrid),
            "pinned": len(hybrid) - len(unpinned) if _mldsa() else 0,
            "unpinned": {role: unpinned.count(role)
                         for role in ("recorder", "bundle")},
            "unchecked": len(hybrid) if _mldsa() is None else 0,
            "pq_algs": sorted({str(o.get("pq_alg")) for o, _ in hybrid}),
            "timestamps": sorted(tsa)}


def _suite_note(facts: dict, pins: "Trust") -> str:
    """The signature suite in the verdict's words, said on every OK line,
    from what each object's own check established: an OK never implies
    post-quantum protection it did not check, and never calls a key pinned
    that no pin named."""
    words = ""
    if facts["objects"]:
        if not facts["hybrid"]:
            words = (", signatures: Ed25519 only - not resistant to a quantum "
                     "forger")
        elif facts["unchecked"]:
            words = (", post-quantum signature present, not checked (library) "
                     "- only the Ed25519 signatures were verified")
        else:
            words = (f", signatures: Ed25519 + {'/'.join(facts['pq_algs'])} "
                     f"(post-quantum)")
            if facts["hybrid"] < facts["objects"]:
                words += (f" on {facts['hybrid']} of {facts['objects']} "
                          f"signed objects, the rest Ed25519 only")
            words += (", post-quantum key pinned"
                      if facts["pinned"] == facts["hybrid"] else
                      " - post-quantum key not pinned: a forger who recovers "
                      "the Ed25519 key can add an ML-DSA key of their own; "
                      "pin it with " + " and ".join(
                          flag for role, flag in (
                              ("recorder", "--expect-recorder-pq-key"),
                              ("bundle", "--expect-pq-key"))
                          if facts["unpinned"][role])
                      + ", or a trust file naming it")
    if facts["timestamps"]:
        words += ", timestamp: " + " and ".join(facts["timestamps"])
    return words


def _signed_word(signed: bool, pins: "Trust") -> str:
    """The signature's verdict, scoped to what it proved.

    With no key pinned, the signature is checked against the public key the
    bundle carries, which proves only that whoever produced these bytes held
    SOME key - anyone can re-sign an altered bundle under their own. So an
    unpinned signature says so, the way an unpinned RFC 3161 time does."""
    if not signed:
        # "bundle unsigned", not "unsigned": a recorder-attested run carries
        # no bundle signature and is not unsigned, and the bare word beside
        # "recorder-attested" read as a failure.
        return "bundle unsigned"
    if pins.bundle_pinned:
        return "signed"
    return ("signed (signing key not pinned - pass --expect-key to know "
            "whose signature it is)")


def _relay_peer(entry):
    """The remote host that captured an observed entry and relayed it to the
    recorder, or None. Its source block - inside the entry's hash - names
    the host by the identity its connection authenticated."""
    data = entry.get("data") if isinstance(entry, dict) else None
    block = data.get("aer_source") if isinstance(data, dict) else None
    if (entry.get("prov") == "observed" and isinstance(block, dict)
            and isinstance(block.get("peer"), str)):
        return block["peer"]
    return None


def _via_tally(entry, into: dict) -> None:
    """Count an entry under the capture path its `via` names. The path is
    inside the entry's hash, but the writer asserts it: any process holding
    the host secret could name any path, so the count is attribution, never
    proof. An entry with no `via` counts under None; one whose `via` is not
    a non-empty string counts as unlabeled. The `run_end` seal is not
    counted: it closes the chain rather than capturing anything, and its
    `sealed_by` names who wrote it."""
    if isinstance(entry, dict) and entry.get("kind") == "run_end":
        return
    if not isinstance(entry, dict) or "via" not in entry:
        label = None
    elif isinstance(entry["via"], str) and entry["via"]:
        label = entry["via"]
    else:
        label = "unlabeled"
    into[label] = into.get(label, 0) + 1


def _via_line(counts: dict) -> "str | None":
    """The per-path mix of a verified chain, most entries first, or None
    when no entry names a path. Entries that name none are unlabeled."""
    named = {k: n for k, n in counts.items() if k is not None}
    if not named:
        return None
    if None in counts:
        named["unlabeled"] = named.get("unlabeled", 0) + counts[None]
    mix = ", ".join(f"{label} {n}" for label, n
                    in sorted(named.items(), key=lambda kv: (-kv[1], kv[0])))
    return f"captured via {mix} (attribution, not proof)"


def _via_out(counts: dict) -> None:
    """The attribution line, on its own line after the OK line."""
    line = _via_line(counts)
    if line:
        _out(line)


def _mix_text(mix: dict, injected: int, relayed: int = 0,
              hosts: int = 0) -> str:
    """What the verified entries are made of. The provenance class is inside
    each entry's hash, so this is proven, not read off a label; a synthetic
    entry is a marked counterfactual and the verdict says so. An observed
    entry a remote host relayed was observed on that host, not by the
    recorder, and the verdict says how many and from how many hosts."""
    observed = f"observed {mix['observed']}"
    if relayed:
        observed += (f", {relayed} of them captured and relayed by "
                     f"{_n(hosts, 'remote host')}")
    text = (f" ({observed} / asserted {mix['asserted']} / "
            f"synthetic {mix['synthetic']})")
    if injected:
        text += (f", {_n(injected, 'injected response')} - a counterfactual, "
                 f"not recorded traffic")
    return text


_CAPTURE_MODES = ("scrub", "hash-only", "unscanned", "withheld", "upstream")


CAPTURE_SCOPE = ("Scrubbed and hash-only fields prove that a value was "
                 "presented and which rule removed it. They do not prove what "
                 "the value was, they cannot be replayed, and hash-only "
                 "custody is not HIPAA de-identification.")
# The scope of a run recorded with no capture policy in force: it removed
# nothing, so the record holds every value as it was presented.
CAPTURE_SCOPE_OFF = ("A run recorded with no capture policy in force kept "
                     "every value as captured, card numbers, IBANs and "
                     "credentials included.")


def _capture_counts(entry, into: dict) -> None:
    """Add an entry's `capture` declarations to `into`: the count of each
    outcome, the detectors' finds, and the hash-only fields a key opens (by
    key id). From the declarations only - a token in a value counts nothing.
    A field claimed cleaned before BitExact saw it counts as `upstream`,
    whether the claim is its declaration or kept beside BitExact's own
    outcome. A run's `run_meta` counts the run (`runs`), and as `off` when
    it says no capture policy was in force when the run opened; the
    deployment standing it states is tallied under `standing`
    (_standing_tally)."""
    data = entry.get("data") if isinstance(entry, dict) else None
    if isinstance(data, dict) and entry.get("kind") == "run_meta":
        into["runs"] = into.get("runs", 0) + 1
        if data.get("capture_policy") == "off":
            into["off"] = into.get("off", 0) + 1
        if "standing" in data:
            _standing_tally(data["standing"], into.setdefault("standing", {}))
    capture = entry.get("capture") if isinstance(entry, dict) else None
    fields = capture.get("fields") if isinstance(capture, dict) else None
    for decl in (fields.values() if isinstance(fields, dict) else ()):
        if not isinstance(decl, dict):
            continue
        mode = ("upstream" if decl.get("mode") == "scrubbed-upstream"
                else decl.get("mode"))
        if mode not in _CAPTURE_MODES:
            continue
        into[mode] = into.get(mode, 0) + 1
        if mode != "upstream" and decl.get("upstream") is True:
            into["upstream"] = into.get("upstream", 0) + 1
        if mode == "scrub" and isinstance(decl.get("found"), dict):
            found = into.setdefault("found", {})
            for name, n in decl["found"].items():
                if isinstance(name, str) and type(n) is int:
                    found[name] = found.get(name, 0) + n
        if mode == "hash-only" and isinstance(decl.get("key_id"), str):
            into["openable"] = into.get("openable", 0) + 1
            keys = into.setdefault("keys", [])
            if decl["key_id"] not in keys:
                keys.append(decl["key_id"])
            under = into.setdefault("under", {})
            under[decl["key_id"]] = under.get(decl["key_id"], 0) + 1
            if decl.get("linkable") is True:
                into["linkable"] = into.get("linkable", 0) + 1


_STANDING_STATES = ("ok", "amber", "red")


def _standing_tally(standing, into: dict) -> None:
    """Count one run's stated standing: the producer's statement, in its
    run_meta, of where its deployment stood when the run opened - `state`
    ok, amber or red, its `reasons`, and whether it was allowed to record
    (`records`). Inside the entry's hash, so it cannot be altered unseen,
    but the producer asserts it. A standing of any other shape counts as
    `malformed`; one that says recording was not allowed is kept under
    `refused` with its reasons."""
    shaped = (isinstance(standing, dict)
              and standing.get("state") in _STANDING_STATES
              and isinstance(standing.get("reasons"), list)
              and all(isinstance(r, str) for r in standing["reasons"])
              and isinstance(standing.get("records"), bool))
    if not shaped:
        into["malformed"] = into.get("malformed", 0) + 1
        return
    state = standing["state"]
    into[state] = into.get(state, 0) + 1
    into.setdefault("reasons", [])
    for reason in standing["reasons"]:
        if reason not in into["reasons"]:
            into["reasons"].append(reason)
    if standing["records"] is False:
        into.setdefault("refused", []).append("; ".join(standing["reasons"]))


def _standing_refusal(counts: dict) -> "str | None":
    """The FAIL a verdict gives a run whose own standing says its deployment
    was not allowed to record: the run recorded what the producer itself
    declared it must not, so none of it can be trusted. None otherwise."""
    refused = counts.get("standing", {}).get("refused")
    if not refused:
        return None
    return (f"{_n(len(refused), 'run')} recorded although its stated "
            f"standing says the deployment was not allowed to record "
            f"(records: false) - {refused[0]}")


def _standing_out(counts: dict) -> None:
    """The standing line, on its own line after the OK line, when any run
    states one: the state each run was recorded under and why, as the
    producer stated it."""
    tally = counts.get("standing")
    if not tally:
        return
    states = [(s, tally[s]) for s in _STANDING_STATES if tally.get(s)]
    if tally.get("malformed"):
        states.append(("malformed", tally["malformed"]))
    if sum(n for _s, n in states) == 1:
        words = states[0][0]
    else:
        words = ", ".join(f"{_n(n, 'run')} {s}" for s, n in states)
    reasons = tally.get("reasons")
    _out(f"standing when recorded: {words}"
         + (f" - {'; '.join(reasons)}" if reasons else "")
         + " (stated by the producer, not proof)")


def _capture_note(counts: dict, revoked: "dict | None" = None) -> str:
    """What the capture policy kept of the verified entries, and - when it
    kept anything less than the value - the scope of what that proves.
    `revoked` (from --revoked-capture-key) maps a capture key id to the date
    from which it may be in other hands; the fields committed under it are
    named guessable from then. Word for word the product's
    capture_policy.verdict_clause."""
    revoked = revoked or {}
    parts = []
    if counts.get("off"):
        parts.append("no capture policy was in force"
                     if counts["off"] == counts.get("runs") == 1 else
                     f"{_n(counts['off'], 'run')} recorded with no capture "
                     f"policy in force")
    if counts.get("scrub"):
        found = ", ".join(f"{name} {n}" for name, n
                          in sorted(counts.get("found", {}).items()))
        parts.append(f"{_n(counts['scrub'], 'field')} scrubbed before "
                     f"capture" + (f" ({found})" if found else ""))
    if counts.get("hash-only"):
        keys = ", ".join(k[:4] + ".." for k in sorted(counts.get("keys", [])))
        opened = (f"{counts.get('openable', 0)} can be opened with key {keys}"
                  if counts.get("openable") else "none can be opened")
        if counts.get("linkable"):
            opened += (f"; {counts['linkable']} linkable - equal values "
                       f"commit equal")
        parts.append(f"{_n(counts['hash-only'], 'field')} hash-only (never "
                     f"held; {opened})")
    for key_id, n in sorted(counts.get("under", {}).items()):
        if key_id in revoked:
            parts.append(f"{_n(n, 'field')} under capture key {key_id[:4]}.. "
                         f"revoked {revoked[key_id]} (guessable by whoever "
                         f"holds it since then)")
    if counts.get("unscanned"):
        parts.append(f"{_n(counts['unscanned'], 'field')} not scanned "
                     f"(binary)")
    if counts.get("withheld"):
        parts.append(f"{_n(counts['withheld'], 'field')} withheld (scrub "
                     f"failed) - declared capture gap")
    if counts.get("upstream"):
        parts.append(f"{_n(counts['upstream'], 'field')} claimed cleaned "
                     f"upstream (asserted, not checked)")
    return f", {', '.join(parts)}" if parts else ""


def _capture_scope_text(counts: dict) -> "str | None":
    """The scope a verdict states: CAPTURE_SCOPE_OFF when a run was recorded
    with no capture policy in force, CAPTURE_SCOPE when the policy kept any
    field as less than its value, both (in that order) for a bag holding
    each, else None. Word for word the product's
    capture_policy.verdict_scope."""
    altered = any(counts.get(m) for m in _CAPTURE_MODES)
    return " ".join(s for s, on in ((CAPTURE_SCOPE_OFF, counts.get("off")),
                                    (CAPTURE_SCOPE, altered)) if on) or None


def _capture_scope(counts: dict) -> None:
    """The scope sentence, on its own line after the OK line, whenever there
    is one to state (_capture_scope_text)."""
    scope = _capture_scope_text(counts)
    if scope:
        _out(scope)


def _gaps(entry) -> int:
    """The capture gaps an entry declares: 1 for a marker carrying a gap -
    the recorder's own record that something it should have captured was
    not - plus one per field its `capture` block names a cause for (withheld
    because it could not be scrubbed, or hash-only with no capture key).
    Read only from entries a verification has passed, each a JSON object."""
    data = entry.get("data")
    count = int(entry.get("kind") == "marker" and isinstance(data, dict)
                and isinstance(data.get("gap"), dict))
    capture = entry.get("capture")
    fields = capture.get("fields") if isinstance(capture, dict) else None
    if isinstance(fields, dict):
        count += sum(1 for decl in fields.values()
                     if isinstance(decl, dict) and "cause" in decl)
    return count


def _pack_verdict(summary: dict, args, pins: "Trust", expect_tsa) -> int:
    """The verdict on a verified evidence pack: what every run in it and
    every ledger in it proved, each to the head the recorder signed."""
    if args.require_sealed and summary["unsealed"]:
        return _fail(f"the pack holds unsealed "
                     f"{'run' if len(summary['unsealed']) == 1 else 'runs'} "
                     f"{', '.join(map(str, summary['unsealed']))} - their "
                     f"ends are not attested and --require-sealed was given")
    signed = _signed_word(summary["signed"], pins)
    note = _tsa_caveat(summary["anchors"], expect_tsa)
    note += _suite_note(summary["signatures"], pins)
    note += _capture_note(summary["capture"], args.revoked_capture)
    note += _gap_note(summary["gaps"] - summary["refusals"])
    note += _refusal_note(summary, pins)
    if summary["unsealed"]:
        note += f", {_n(len(summary['unsealed']), 'run')} unsealed"
    note += "".join(summary["log"])
    note += _view_note(args.bundle)
    _out(f"OK: evidence pack - {_n(summary['runs'], 'run')} verified"
         f"{_ledger_note(summary, pins)}, bag checksums verified, {signed}"
         f"{_attested(pins.recorder_pinned)}{note}")
    _capture_scope(summary["capture"])
    _standing_out(summary["capture"])
    _via_out(summary["via"])
    _unchecked_out(args.bundle)
    return _complete(summary["gaps"], args)


def _refusal_note(summary: dict, pins: "Trust") -> str:
    """The verdict's clause on the refusals a bag carries (_verify_ledgers):
    executions refused at open, which left no run and so no evidence."""
    if not summary["refusals"]:
        return ""
    by = ("the pinned recorder key" if pins.recorder_pinned
          else "a recorder key, unpinned")
    return (f", {_n(summary['refusals'], 'recorded refusal')} - executions "
            f"that left no run ({summary['refusals_signed']} signed by {by})")


def _ledger_note(summary: dict, pins: "Trust") -> str:
    """The verdict's clause on the ledgers a bag carries (_verify_ledgers):
    each anchored at the head the recorder signed, at its event count. The
    anchor proves no event is missing only when the recorder key is pinned:
    a key nobody vouched for could be anyone's, re-signing a cut ledger."""
    if not summary["ledgers"]:
        return ""
    at = "; ".join(f"{rel} at {_n(n, 'event')}"
                   for rel, n in summary["anchored"])
    if pins.recorder_pinned:
        return (f", {_n(summary['ledgers'], 'ledger')} chain-verified and "
                f"anchored at the head the pinned recorder key signed ({at})")
    return (f", {_n(summary['ledgers'], 'ledger')} chain-verified to a "
            f"signed head ({at}; recorder key not pinned - pass "
            f"--expect-recorder-key to know no newest event is missing)")


def _complete(gaps: int, args) -> int:
    """The exit code of a verified bundle: 0 for a complete capture, 3 for
    one that declares gaps unless --allow-gaps accepts them - the product's
    own `bitexact verify` contract, so a CI gate built on either agrees."""
    return EXIT_GAPS if gaps and not args.allow_gaps else EXIT_OK


def _n(count, word: str, many: "str | None" = None) -> str:
    """A count in words: "1 run", "3 runs"."""
    return f"{count} {word if count == 1 else many or word + 's'}"


def _gap_note(gaps: int) -> str:
    """An intact chain of an incomplete capture is not a complete record."""
    if not gaps:
        return ""
    return (f", {_n(gaps, 'declared capture gap')} - the capture is incomplete; "
            f"each gap names its cause")


def _redaction_note(redacted: int, signed: bool, recorder_attested: bool) -> str:
    """The redaction count, with a demand for a signature only where nothing
    attests the redaction: at the recorder tier an unaccountable strip was
    refused before this line could print, so the recorder has attested it."""
    if not redacted:
        return ""
    note = f", {_n(redacted, 'field')} redacted"
    if not signed and not recorder_attested:
        note += " (unsigned redaction - demand a signed bundle)"
    return note


def _anchor_note(anchors) -> str:
    """Which external anchors bind the head - a WORM anchor was verified and
    then went unmentioned."""
    counts = {}
    for a in anchors or []:
        kind = a.get("type") if isinstance(a, dict) else None
        if kind in ("worm", "rfc3161"):
            counts[kind] = counts.get(kind, 0) + 1
    parts = []
    if counts.get("worm"):
        parts.append(_n(counts["worm"], "worm anchor"))
    if counts.get("rfc3161"):
        parts.append(_n(counts["rfc3161"], "RFC 3161 timestamp"))
    return (", " + ", ".join(parts)) if parts else ""


def _seal_word(sealed: bool) -> str:
    """What the verdict may say about the run's end: `sealed` means a
    run_end attests it; otherwise the end is simply not attested - a live
    run and a truncated one look the same to the chain alone."""
    return "sealed" if sealed else "unsealed - end not attested"


def _bag_root_bundle(bag: Path, root):
    """The root run's bundle document inside a verified bag, or None.

    Total: the bag has already verified when this runs, so a shape it cannot
    read is a report this cannot print, never a verdict this can change."""
    try:
        graph = _loads((bag / "data" / "provenance-graph.json")
                       .read_text(encoding="utf-8"))
        for node in graph.get("nodes", []):
            if node.get("run_id") == root:
                return _loads((bag / "data" / node["bundle"])
                              .read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - a report, never a verdict
        return None
    return None


def _attested(recorder_attested) -> str:
    """`recorder-attested` is claimed only when the caller pinned a recorder
    key and the head-coverage demand held - never from checkpoints of a key
    nobody vouched for, and never merely because a trust file was passed: a
    trust file that names only bundle keys pins no recorder key, so the
    recorder tier never runs and there is nothing to attest."""
    return ", recorder-attested" if recorder_attested else ""


if __name__ == "__main__":
    sys.exit(main())
