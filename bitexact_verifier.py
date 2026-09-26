"""Standalone verifier for BitExact evidence bundles.

Implements bundle-spec.md (bitexact-bundle/1): hash-chain verification
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
import hmac
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
__version__ = "2.3.0"

class Trust(NamedTuple):
    """What a caller pins a verdict to, travelling as one value.

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


FORMAT = "bitexact-bundle/1"
CANON_DIALECT = "bitexact-jcs/1"
GRAPH_FORMAT = "bitexact-provenance-graph/1"
GRAPH_PREDICATE_TYPE = "https://bitexact.dev/provenance-graph/v1"
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
# is inside the entry hash, so relabelling re-chains - and on a keyless
# bundle re-chaining is free. Fixing the class per kind is what stops an
# `injected` counterfactual being presented as an observed `http_call`, or
# an operator's assertion as something the recorder saw.
PROV_BY_KIND = {
    "run_meta": ("observed",), "run_end": ("observed",),
    "fork": ("observed",), "http_call": ("observed",),
    "nondet": ("observed",),
    "tool_call": ("observed", "asserted"),
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
        # not of the evidence: 3.10 - the floor this verifier declares -
        # raises here, where 3.12 parses the same document and lets the
        # MAX_DEPTH check below refuse it. Nesting is the only thing
        # that recurses in a JSON document, so this is that refusal
        # arriving early. An auditor must read the same reason on every
        # supported version, not "malformed bundle: RecursionError(...)"
        # on the floor.
        raise ValueError(
            f"nesting deeper than {MAX_DEPTH} levels is refused") from None
    if _has_nonfinite(value):  # the overflow-literal form parse_constant misses
        raise ValueError("non-finite number is not allowed")
    if _too_deep(value, MAX_DEPTH):
        raise ValueError(f"nesting deeper than {MAX_DEPTH} levels is refused")
    return value


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
RUN_PREDICATE_TYPE = "https://bitexact.dev/run/v1"


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


def _verify_entry_data(entry: dict):
    data = entry.get("data", {})
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
    commitments = entry.get("commitments", {})
    if not isinstance(commitments, dict):
        return False, "entry commitments is not a JSON object"
    redacted = entry.get("redacted", [])
    if not isinstance(redacted, list) \
            or any(not isinstance(p, str) for p in redacted):
        # a redaction marker is a list of step:path strings; a non-string
        # (e.g. unhashable) element is a verdict, not a TypeError out of set()
        return False, "entry redacted is not a JSON array of strings"
    redacted = set(redacted)
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
        if not present:
            return False, f"path {path} missing without a redaction marker"
        salt_hex = salts.get(path, "")
        try:
            raw_salt = (bytes.fromhex(salt_hex) if isinstance(salt_hex, str)
                        else b"")
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
                  expect_tsa: str | None = None):
    """Return (ok, error). The error names what failed and where.

    Total: hostile input of any shape is a failed verification, never an
    exception."""
    try:
        return _verify_bundle(bundle, Trust(
            expect_key, expect_recorder_key, trusted_bundle_keys,
            trusted_recorder_keys, expect_tsa))
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
            claims.extend((i, t) for t in _redaction_fields(entry))
        marks = entry.get("redacted")
        if isinstance(marks, list) and marks:
            markers[i] = marks

    head = entries[-1]["hash"] if entries else None
    if bundle.get("chain", {}).get("head_hash") != head:
        return False, "chain head_hash does not match the final entry"

    err = _redaction_incomplete(claims, markers, len(entries))
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
                        sealed=run_end_at is not None)


def _seal_step(entry, i, run_end_at):
    """Enforce run_end seal semantics as each entry streams past: only
    redaction/repair audit entries may follow a seal, and a seal's
    attested step count must equal its own position + 1. Matches the
    product's verify_run/verify_stream so the public verifier proves the
    same 'complete run vs truncated' distinction the docs claim."""
    if run_end_at is not None and entry.get("kind") not in AUDIT_KINDS:
        return (f"step {run_end_at}: run_end seal is not final - only "
                f"redaction, repair, hold and hold_release audit entries may "
                f"follow a seal")
    if entry.get("kind") == "run_end":
        sealed = (entry.get("data") or {}).get("steps")
        if sealed != i + 1:
            return (f"step {i}: run_end seal attests {sealed} steps but "
                    f"was sealed at {i + 1}")
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
        # simply names no step.
        if not (step_text.isascii() and step_text.isdigit()) \
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


def _iso_instant(value) -> bool:
    """An ISO 8601 instant with a UTC offset, as the recorder writes it."""
    import datetime as _dt
    if not isinstance(value, str) or "T" not in value:
        return False
    try:
        return _dt.datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def _entry_rules(entry: dict):
    """The spec's per-entry vocabulary rules (bundle-spec.md, Entries):
    a known kind, the provenance class that kind may carry, a parseable
    timestamp, and an audit entry left whole."""
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
    return None


def _entry_check(entry: dict, i: int, prev: str, run_id):
    """One entry against its position, predecessor, and run identity."""
    if not isinstance(entry, dict):
        return False, f"step {i}: entry is not a JSON object"
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
        steps = cp.get("steps", 0)
        # An integer-valued float `steps` indexes differently in a list than
        # in a dict, so the two bundle forms would split on it; refuse a
        # non-int, matching the product verifier and the anchor binding.
        if not isinstance(steps, int) or isinstance(steps, bool):
            return False, f"checkpoint {i}: non-integer step count {steps!r}"
        if steps > entries_len:
            return False, (f"checkpoint {i}: attests {steps} steps but the "
                           f"bundle has {entries_len} - history removed "
                           f"below a signed checkpoint")
        if steps > 0 and hash_at(steps - 1) != cp.get("head_hash"):
            return False, (f"checkpoint {i}: attested head does not match "
                           f"the chain at step {steps - 1}")
        prev_checkpoint = _hash_hex(cp["alg"], _canonical(attested))

    anchor_err = _verify_anchors(
        container, entries_len, hash_at, trust.expect_tsa,
        trust.expect_recorder_key, trust.trusted_recorder_keys)
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

    signature = container.get("signature")
    if signature is None:
        if trust.bundle_pinned:
            return False, ("bundle is unsigned but a trusted key was "
                           "required - refusing to verify")
        return True, None
    if signature.get("algorithm") != "ed25519":
        return False, (f"unsupported signature algorithm "
                       f"{signature.get('algorithm')!r}")
    for field, shape in (("public_key", _HEX64), ("signature", _HEX128)):
        value = signature.get(field)
        if not isinstance(value, str) or not shape.fullmatch(value):
            return False, f"signature.{field} is not a hex string"
    if "key_id" in signature and not _derived_key_id(signature):
        return False, "signature key_id does not derive from its public_key"
    if (trust.expect_key is not None
            and not _same_key(signature["public_key"], trust.expect_key)):
        return False, "signature public_key is not the trusted key"
    if (trust.trusted_bundle_keys is not None
            and not _key_in(signature["public_key"], trust.trusted_bundle_keys)):
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
    if "anchors" in container:
        signed_body["anchors"] = container["anchors"]
    red = {str(i): sorted(m) for i, m in (markers or {}).items()
           if isinstance(m, list) and m}
    if red:  # bind the redaction set: a marker added after signing breaks this
        signed_body["redactions"] = red
    if not _ed25519_verify(signature["public_key"], _canonical(signed_body),
                           signature["signature"]):
        return False, "signature check failed - bundle altered after signing"
    return True, None


JSONL_FORMAT = "bitexact-bundle-jsonl/1"


def verify_jsonl(lines, expect_key: str | None = None,
                 expect_recorder_key: str | None = None,
                 trusted_bundle_keys: list | None = None,
                 trusted_recorder_keys: list | None = None,
                 expect_tsa: str | None = None):
    """Streaming verification of the JSONL bundle form.

    `lines` is any iterable of text lines: header first, then one entry
    per line. Entries are verified as they stream and never held
    together - the GB-scale path. Returns (ok, error, summary) where
    summary carries steps/signed/redacted counts. Total: hostile input
    is a failed verification, never an exception."""
    try:
        return _verify_jsonl(lines, Trust(
            expect_key, expect_recorder_key, trusted_bundle_keys,
            trusted_recorder_keys, expect_tsa))
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
    needed = {cp.get("steps", 0) - 1 for cp in checkpoints
              if cp.get("steps", 0) > 0}
    needed |= {a.get("steps", 0) - 1 for a in header.get("anchors", [])
               if isinstance(a.get("steps"), int)
               and not isinstance(a.get("steps"), bool)
               and a.get("steps", 0) > 0}
    captured: dict[int, str] = {}
    markers: dict[int, list] = {}
    claims = []
    prev = GENESIS
    count = 0
    redacted = 0
    run_end_at = None
    mix = {"observed": 0, "asserted": 0, "synthetic": 0}
    injected = 0
    for i, (number, line) in enumerate(stream):
        entry = _loads_line(number, line)
        ok, err = _entry_check(entry, i, prev, run_id)
        if not ok:
            return False, err, None
        prev = entry["hash"]
        count = i + 1
        mix[entry["prov"]] += 1
        injected += entry.get("kind") == "injected"
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
            claims.extend((i, t) for t in _redaction_fields(entry))
    if not count:
        return False, ("bundle carries no entries - an empty chain is not "
                       "evidence of a run"), None
    head = prev
    if header.get("chain", {}).get("head_hash") != head:
        return False, "chain head_hash does not match the final entry", None
    err = _redaction_incomplete(claims, markers, count)
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
                           sealed=run_end_at is not None)
    if not ok:
        return False, err, None
    summary = {"steps": count, "signed": "signature" in header,
               "redacted": redacted, "sealed": run_end_at is not None,
               "mix": mix, "injected": injected}
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
    if not isinstance(steps, int) or isinstance(steps, bool) or steps < 0:
        return "anchor has a non-integer step count"
    if steps > entries_len:
        return (f"anchor attests {steps} steps but the bundle has "
                f"{entries_len} - truncated below an externally anchored "
                f"head")
    if steps > 0 and hash_at(steps - 1) != anchor.get("head_hash"):
        return ("anchor head does not match the bundle chain at the "
                "anchored step")
    return None


def _verify_worm_anchor(anchor, expect_recorder_key, trusted_recorder_keys):
    public = anchor.get("public_key", "")
    if (expect_recorder_key is not None
            and not _same_key(public, expect_recorder_key)):
        return "worm anchor not signed by the trusted recorder key"
    if (trusted_recorder_keys is not None
            and not _key_in(public, trusted_recorder_keys)):
        return "worm anchor not signed by a trusted recorder key"
    attested = {k: anchor.get(k) for k in _WORM_ATTESTED}
    if not _ed25519_verify(public, _canonical(attested),
                           anchor.get("signature", "")):
        return "worm anchor signature invalid"
    if not _derived_key_id(anchor):
        return "worm anchor key_id does not derive from its public_key"
    return None


def _verify_anchors(container, entries_len, hash_at, expect_tsa,
                    expect_recorder_key, trusted_recorder_keys):
    run_id = container.get("run_id")
    for i, anchor in enumerate(container.get("anchors", [])):
        kind = anchor.get("type")
        if kind == "worm":
            err = _verify_worm_anchor(anchor, expect_recorder_key,
                                      trusted_recorder_keys)
        elif kind == "rfc3161":
            err = _verify_rfc3161_anchor(anchor, expect_tsa)
        else:
            err = f"unknown anchor type {kind!r}"
        if err is None:
            err = _anchor_binding(anchor, run_id, entries_len, hash_at)
        if err is not None:
            return f"anchor {i}: {err}"
    return None


def _verify_rfc3161_anchor(anchor, expect_tsa):
    if "hash_alg" in anchor and anchor.get("hash_alg") != "sha256":
        return (f"rfc3161 anchor declares hash_alg {anchor.get('hash_alg')!r} "
                f"- only sha256 is defined for the message imprint")
    try:
        token = base64.b64decode(anchor.get("token", ""), validate=True)
    except Exception:
        return "rfc3161 anchor token is not valid base64"
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
                    trusted_recorder_keys=None, expect_tsa=None):
    """Verify a DSSE envelope carrying an in-toto statement whose
    predicate is a bundle; returns (ok, error, bundle_or_none).

    Total: hostile input of any shape is a failed verification, never an
    exception."""
    try:
        return _verify_envelope(envelope, Trust(
            expect_key, expect_recorder_key, trusted_bundle_keys,
            trusted_recorder_keys, expect_tsa))
    except RuntimeError as exc:
        return False, str(exc), None
    except Exception as exc:
        return False, f"malformed envelope: {exc!r}", None


def _dsse_accepted_payload(envelope, expect_key, trusted_bundle_keys):
    """The signed payload bytes of a DSSE envelope, if a signature by an
    acceptable key verifies over it. Returns (payload, None) or (None, error).
    Shared by the run-bundle envelope and the provenance graph attestation so
    the key-acceptance rule cannot drift between them."""
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        return None, f"unsupported payloadType {envelope.get('payloadType')!r}"
    try:
        payload = base64.b64decode(envelope.get("payload", ""), validate=True)
    except Exception:
        return None, "payload is not valid base64"
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
                return None, ("signature keyid does not match its "
                              "public_key")
            return payload, None
    return None, ("signature verification failed - no acceptable signature "
                  "over the payload")


def _verify_envelope(envelope, trust):
    payload, err = _dsse_accepted_payload(envelope, trust.expect_key,
                                          trust.trusted_bundle_keys)
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
                             expect_tsa=None):
    """Verify a BagIt provenance bag: bag integrity, each member run's bundle,
    and every fork edge (its prefix hash re-derived from the parent's own
    verified entries in the bag). Returns (ok, error, summary_or_none).

    Total: hostile input of any shape is a failed verification, never an
    exception."""
    try:
        return _verify_provenance_bundle(bag_dir, Trust(
            expect_key, expect_recorder_key, trusted_bundle_keys,
            trusted_recorder_keys, expect_tsa))
    except RuntimeError as exc:
        return False, str(exc), None
    except OSError as exc:
        name = getattr(exc, "filename", None)
        return False, (f"cannot read {Path(name).name}: {exc.strerror}"
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


def _verify_provenance_bundle(bag_dir, trust):
    bag = Path(bag_dir)
    decl = bag / "bagit.txt"
    if not decl.is_file() or not decl.read_text(
            encoding="utf-8").startswith("BagIt-Version:"):
        return False, "not a BagIt bag - missing or malformed bagit.txt", None

    manifest_path = bag / "manifest-sha256.txt"
    if not manifest_path.is_file():
        return False, "missing manifest-sha256.txt", None
    listed = _read_manifest(manifest_path)
    data = bag / "data"
    present = ({p.relative_to(bag).as_posix()
                for p in data.rglob("*") if p.is_file()}
               if data.is_dir() else set())
    if set(listed) != present:
        return False, ("bag payload does not match manifest-sha256.txt - "
                       "files were added or removed"), None
    for rel, digest in listed.items():
        if _sha256_file(bag / rel) != digest:
            return False, f"payload file {rel} fails its sha256 checksum", None

    tag_path = bag / "tagmanifest-sha256.txt"
    if not tag_path.is_file():
        return False, "missing tagmanifest-sha256.txt", None
    for name, digest in _read_manifest(tag_path).items():
        if _sha256_file(bag / name) != digest:
            return False, f"tag file {name} fails its sha256 checksum", None

    graph_path = data / "provenance-graph.json"
    if not graph_path.is_file():
        return False, "missing data/provenance-graph.json", None
    graph = _loads(graph_path.read_text(encoding="utf-8"))
    if not isinstance(graph, dict):
        return False, "provenance-graph.json is not a JSON object", None
    if graph.get("format") != GRAPH_FORMAT:
        return False, (f"unsupported provenance graph format "
                       f"{graph.get('format')!r}"), None

    verified = {}
    anchors = []   # any member run's anchors, for the RFC 3161 time-trust caveat
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
            _loads(att.read_text(encoding="utf-8")), graph, verified,
            trust.expect_key, trust.trusted_bundle_keys)
        if err:
            return False, err, None
    # The fork-edge count printed on the OK verdict is DERIVED from the verified
    # node set, never read from the graph's `edges` array - on an unsigned bag
    # that array is attacker-writable, so a doctorer could otherwise print "N
    # run(s), 0 fork edge(s)". _check_edges proves the bag is one tree rooted at
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
                        "anchors": anchors, "sealed": root_sealed}


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
    derived = set()
    for child, entries in verified.items():
        fork = next((e for e in entries if e.get("kind") == "fork"), None)
        data = (fork or {}).get("data") or {}
        if fork is not None and data.get("source_run") in verified:
            derived.add((child, data.get("source_run"), data.get("at_step"),
                         data.get("source_prev_hash")))
    for node in graph.get("nodes", []):
        rid = node.get("run_id")
        expected = "fork" if any(c == rid for c, *_ in derived) else "original"
        if node.get("role") != expected:
            return (f"graph node {rid!r} declares role {node.get('role')!r} "
                    f"but its fork entry makes it {expected!r}")
    listed = set()
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            return "graph edges carry a non-object edge"
        listed.add((edge.get("child"), edge.get("source_run"),
                    edge.get("at_step"), edge.get("source_prev_hash")))
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
        if not isinstance(at, int) or not 0 <= at <= len(parent):
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


def _verify_graph_attestation(envelope, graph, verified, expect_key,
                              trusted_bundle_keys):
    """Verify the signed graph attestation binds exactly this graph and pins
    each run's verified head. Returns an error string, or None on success."""
    payload, err = _dsse_accepted_payload(envelope, expect_key,
                                          trusted_bundle_keys)
    if err:
        return f"attestation {err}"
    statement = _loads(payload)
    if statement.get("predicateType") != GRAPH_PREDICATE_TYPE:
        return f"attestation is not a provenance graph ({statement.get('predicateType')!r})"
    if statement.get("predicate") != graph:
        return "attestation does not sign the provenance graph in the bag"
    for subject in statement.get("subject") or []:
        name = subject.get("name")
        entries = verified.get(name)
        if entries is None:
            return f"attestation names a run {name!r} not present in the bag"
        head = entries[-1]["hash"] if entries else None
        if subject.get("digest", {}).get("head") != head:
            return f"attestation head for {name!r} does not match its verified chain"
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
    return None


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


def license_provenance(container: dict, vendor_key_hex: str) -> str:
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
        return _license_provenance(container, vendor_key_hex)
    except Exception as exc:
        return ("license: unverifiable - malformed license material "
                f"({type(exc).__name__})")


def _license_provenance(container: dict, vendor_key_hex: str) -> str:
    cert = container.get("license_cert")
    if not isinstance(cert, dict):
        return "license: none - no vendor license cert in this bundle"
    signature = cert.get("signature")
    body = {k: v for k, v in cert.items() if k != "signature"}
    if not (isinstance(signature, str)
            and _ed25519_verify(vendor_key_hex, _canonical(body), signature)):
        return "license: INVALID - the vendor signature does not verify"
    detail = (f"license {cert.get('license_id')} for {cert.get('licensee')!r}, "
              f"expires {cert.get('expires')}")
    if _date_passed(cert.get("expires")):
        # Advisory like the rest of this report: a lapsed licence says
        # nothing about the integrity of what was recorded under it.
        detail += " - EXPIRED"
    if cert.get("scope"):
        detail += f", scope {cert['scope']}"
    detail += " - vendor signature OK"

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


def _out(msg: str) -> None:
    """Print a verdict message total on any content. A run_id, path, or error
    is attacker-controlled and unvalidated offline, and stdout under Windows/CI
    is often a legacy code page (cp1252); a lone surrogate OR any non-Latin
    character (CJK, emoji) would otherwise crash the encode and flip a valid
    bundle to FAIL. Escape every non-ASCII byte so the write cannot fail on any
    locale codec."""
    sys.stdout.write(str(msg).encode("ascii", "backslashreplace").decode() + "\n")


class _VersionAction(argparse.Action):
    """Print the release + spec identity verbatim, then exit. Unlike argparse's
    built-in `version` action, this does not reflow the text to the terminal
    width - which would split a token like `bitexact-jcs/1` across a line."""

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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="bitexact-verifier",
        description="Verify a BitExact evidence bundle")
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
    parser.add_argument("--require-sealed", action="store_true",
                        help="fail a bundle whose run is not sealed (an "
                             "unfinished run's end is not attested)")
    args = parser.parse_args(argv)
    try:
        return _verify_cli(args)
    except Exception as exc:  # noqa: BLE001 - totality: the reference CLI
        # renders a verdict and exits nonzero on any input, never a traceback,
        # even where glue code (dispatch, indexing) touches a hostile shape
        # before a verify call. Mirrors the product's blanket verify boundary.
        _out(f"FAIL: {type(exc).__name__}: {exc}")
        return 1


def _verify_cli(args) -> int:
    expect_tsa = None
    if args.expect_tsa:
        try:
            with open(args.expect_tsa, "rb") as f:
                expect_tsa = f.read()
        except OSError as exc:
            _out(f"FAIL: no such file: {args.expect_tsa} ({exc.strerror})")
            return 1

    trusted_bundle_keys = trusted_recorder_keys = None
    if args.trust_file:
        try:
            with open(args.trust_file, encoding="utf-8") as f:
                raw = f.read()  # decode inside the guard: bad UTF-8 is
            trust_doc = _loads(raw)  # a verdict (UnicodeDecodeError is a
                                     # ValueError)
        except OSError as exc:
            _out(f"FAIL: no such file: {args.trust_file} ({exc.strerror})")
            return 1
        except ValueError as exc:
            _out(f"FAIL: trust file is not valid JSON: {exc}")
            return 1
        problem = _validate_trust(trust_doc)
        if problem:
            _out(f"FAIL: {problem}")
            return 1
        if "bundle_keys" in trust_doc:
            trusted_bundle_keys = [k["public_key"]
                                   for k in trust_doc["bundle_keys"]]
        if "recorder_keys" in trust_doc:
            trusted_recorder_keys = [k["public_key"]
                                     for k in trust_doc["recorder_keys"]]

    if not Path(args.bundle).exists():
        _out(f"FAIL: no such file: {args.bundle}")
        return 1
    # Built once. Four dispatch paths repeated the same five keywords, and a
    # pin left out of one of them is a check that silently does not run on
    # that form while the other three still enforce it.
    pins = Trust(args.expect_key, args.expect_recorder_key,
                 trusted_bundle_keys, trusted_recorder_keys, expect_tsa)
    recorder_attested = pins.recorder_pinned
    if Path(args.bundle).is_dir():
        ok, err, summary = verify_provenance_bundle(
            args.bundle, **pins._asdict())
        if ok and args.require_sealed and not summary.get("sealed"):
            _out(f"FAIL: the bundle rooted at {summary['root']!r} is unsealed "
                 f"- its end is not attested and --require-sealed was given")
            return 1
        if ok:
            signed = _signed_word(summary["signed"], pins)
            # Same time-trust caveat the single-bundle path prints: an unpinned
            # RFC 3161 anchor's attested time is untrusted until --expect-tsa.
            note = _tsa_caveat(summary.get("anchors"), expect_tsa)
            _out(f"OK: provenance bundle rooted at {summary['root']!r} - "
                  f"{summary['runs']} run(s), {summary['edges']} fork "
                  f"edge(s), graph verified, {signed}{note}")
            if args.vendor_key:
                # The same licence report the single-bundle form prints: an
                # auditor handed a pack asks the same question of it. Read
                # from the bag that has just verified, so the line describes
                # evidence the verdict above already stands behind.
                root = _bag_root_bundle(Path(args.bundle), summary["root"])
                if root is not None:
                    _out(license_provenance(root, args.vendor_key))
            return 0
        _out(f"FAIL: {err}")
        return 1

    with open(args.bundle, encoding="utf-8") as f:
        try:
            # The header is the first NON-BLANK line: the spec says blank
            # lines between records are skipped, and that has to include the
            # ones before the header.
            first = f.readline()
            while first and not first.strip():
                first = f.readline()
        except UnicodeDecodeError as exc:  # hostile bytes are a verdict
            _out(f"FAIL: bundle is not valid JSON: {exc}")
            return 1
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
                _out("FAIL: bundle is unsealed - its end is not attested "
                     "and --require-sealed was given")
                return 1
            if ok:
                signed = _signed_word(summary["signed"], pins)
                note = _redaction_note(summary["redacted"], summary["signed"],
                                       recorder_attested)
                note += _anchor_note(first_doc.get("anchors"))
                note += _tsa_caveat(first_doc.get("anchors"), expect_tsa)
                _out(f"OK: {first_doc.get('run_id')} - "
                      f"{summary['steps']} steps"
                      f"{_mix_text(summary['mix'], summary['injected'])}, "
                      f"chain verified, "
                      f"{_seal_word(summary['sealed'])}, {signed}"
                      f"{_attested(recorder_attested)}{note} (jsonl, streamed)")
                if args.vendor_key:
                    _out(license_provenance(first_doc, args.vendor_key))
                return 0
            _out(f"FAIL: {err}")
            return 1
        f.seek(0)
        try:
            bundle = _loads(f.read())
        except ValueError as exc:
            _out(f"FAIL: bundle is not valid JSON: {exc}")
            return 1
    if isinstance(bundle, dict) and "payloadType" in bundle:
        ok, err, inner = verify_envelope(
            bundle, **pins._asdict())
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
            _out("FAIL: bundle is unsealed - its end is not attested and "
                 "--require-sealed was given")
            return 1
        signed = _signed_word(bool(bundle.get("signature")), pins)
        marks = [e.get("redacted") for e in entries]
        redacted = sum(len(r) if isinstance(r, list) else 1
                       for r in marks if r)
        note = _redaction_note(redacted, bool(bundle.get("signature")),
                               recorder_attested)
        note += _anchor_note(bundle.get("anchors"))
        note += _tsa_caveat(bundle.get("anchors"), expect_tsa)
        mix = {"observed": 0, "asserted": 0, "synthetic": 0}
        for e in entries:
            mix[e.get("prov")] += 1
        injected = sum(e.get("kind") == "injected" for e in entries)
        _out(f"OK: {bundle.get('run_id')} - {n} steps"
              f"{_mix_text(mix, injected)}, chain verified, "
              f"{_seal_word(sealed)}, {signed}"
              f"{_attested(recorder_attested)}{note}")
        if args.vendor_key:
            _out(license_provenance(bundle, args.vendor_key))
        return 0
    _out(f"FAIL: {err}")
    return 1


def _signed_word(signed: bool, pins: "Trust") -> str:
    """The signature's verdict, scoped to what it proved.

    With no key pinned, the signature is checked against the public key the
    bundle carries, which proves only that whoever produced these bytes held
    SOME key - anyone can re-sign an altered bundle under their own. So an
    unpinned signature says so, the way an unpinned RFC 3161 time does."""
    if not signed:
        return "unsigned"
    if pins.bundle_pinned:
        return "signed"
    return ("signed (signing key not pinned - pass --expect-key to know "
            "whose signature it is)")


def _mix_text(mix: dict, injected: int) -> str:
    """What the verified entries are made of. The provenance class is inside
    each entry's hash, so this is proven, not read off a label; a synthetic
    entry is a marked counterfactual and the verdict says so."""
    text = (f" (observed {mix['observed']} / asserted {mix['asserted']} / "
            f"synthetic {mix['synthetic']})")
    if injected:
        text += (f", {injected} injected response(s) - a counterfactual, "
                 f"not recorded traffic")
    return text


def _redaction_note(redacted: int, signed: bool, recorder_attested: bool) -> str:
    """The redaction count, with a demand for a signature only where nothing
    attests the redaction: at the recorder tier an unaccountable strip was
    refused before this line could print, so the recorder has attested it."""
    if not redacted:
        return ""
    note = f", {redacted} field(s) redacted"
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
        parts.append(f"{counts['worm']} worm anchor(s)")
    if counts.get("rfc3161"):
        parts.append(f"{counts['rfc3161']} RFC 3161 timestamp(s)")
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
