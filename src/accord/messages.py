"""Accord version 1 wire messages.

This module implements the closed wire grammar in spec/protocol.json:
strict JSON parse, RFC 8785 canonical encoding, byte limits, base64url
rules and Ed25519 (PureEdDSA, RFC 8032 section 5.1) signature checks.

It does no network, clock or file access.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Callable

try:  # The verifier is optional at import time so that a missing package
    # gives unknown evidence instead of a crash.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    VERIFIER_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the package
    InvalidSignature = Exception  # type: ignore[assignment,misc]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]
    VERIFIER_AVAILABLE = False


class Rejected(Exception):
    """The bytes or the message break a grammar rule. The message has no effect."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Unavailable(Exception):
    """Verification cannot run, for example a pinned role key is absent."""


# ---------------------------------------------------------------------------
# Grammar constants. These mirror spec/protocol.json; a test compares them.

MAX_SIGNED_MESSAGE_BYTES = 4096
MAX_EVENT_DECODED_BYTES = 4096
MAX_EVENT_BYTES_CHARS = 5462
MAX_WIRE_BYTES = 8192  # ENTRY, the largest kind limit, bounds any wire message.
UINT_MAX = 9007199254740991

KIND_BYTE_LIMITS = {
    "RESPONSE": 512,
    "PROPOSE": 4096,
    "MANDATE": 2048,
    "ACCEPT": 1024,
    "REVOKE": 1024,
    "CONDITION": 1024,
    "FORM": 1024,
    "ABORT": 1024,
    "OUTCOME": 1024,
    "COVERAGE": 1024,
    "SESSION": 2048,
    "ENTRY": 8192,
    "CHECKPOINT": 2048,
}

COMMON_FIELDS = {
    "version": {"const": 1},
    "session": "id",
    "id": "id",
    "signer": "id",
    "kind": "kind",
    "tick": "uint",
    "signature": "signature",
}

RESPONSE_WORDS = ["VETO", "ACCEPTABLE", "PREFERRED", "COUNTER", "CONDITIONAL", "DEFER", "ASK_HUMAN"]

MESSAGES: dict[str, dict[str, dict[str, Any]]] = {
    "SESSION": {
        "required": {
            "nonce": "id",
            "principals": "pair",
            "agents": "pair",
            "proposer": "id",
            "log_operator": "id",
            "referee": "id|null",
            "catalog_digest": "digest",
            "start": "uint",
            "expiry": "uint",
        },
        "optional": {},
    },
    "PROPOSE": {
        "required": {
            "proposal_id": "id",
            "revision": "positive",
            "previous": "digest|null",
            "terms": "id",
            "conditions": "conditions",
            "obligations": "obligations",
            "expiry": "uint",
            "mode": {"enum": ["direct", "referee"]},
            "referee": "id|null",
        },
        "optional": {},
    },
    "MANDATE": {
        "required": {
            "principal": "id",
            "agent": "id",
            "setup_digest": "digest",
            "terms": "ids",
            "action": {"enum": ["accept", "perform"]},
            "actions": "ids",
            "max_quantity": "positive",
            "start": "uint",
            "expiry": "uint",
            "revocation_id": "id",
        },
        "optional": {},
    },
    "RESPONSE": {
        "required": {
            "digest": "digest",
            "response": {"enum": RESPONSE_WORDS},
            "expiry": "uint",
            "confidence": {"const": "unspecified"},
        },
        "optional": {
            "comparison_digest": "digest",
            "counter_digest": "digest",
            "condition_ids": "ids",
            "retry_round": "positive",
        },
    },
    "ACCEPT": {
        "required": {"digest": "digest", "mandate": "id", "expiry": "uint"},
        "optional": {},
    },
    "REVOKE": {
        "required": {"target_kind": {"enum": ["MANDATE", "ACCEPT"]}, "target": "id"},
        "optional": {},
    },
    "CONDITION": {
        "required": {"digest": "digest", "condition": "id", "value": "boolean"},
        "optional": {},
    },
    "FORM": {
        "required": {"digest": "digest", "accept_ids": "accept_pair"},
        "optional": {},
    },
    "ABORT": {
        "required": {"digest": "digest"},
        "optional": {},
    },
    "OUTCOME": {
        "required": {
            "digest": "digest",
            "obligation": "id",
            "debtor": "id",
            "action": "id",
            "quantity": "uint",
            "completed_tick": "uint",
            "status": {"enum": ["done", "partial", "missed"]},
        },
        "optional": {},
    },
    "COVERAGE": {
        "required": {
            "digest": "digest",
            "obligation": "id",
            "start": "uint",
            "cutoff": "uint",
            "quantity": "uint",
            "complete": {"const": True},
            "exclusive": {"const": True},
        },
        "optional": {},
    },
    "ENTRY": {
        "required": {"sequence": "positive", "previous": "digest|null", "event_bytes": "event_bytes"},
        "optional": {},
    },
    "CHECKPOINT": {
        "required": {
            "last_sequence": "positive",
            "last_entry_digest": "digest",
            "start": "uint",
            "cutoff": "uint",
            "formation_complete": {"const": True},
        },
        "optional": {},
    },
}

_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_SIG_RE = re.compile(r"[A-Za-z0-9_-]{86}")
_KEY_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_B64_RE = re.compile(r"[A-Za-z0-9_-]*")


# ---------------------------------------------------------------------------
# base64url


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: Any, max_decoded: int | None = None) -> bytes:
    """Decode canonical unpadded base64url. Reject any other form."""
    if not isinstance(text, str) or _B64_RE.fullmatch(text) is None or len(text) % 4 == 1:
        raise Rejected("base64url")
    if max_decoded is not None and len(text) > (max_decoded * 4 + 2) // 3:
        raise Rejected("byte_limit")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url_encode(data) != text:
        raise Rejected("base64url_noncanonical")
    if max_decoded is not None and len(data) > max_decoded:
        raise Rejected("byte_limit")
    return data


# ---------------------------------------------------------------------------
# Strict JSON and RFC 8785 canonical encoding


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Rejected("duplicate_key")
        out[key] = value
    return out


def _reject_float(_text: str) -> Any:
    raise Rejected("float")


def _reject_constant(_text: str) -> Any:
    raise Rejected("constant")


def loads_strict(data: bytes) -> Any:
    """Parse one UTF-8 JSON value. No BOM, duplicate keys, floats or constants."""
    if not isinstance(data, (bytes, bytearray)):
        raise Rejected("not_bytes")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        raise Rejected("utf8") from None
    if text.startswith("﻿"):
        raise Rejected("bom")
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except Rejected:
        raise
    except (ValueError, RecursionError):
        raise Rejected("json") from None


def _canon_string(value: str) -> str:
    # RFC 8785 uses the ECMAScript JSON.stringify string form. For valid
    # Unicode this equals json.dumps with ensure_ascii=False: short escapes for
    # \b \f \n \r \t, lowercase \u00XX for other control characters, and all
    # other characters literal.
    out = json.dumps(value, ensure_ascii=False)
    try:
        out.encode("utf-8")
    except UnicodeEncodeError:
        raise Rejected("unicode") from None
    return out


def _canon(value: Any, parts: list[str]) -> None:
    if value is None:
        parts.append("null")
    elif value is True:
        parts.append("true")
    elif value is False:
        parts.append("false")
    elif type(value) is int:
        if not -UINT_MAX <= value <= UINT_MAX:
            raise Rejected("integer_range")
        parts.append(str(value))
    elif type(value) is str:
        parts.append(_canon_string(value))
    elif type(value) is list:
        parts.append("[")
        for index, item in enumerate(value):
            if index:
                parts.append(",")
            _canon(item, parts)
        parts.append("]")
    elif type(value) is dict:
        parts.append("{")
        for index, key in enumerate(sorted(value, key=lambda k: k.encode("utf-16-be"))):
            if type(key) is not str:
                raise Rejected("key_type")
            if index:
                parts.append(",")
            parts.append(_canon_string(key))
            parts.append(":")
            _canon(value[key], parts)
        parts.append("}")
    else:
        raise Rejected("value_type")


def canonical(value: Any) -> bytes:
    """RFC 8785 canonical JSON bytes for the integer-only value domain of Accord."""
    parts: list[str] = []
    _canon(value, parts)
    return "".join(parts).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unsigned(msg: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in msg.items() if k != "signature"}


def signed_bytes(msg: dict[str, Any]) -> bytes:
    """The bytes a signer signs: canonical JSON without the top-level signature."""
    return canonical(unsigned(msg))


def proposal_digest(msg: dict[str, Any]) -> str:
    """SHA-256 of the unsigned canonical envelope (proposal.digest_fields)."""
    return sha256_hex(signed_bytes(msg))


def event_digest(msg: dict[str, Any]) -> str:
    """SHA-256 of the complete canonical signed envelope."""
    return sha256_hex(canonical(msg))


# ---------------------------------------------------------------------------
# Closed grammar


def _is_uint(v: Any) -> bool:
    return type(v) is int and 0 <= v <= UINT_MAX


def _is_id(v: Any) -> bool:
    return type(v) is str and _ID_RE.fullmatch(v) is not None


def _check_ids(v: Any, lo: int, hi: int, ordered: bool) -> bool:
    if type(v) is not list or not lo <= len(v) <= hi:
        return False
    if not all(_is_id(x) for x in v) or len(set(v)) != len(v):
        return False
    return not ordered or v == sorted(v)


def _check_object_list(v: Any, item: str, lo: int, hi: int) -> bool:
    if type(v) is not list or not lo <= len(v) <= hi:
        return False
    for x in v:
        _check_type(x, item)
    ids = [x["id"] for x in v]
    return len(set(ids)) == len(ids) and ids == sorted(ids)


_OBJECT_TYPES = {
    "condition": {"id": "id", "observer": "id", "predicate": "id"},
    "obligation": {
        "id": "id",
        "debtor": "id",
        "action": "id",
        "quantity": "positive",
        "deadline": "uint",
        "observer": "id",
        "predicate": "id",
    },
}


def _check_type(value: Any, spec: Any) -> None:
    ok: bool
    if isinstance(spec, dict):
        if "const" in spec:
            c = spec["const"]
            ok = type(value) is type(c) and value == c
        else:
            ok = type(value) is str and value in spec["enum"]
    elif "|" in spec:
        for part in spec.split("|"):
            if part == "null":
                if value is None:
                    return
                continue
            try:
                _check_type(value, part)
                return
            except Rejected:
                continue
        ok = False
    elif spec == "id":
        ok = _is_id(value)
    elif spec == "kind":
        ok = type(value) is str and value in MESSAGES
    elif spec == "digest":
        ok = type(value) is str and _DIGEST_RE.fullmatch(value) is not None
    elif spec == "signature":
        ok = type(value) is str and _SIG_RE.fullmatch(value) is not None
        if ok:
            b64url_decode(value)  # rejects a noncanonical final character
    elif spec == "uint":
        ok = _is_uint(value)
    elif spec == "positive":
        ok = _is_uint(value) and value >= 1
    elif spec == "boolean":
        ok = type(value) is bool
    elif spec == "ids":
        ok = _check_ids(value, 0, 8, True)
    elif spec in ("pair", "accept_pair"):
        ok = _check_ids(value, 2, 2, False)
    elif spec in _OBJECT_TYPES:
        fields = _OBJECT_TYPES[spec]
        ok = type(value) is dict and set(value) == set(fields)
        if ok:
            for name, sub in fields.items():
                _check_type(value[name], sub)
    elif spec == "conditions":
        ok = _check_object_list(value, "condition", 0, 8)
    elif spec == "obligations":
        ok = _check_object_list(value, "obligation", 1, 8)
    elif spec == "event_bytes":
        ok = type(value) is str and len(value.encode("utf-8")) <= MAX_EVENT_BYTES_CHARS
        if ok:
            b64url_decode(value, MAX_EVENT_DECODED_BYTES)
    else:  # pragma: no cover - a grammar table defect
        raise AssertionError(f"unknown type {spec!r}")
    if not ok:
        raise Rejected(f"type:{spec}")


def validate(msg: Any) -> None:
    """Check one parsed message against the closed grammar. Raise Rejected."""
    if type(msg) is not dict:
        raise Rejected("not_object")
    kind = msg.get("kind")
    if type(kind) is not str or kind not in MESSAGES:
        raise Rejected("kind")
    grammar = MESSAGES[kind]
    required = {**COMMON_FIELDS, **grammar["required"]}
    optional = grammar["optional"]
    for name in msg:
        if name not in required and name not in optional:
            raise Rejected(f"unknown_field:{name}")
    for name, spec in required.items():
        if name not in msg:
            raise Rejected(f"missing_field:{name}")
        _check_type(msg[name], spec)
    for name, spec in optional.items():
        if name in msg:
            _check_type(msg[name], spec)


def parse_message(data: bytes, *, max_bytes: int = MAX_WIRE_BYTES) -> dict[str, Any]:
    """Strict parse of one wire message.

    Order: byte limit before parse, strict JSON, closed grammar, the kind byte
    limit, then exact equality with the canonical signed envelope bytes.
    The signature is not verified here; see verify_signature.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise Rejected("not_bytes")
    data = bytes(data)
    if len(data) > max_bytes:
        raise Rejected("byte_limit")
    msg = loads_strict(data)
    validate(msg)
    kind = msg["kind"]
    limit = KIND_BYTE_LIMITS[kind]
    if kind != "ENTRY":
        limit = min(limit, MAX_SIGNED_MESSAGE_BYTES)
    if len(data) > limit:
        raise Rejected("byte_limit")
    if canonical(msg) != data:
        raise Rejected("noncanonical")
    return msg


# ---------------------------------------------------------------------------
# Keys and signatures


def decode_public_key(text: Any) -> bytes:
    if type(text) is not str or _KEY_RE.fullmatch(text) is None:
        raise Rejected("public_key")
    raw = b64url_decode(text)
    if len(raw) != 32:
        raise Rejected("public_key")
    return raw


def verify_signature(msg: dict[str, Any], public_key: bytes) -> bool:
    """Ed25519 verify of the signature over signed_bytes(msg)."""
    if not VERIFIER_AVAILABLE:
        raise Unavailable("cryptography package is not available")
    sig_text = msg.get("signature")
    if type(sig_text) is not str or _SIG_RE.fullmatch(sig_text) is None:
        return False
    try:
        sig = b64url_decode(sig_text)
        payload = signed_bytes(msg)
    except Rejected:
        return False
    if len(sig) != 64:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError:
        raise Unavailable("pinned public key cannot be loaded") from None
    try:
        key.verify(sig, payload)
    except InvalidSignature:
        return False
    return True


KeyLookup = Callable[[str], "bytes | None"]


def authenticate(data: bytes, key_for: KeyLookup) -> tuple[tuple[str, str], bytes] | None:
    """Return ((session, id), signed bytes) when the bytes carry a valid signature.

    This runs before the closed grammar so that an authenticated message-ID
    collision is found even when one copy later fails a grammar or scope rule.
    key_for returns None for a signer with no role and raises Unavailable for
    a pinned role whose key is absent.
    """
    if len(data) > MAX_SIGNED_MESSAGE_BYTES:
        return None
    try:
        obj = loads_strict(data)
    except Rejected:
        return None
    if type(obj) is not dict:
        return None
    session, ident, signer = obj.get("session"), obj.get("id"), obj.get("signer")
    if not (type(session) is str and type(ident) is str and _is_id(signer)):
        return None
    key = key_for(signer)
    if key is None:
        return None
    if not verify_signature(obj, key):
        return None
    return (session, ident), signed_bytes(obj)
