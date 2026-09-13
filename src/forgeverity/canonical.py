"""Canonical JSON: strict I-JSON decode, RFC8785 JCS encode, digests, base64url.

J(x) is the RFC8785 UTF-8 byte encoding. B(x) = "sha256:" + hex(SHA256(J(x))).
D(bytes) = "sha256:" + hex(SHA256(bytes)). Wire numbers are integers in the
range [-(2**53 - 1), 2**53 - 1]; exponent-form integers and -0 decode then
canonicalize. Duplicate keys, unpaired surrogates, invalid UTF-8, BOM, NaN,
Infinity, non-integral numbers, and out-of-range integers are decode errors.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from decimal import Decimal

from .errors import ApiError

INT_MIN = -(2**53 - 1)
INT_MAX = 2**53 - 1
MAX_JSON_DEPTH = 16
MAX_BODY_BYTES = 33554432

Digest = str


class _DuplicateKey(ValueError):
    pass


class _UnsafeNumber(ValueError):
    pass


class _Depth(ValueError):
    pass


def _parse_int(token: str) -> int:
    value = int(token, 10)
    if value < INT_MIN or value > INT_MAX:
        raise _UnsafeNumber(token)
    return value


def _parse_number(token: str) -> int:
    """Exponent/decimal forms are accepted only when the value is integral."""
    try:
        dec = Decimal(token)
    except Exception as exc:  # pragma: no cover - Decimal is strict already
        raise _UnsafeNumber(token) from exc
    if not dec.is_finite() or dec != dec.to_integral_value():
        raise _UnsafeNumber(token)
    value = int(dec)
    if value < INT_MIN or value > INT_MAX:
        raise _UnsafeNumber(token)
    return value


def _reject_constant(token: str) -> None:
    # NaN / Infinity / -Infinity literals are not I-JSON.
    raise _UnsafeNumber(token)


def decode_json(data: bytes, *, max_depth: int = MAX_JSON_DEPTH) -> object:
    """Strictly decode wire JSON bytes.

    Raises ApiError(400, INVALID_JSON | DUPLICATE_KEY | SCHEMA).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("decode_json expects bytes")
    raw = bytes(data)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ApiError(400, "INVALID_JSON", "UTF-8 BOM is not permitted.")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ApiError(400, "INVALID_JSON", "Body is not valid UTF-8.") from exc

    def pairs_hook(pairs: list) -> dict:
        out: dict = {}
        for key, value in pairs:
            if key in out:
                raise _DuplicateKey(key)
            out[key] = value
        return out

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_int=_parse_int,
            parse_float=_parse_number,
            parse_constant=_reject_constant,
        )
    except _DuplicateKey as exc:
        raise ApiError(400, "DUPLICATE_KEY", f"Duplicate object key: {exc}.") from exc
    except _UnsafeNumber as exc:
        raise ApiError(400, "SCHEMA", f"Number is not a safe integer: {exc}.") from exc
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ApiError(400, "INVALID_JSON", "Body is not well-formed JSON.") from exc

    try:
        _check_value(value, 1, max_depth)
    except _Depth as exc:
        raise ApiError(400, "SCHEMA", f"JSON nesting exceeds depth {max_depth}.") from exc
    except _UnsafeNumber as exc:
        raise ApiError(400, "SCHEMA", str(exc)) from exc
    return value


def _check_value(value: object, depth: int, max_depth: int) -> None:
    if depth > max_depth:
        raise _Depth(depth)
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise _UnsafeNumber("non-string object key")
            _check_string(key)
            _check_value(child, depth + 1, max_depth)
    elif isinstance(value, list):
        for child in value:
            _check_value(child, depth + 1, max_depth)
    elif isinstance(value, str):
        _check_string(value)
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, int):
        if value < INT_MIN or value > INT_MAX:
            raise _UnsafeNumber(f"integer out of range: {value}")
    else:  # float or anything else never survives decode
        raise _UnsafeNumber(f"non-integer number: {value!r}")


def _check_string(text: str) -> None:
    # Reject unpaired surrogates (invalid UTF-8 already rejected).
    for ch in text:
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            raise _UnsafeNumber("unpaired surrogate in string")


def _sort_key_utf16(key: str) -> bytes:
    # RFC8785 sorts object keys by UTF-16 code units.
    return key.encode("utf-16-be", "surrogatepass")


def _escape_string(text: str) -> str:
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        elif 0xD800 <= code <= 0xDFFF:
            raise _UnsafeNumber("unpaired surrogate in string")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonicalize(value: object) -> bytes:
    """RFC8785 JCS canonical UTF-8 bytes of a decoded JSON value."""
    parts: list[str] = []

    def emit(v: object) -> None:
        if v is None:
            parts.append("null")
        elif v is True:
            parts.append("true")
        elif v is False:
            parts.append("false")
        elif isinstance(v, int):
            if v < INT_MIN or v > INT_MAX:
                raise _UnsafeNumber(f"integer out of range: {v}")
            parts.append(str(v))
        elif isinstance(v, str):
            parts.append(_escape_string(v))
        elif isinstance(v, list):
            parts.append("[")
            for i, child in enumerate(v):
                if i:
                    parts.append(",")
                emit(child)
            parts.append("]")
        elif isinstance(v, dict):
            parts.append("{")
            for i, key in enumerate(sorted(v.keys(), key=_sort_key_utf16)):
                if i:
                    parts.append(",")
                parts.append(_escape_string(key))
                parts.append(":")
                emit(v[key])
            parts.append("}")
        else:
            raise TypeError(f"cannot canonicalize {type(v).__name__}")

    emit(value)
    return "".join(parts).encode("utf-8")


def J(value: object) -> bytes:
    return canonicalize(value)


def D(data: bytes) -> Digest:
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


def B(value: object) -> Digest:
    return D(canonicalize(value))


_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str, expected_len: int | None = None) -> bytes:
    """Canonical unpadded base64url decode; rejects padding and non-canonical
    encodings (nonzero unused trailing bits)."""
    if not isinstance(text, str) or not _B64URL_RE.match(text) or "=" in text:
        raise ValueError("not canonical base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise ValueError("invalid base64url") from exc
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError("wrong decoded length")
    if b64u_encode(raw) != text:
        raise ValueError("non-canonical base64url encoding")
    return raw


def is_canonical_body(data: bytes) -> bool:
    """True when the bytes are already the JCS encoding of their value."""
    try:
        return canonicalize(decode_json(data)) == bytes(data)
    except (ApiError, ValueError, TypeError):
        return False
