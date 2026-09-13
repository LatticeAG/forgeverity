"""Key lifecycle (spec sections 5, 10): Ed25519 generation, 0600 file
storage, and the fixture denylist enforced on production trust init."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import J
from .errors import ApiError
from .ids import new_id

# §9.2 fixture seeds — their public keys are public test material and a
# production trust initializer must refuse them (TV-F--63).
FIXTURE_SEEDS = (
    bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    bytes.fromhex("01" * 32),
    bytes.fromhex("02" * 32),
)


def _pub_b64(priv: Ed25519PrivateKey) -> str:
    import base64

    raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def load_private(pem: bytes) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def public_b64(pem: bytes) -> str:
    return _pub_b64(load_private(pem))


def fixture_public_keys() -> set[str]:
    return {_pub_b64(Ed25519PrivateKey.from_private_bytes(s)) for s in FIXTURE_SEEDS}


def generate_key_record(priv: Ed25519PrivateKey, purpose: str, valid_from_ms: int, valid_until_ms: int) -> dict:
    if purpose not in ("receipt", "origin", "generator"):
        raise ApiError(400, "SCHEMA", "purpose must be receipt, origin, or generator.")
    return {
        "id": new_id("fvkey_"),
        "public_key": _pub_b64(priv),
        "purpose": purpose,
        "valid_from_ms": valid_from_ms,
        "valid_until_ms": valid_until_ms,
        "revoked_at_ms": None,
    }


def check_fixture_denied(record: dict, production: bool) -> None:
    if production and record.get("public_key") in fixture_public_keys():
        raise ApiError(403, "TRUST_MISMATCH", "Fixture key material is denied in production mode.")


def save_key(path: str | Path, record: dict, pem: bytes) -> None:
    """Write a key locator file with exclusive creation and mode 0600."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = {"key": record, "private_key_pem": pem.decode("ascii")}
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(J(doc))
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        os.unlink(str(p))
        raise
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)


def load_key(path: str | Path) -> tuple[dict, bytes]:
    """Load a key file; refuse world/group-readable files."""
    p = Path(path)
    mode = p.stat().st_mode & 0o777
    if mode != 0o600:
        raise ApiError(503, "SIGNING_UNAVAILABLE", f"Key file {p} has insecure permissions.")
    doc = json.loads(p.read_bytes())
    return doc["key"], doc["private_key_pem"].encode("ascii")
