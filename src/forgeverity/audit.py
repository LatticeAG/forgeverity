"""Hash-chained VisReceipt-style audit (spec section 8) and trust snapshots.

entry_hash = D(UTF8("forgeverity.audit.v1\\n") || J(AuditBody))
signature  = Ed25519(key, UTF8("forgeverity.receipt.v1\\n") || digest_bytes(entry_hash))
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .canonical import B, D, J, b64u_decode, b64u_encode
from .errors import ApiError, VerifyError
from .ids import new_id

AUDIT_HASH_DOMAIN = b"forgeverity.audit.v1\n"
RECEIPT_SIGN_DOMAIN = b"forgeverity.receipt.v1\n"
ORIGIN_SIGN_DOMAIN = b"forgeverity.origin.v1\n"
GENERATION_SIGN_DOMAIN = b"forgeverity.generation.v1\n"
TRUST_SIGN_DOMAIN = b"forgeverity.trust.v1\n"

JOB_LIFECYCLE_EVENTS = (
    "JOB_QUEUED",
    "FILTER_STARTED",
    "SCORE_STARTED",
    "COMMIT_STARTED",
    "JOB_FAILED",
    "JOB_STALE",
    "JOB_CANCELLED",
    "LEASE_RECOVERED",
)
STREAM_CONTROL_EVENTS = ("STREAM_PAUSED", "STREAM_RESUMED")


def sign_bytes(key: Ed25519PrivateKey, message: bytes) -> str:
    return b64u_encode(key.sign(message))


def verify_bytes(public_key: str, signature: str, message: bytes) -> bool:
    try:
        raw_pub = b64u_decode(public_key, 32)
        raw_sig = b64u_decode(signature, 64)
    except ValueError:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(raw_sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_origin(priv: Ed25519PrivateKey, body: dict) -> dict:
    return {"body": body, "signature": sign_bytes(priv, ORIGIN_SIGN_DOMAIN + J(body))}


def verify_origin(signed: dict, public_key: str) -> bool:
    return verify_bytes(public_key, signed["signature"], ORIGIN_SIGN_DOMAIN + J(signed["body"]))


def sign_generation(priv: Ed25519PrivateKey, body: dict) -> dict:
    return {"body": body, "signature": sign_bytes(priv, GENERATION_SIGN_DOMAIN + J(body))}


def verify_generation(signed: dict, public_key: str) -> bool:
    return verify_bytes(public_key, signed["signature"], GENERATION_SIGN_DOMAIN + J(signed["body"]))


def trust_payload(snapshot: dict) -> bytes:
    """The signed bytes of a trust snapshot: domain + JCS of the snapshot
    without either signature field."""
    body = {k: v for k, v in snapshot.items() if k not in ("old_signature", "new_signature")}
    return TRUST_SIGN_DOMAIN + J(body)


def sign_trust(priv: Ed25519PrivateKey, snapshot_body: dict) -> str:
    return sign_bytes(priv, TRUST_SIGN_DOMAIN + J(snapshot_body))


def verify_trust_sig(public_key: str, signature: str, snapshot: dict) -> bool:
    return verify_bytes(public_key, signature, trust_payload(snapshot))


def make_origin_assertion(body_fields: dict, priv: Ed25519PrivateKey) -> dict:
    """Build {v:fv.origin/1,...} body fields and return the SignedOrigin."""
    body = {"v": "fv.origin/1", "origin": "human_attested", **body_fields}
    return sign_origin(priv, body)


def make_generation_assertion(body_fields: dict, priv: Ed25519PrivateKey) -> dict:
    body = {"v": "fv.generation/1", "generator": "ForgeDistill", **body_fields}
    return sign_generation(priv, body)


def make_trust_snapshot(
    *,
    project_id: str,
    receipt_root: dict,
    sources: list[dict],
    generators: list[dict],
    previous_hash: str | None,
    new_priv: Ed25519PrivateKey,
    old_priv: Ed25519PrivateKey | None = None,
) -> dict:
    """Assemble and dual-sign a TrustSnapshot. For the initial snapshot pass
    previous_hash=None and old_priv=None; later snapshots need both."""
    snapshot = {
        "v": "fv.trust/1",
        "project_id": project_id,
        "receipt_root": receipt_root,
        "sources": sorted(sources, key=lambda s: s["source_id"]),
        "generators": sorted(generators, key=lambda k: k["id"]),
        "previous_hash": previous_hash,
        "old_signature": None,
        "new_signature": None,
    }
    payload = {k: v for k, v in snapshot.items() if k not in ("old_signature", "new_signature")}
    if old_priv is not None:
        snapshot["old_signature"] = sign_trust(old_priv, payload)
    snapshot["new_signature"] = sign_trust(new_priv, payload)
    return snapshot


def entry_hash(body: dict) -> str:
    return D(AUDIT_HASH_DOMAIN + J(body))


def sign_receipt(priv: Ed25519PrivateKey, hash_digest: str) -> str:
    return sign_bytes(priv, RECEIPT_SIGN_DOMAIN + bytes.fromhex(hash_digest[7:]))


def verify_receipt_sig(public_key: str, signature: str, hash_digest: str) -> bool:
    return verify_bytes(public_key, signature, RECEIPT_SIGN_DOMAIN + bytes.fromhex(hash_digest[7:]))


def lifecycle_subject(job_id: str, from_state: str | None, to_state: str, fence: int) -> str:
    return B({"job_id": job_id, "from_state": from_state, "to_state": to_state, "fence": fence})


def stream_control_subject(stream_id: str, state: str, revision: int, reason: str) -> str:
    return B({"stream_id": stream_id, "state": state, "revision": revision, "reason": reason})


def consumption_subject(consumption_body: dict) -> str:
    """B({v,id,request,at_ms}) — receipt_hash omitted to avoid a cycle."""
    return B({k: consumption_body[k] for k in ("v", "id", "request", "at_ms")})


def checkpoint_subject(tip_seq: int, tip_hash: str) -> str:
    return B({"seq": tip_seq, "entry_hash": tip_hash})


def migrated_subject(from_version: int, to_version: int, before_tip: dict, after_schema_hash: str) -> str:
    return B(
        {
            "from_version": from_version,
            "to_version": to_version,
            "before_tip": before_tip,
            "after_schema_hash": after_schema_hash,
        }
    )


def make_event_data(
    *,
    job_id: str | None = None,
    stream_id: str | None = None,
    from_state: str | None = None,
    to_state: str | None = None,
    reasons: list[str] | None = None,
    revision: int | None = None,
) -> dict:
    return {
        "job_id": job_id,
        "stream_id": stream_id,
        "from_state": from_state,
        "to_state": to_state,
        "reasons": reasons or [],
        "revision": revision,
    }


def make_entry(
    *,
    seq: int,
    previous_hash: str | None,
    at_ms: int,
    event: str,
    subject_hash: str,
    data: dict,
    key_id: str,
    project_id: str,
    signer: Ed25519PrivateKey,
    entry_id: str | None = None,
) -> dict:
    body = {
        "v": "fv.audit/1",
        "entry_id": entry_id or new_id("fvent_"),
        "project_id": project_id,
        "seq": seq,
        "previous_hash": previous_hash,
        "at_ms": at_ms,
        "event": event,
        "subject_hash": subject_hash,
        "data": data,
        "key_id": key_id,
    }
    digest = entry_hash(body)
    return {"body": body, "entry_hash": digest, "signature": sign_receipt(signer, digest)}


def find_key(keys: list[dict], key_id: str, purpose: str | None = None) -> dict | None:
    for k in keys:
        if k["id"] == key_id and (purpose is None or k["purpose"] == purpose):
            return k
    return None


def key_valid_at(key: dict, at_ms: int) -> bool:
    """Half-open validity: valid_from <= at < valid_until; revocation does not
    erase historical validity (checked separately for new writes)."""
    return key["valid_from_ms"] <= at_ms < key["valid_until_ms"]


def key_usable_for_write(key: dict, now_ms: int) -> bool:
    if not key_valid_at(key, now_ms):
        return False
    if key["revoked_at_ms"] is not None and now_ms >= key["revoked_at_ms"]:
        return False
    return True


def trust_generator_key(snapshot: dict, key_id: str) -> dict | None:
    for k in snapshot["generators"]:
        if k["id"] == key_id:
            return k
    return None


def trust_source_key(snapshot: dict, source_id: str, key_id: str) -> dict | None:
    for entry in snapshot["sources"]:
        if entry["source_id"] == source_id and entry["key"]["id"] == key_id:
            return entry["key"]
    return None


def verify_trust_chain(snapshots: list[dict], pinned_root: dict) -> bool:
    """Walk the snapshot chain from the pinned root.

    The first snapshot must have null previous_hash/old_signature and a
    new_signature valid under the pinned root; each later snapshot needs
    old_signature under the preceding root plus new_signature under its own.
    """
    if not snapshots:
        return False
    first = snapshots[0]
    if first["previous_hash"] is not None or first["old_signature"] is not None:
        return False
    if first["receipt_root"]["id"] != pinned_root["id"]:
        return False
    if first["receipt_root"]["public_key"] != pinned_root["public_key"]:
        return False
    if not verify_trust_sig(pinned_root["public_key"], first["new_signature"], first):
        return False
    prev = first
    for snap in snapshots[1:]:
        if snap["previous_hash"] != B(prev) or snap["old_signature"] is None:
            return False
        if not verify_trust_sig(prev["receipt_root"]["public_key"], snap["old_signature"], snap):
            return False
        if not verify_trust_sig(snap["receipt_root"]["public_key"], snap["new_signature"], snap):
            return False
        prev = snap
    return True


def verify_receipt(
    receipt: dict,
    key_lookup,
    *,
    err=VerifyError,
) -> bool:
    """Verify one receipt's hash and signature.

    key_lookup(body) -> KeyRecord|None resolves the signing key (must be
    valid at body.at_ms). Raises err(code) on failure."""
    body = receipt["body"]
    if entry_hash(body) != receipt["entry_hash"]:
        raise err("HASH_MISMATCH", "Audit entry hash does not match its body.")
    key = key_lookup(body)
    if key is None:
        raise err("TRUST_MISMATCH", "Receipt signing key is not pinned.")
    if not key_valid_at(key, body["at_ms"]):
        raise err("TRUST_MISMATCH", "Receipt key was not valid at event time.")
    if not verify_receipt_sig(key["public_key"], receipt["signature"], receipt["entry_hash"]):
        raise err("SIGNATURE_INVALID", "Receipt signature verification failed.")
    return True


def public_key_of(priv: Ed25519PrivateKey) -> str:
    return b64u_encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
