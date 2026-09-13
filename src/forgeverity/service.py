"""ForgeVerity service operations — the shared business logic used by the HTTP
API, the CLI, and the internal worker dispatcher.

All state mutations happen inside SQLite immediate transactions; every
mutation appends signed hash-chained audit entries. Only committed state is
authoritative.
"""

from __future__ import annotations

import hmac
import json
import secrets
import sqlite3
import time
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import audit as audit_mod
from .canonical import B, D, J, b64u_decode, b64u_encode, decode_json
from .errors import ApiError, EvaluationError
from .filter import (
    MAX_CANDIDATE_RECORDS,
    filter_candidates,
    near_duplicate,
    record_id_conflicts,
    token_set,
    tokenize,
    validate_candidate_document,
)
from .gate import evaluate
from .ids import new_id, valid_id
from .schema import (
    ARTIFACT_V,
    GENERATED_V,
    SUITES,
    validate_artifact,
    validate_consumption_request,
    validate_decision,
    validate_generation,
    validate_job_cancel_request,
    validate_job_request,
    validate_policy,
    validate_reference,
    validate_reference_register_request,
    validate_signed_origin,
    validate_stream_create_request,
    validate_stream_state_request,
    validate_ticket,
    validate_trust,
)
from .store import ProjectStore, store_object_json

LEASE_MS = 60000
HEARTBEAT_MS = 20000
MAX_ATTEMPTS = 3
GEN_WINDOW_PAST_MS = 300000
GEN_WINDOW_FUTURE_MS = 120000
MAX_BODY_BYTES = 33554432
MUTATIONS_PER_MINUTE = 60
READS_PER_MINUTE = 300
CHAINS_PER_DAY = 20
QUEUE_LIMIT_DEFAULT = 32

CAPABILITIES = {
    "protocol": "fv.http/1",
    "suites": list(SUITES),
    "max_body_bytes": MAX_BODY_BYTES,
    "max_candidate_records": MAX_CANDIDATE_RECORDS,
    "max_corpus_records": 4096,
    "sample_size": 128,
}

# §9.2 fixture private seeds — public keys derived from them are test material
# and MUST be rejected by a production trust initializer.
FIXTURE_SEEDS = (
    bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    bytes.fromhex("01" * 32),
    bytes.fromhex("02" * 32),
)


def fixture_public_keys() -> set[str]:
    return {audit_mod.public_key_of(Ed25519PrivateKey.from_private_bytes(s)) for s in FIXTURE_SEEDS}


class WallClock:
    """Service wall clock with rollback detection (>1000 ms marks the service
    unready until caught up)."""

    def __init__(self):
        self._last = 0
        self.unsafe = False

    def now_ms(self) -> int:
        now = int(time.time() * 1000)
        if self._last and now < self._last - 1000:
            self.unsafe = True
        elif self.unsafe and now >= self._last:
            self.unsafe = False
        self._last = max(self._last, now)
        return self._last if self.unsafe else now


def _job_public(row: dict) -> dict:
    return {
        "v": "fv.job/1",
        "id": row["id"],
        "request": decode_json(row["request_json"].encode("utf-8")),
        "state": row["state"],
        "trust_hash": row["trust_hash"],
        "round": row["round"],
        "total_candidates": row["total_candidates"],
        "attempt": row["attempt"],
        "fence": row["fence"],
        "created_at_ms": row["created_at_ms"],
        "updated_at_ms": row["updated_at_ms"],
        "decision_hash": row["decision_hash"],
        "release_hash": row["release_hash"],
        "receipt_hash": row["receipt_hash"],
        "error": decode_json(row["error_json"].encode("utf-8")) if row["error_json"] else None,
    }


def _stream_public(row: dict) -> dict:
    return {
        "v": "fv.stream/1",
        "id": row["id"],
        "project_id": row["project_id"],
        "state": row["state"],
        "revision": row["revision"],
        "policy_hash": row["policy_hash"],
        "reference_hash": row["reference_hash"],
        "head_release_hash": row["head_release_hash"],
    }


class Service:
    """Per-project ForgeVerity service.

    clock: callable returning service wall-clock ms.
    id_allocator: callable(prefix) -> id (CSPRNG default; tests may inject a
        deterministic allocator, which also requires testing=True).
    key_resolver: callable(key_id) -> Ed25519PrivateKey | None, used to load
        the active receipt signing key.
    pepper: bytes used for token digests and pagination cursors.
    testing: permits fixture keys and injected allocators; production code
        paths must never set it.
    """

    def __init__(
        self,
        store: ProjectStore,
        *,
        clock=None,
        id_allocator=None,
        key_resolver=None,
        pepper: bytes | None = None,
        testing: bool = False,
        limits: dict | None = None,
    ):
        self.store = store
        self._wall = WallClock() if clock is None else None
        self.clock = clock or self._wall.now_ms
        if id_allocator is not None and not testing:
            raise ValueError("deterministic ID allocators are test-only")
        self._alloc = id_allocator or new_id
        self._resolve_key = key_resolver or (lambda key_id: None)
        self.pepper = pepper if pepper is not None else b"\x00" * 32
        self.testing = testing
        self.limits = limits or {}

    # ---- basics ------------------------------------------------------------

    def now(self) -> int:
        return int(self.clock())

    def _require_trust(self) -> dict:
        cur = self.store.current_trust()
        if cur is None:
            raise ApiError(503, "STORAGE_UNAVAILABLE", "Project trust is not initialized.")
        return cur

    def _receipt_key_record(self, trust: dict) -> dict:
        return trust["snapshot"]["receipt_root"]

    def _signer(self, key_id: str) -> Ed25519PrivateKey:
        key = self._resolve_key(key_id)
        if key is None:
            raise ApiError(500, "SIGNING_UNAVAILABLE", "Receipt signing key is unavailable.")
        return key

    def _append_event(self, conn, event: str, subject_hash: str, data: dict) -> dict:
        trust = self._require_trust()
        key_id = self._receipt_key_record(trust)["id"]
        signer = self._signer(key_id)
        tip_seq, tip_hash = self.store.audit_tip(conn)
        receipt = audit_mod.make_entry(
            seq=tip_seq + 1,
            previous_hash=tip_hash,
            at_ms=self.now(),
            event=event,
            subject_hash=subject_hash,
            data=data,
            key_id=key_id,
            project_id=self.store.project_id,
            signer=signer,
            entry_id=self._alloc("fvent_"),
        )
        self.store.append_audit(conn, receipt)
        if event != "CHECKPOINTED":
            # A checkpoint itself never needs a checkpoint task; otherwise the
            # outbox would cascade a new checkpoint per processed task.
            conn.execute(
                "INSERT OR IGNORE INTO outbox(audit_seq, kind, attempts, delivered_at_ms) VALUES (?,?,0,NULL)",
                (receipt["body"]["seq"], "checkpoint"),
            )
        return receipt

    # ---- idempotency ---------------------------------------------------------

    def idem_lookup(self, idem: dict) -> dict | None:
        row = self.store.conn.execute(
            "SELECT request_hash, status, response_json FROM idempotency"
            " WHERE principal=? AND method=? AND path=? AND key=?",
            (idem["principal"], idem["method"], idem["path"], idem["key"]),
        ).fetchone()
        return dict(row) if row else None

    def _consume_idem(self, conn, idem: dict | None, status: int, response) -> None:
        """Store the tombstone in the same transaction as the mutation."""
        if idem is None:
            return
        conn.execute(
            "INSERT INTO idempotency(principal, method, path, key, request_hash, status, response_json, created_at_ms)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                idem["principal"],
                idem["method"],
                idem["path"],
                idem["key"],
                idem["request_hash"],
                status,
                store_object_json(response),
                self.now(),
            ),
        )

    def ready_reasons(self) -> list[str]:
        reasons = []
        if self.store.restored_stale():
            return ["STORAGE_UNAVAILABLE"]
        if self._wall is not None and self._wall.unsafe:
            reasons.append("CLOCK_UNSAFE")
        try:
            self.store.conn.execute("SELECT 1").fetchone()
        except Exception:
            reasons.append("STORAGE_UNAVAILABLE")
            return reasons
        cur = self.store.current_trust()
        if cur is None:
            reasons.append("STORAGE_UNAVAILABLE")
        else:
            key_id = cur["snapshot"]["receipt_root"]["id"]
            if self._resolve_key(key_id) is None:
                reasons.append("SIGNING_UNAVAILABLE")
        return reasons

    # ---- trust -------------------------------------------------------------

    def initialize_trust(self, snapshot: dict) -> str:
        """Install the initial trust snapshot (stopped-service operation)."""
        validate_trust(snapshot)
        if snapshot["project_id"] != self.store.project_id:
            raise ApiError(400, "SCHEMA", "Trust snapshot is bound to a different project.")
        if snapshot["previous_hash"] is not None or snapshot["old_signature"] is not None:
            raise ApiError(400, "SCHEMA", "Initial trust snapshot must have null previous_hash/old_signature.")
        if not audit_mod.verify_trust_sig(
            snapshot["receipt_root"]["public_key"], snapshot["new_signature"], snapshot
        ):
            raise ApiError(403, "SIGNATURE_INVALID", "Trust snapshot self-signature is invalid.")
        if not self.testing:
            fixture_pubs = fixture_public_keys()
            all_keys = [snapshot["receipt_root"]] + [s["key"] for s in snapshot["sources"]] + snapshot["generators"]
            if any(k["public_key"] in fixture_pubs for k in all_keys):
                raise ApiError(403, "TRUST_MISMATCH", "Published fixture keys are forbidden in production.")
        digest = B(snapshot)
        with self.store.tx() as conn:
            existing = self.store.current_trust()
            if existing is not None:
                if existing["digest"] == digest:
                    return digest
                raise ApiError(409, "TERMINAL_STATE", "Trust is already initialized.")
            conn.execute(
                "INSERT INTO trust_snapshots(digest, canonical_json, activation_seq) VALUES (?,?,0)",
                (digest, store_object_json(snapshot)),
            )
        return digest

    def rotate_trust(self, new_snapshot: dict) -> dict:
        """Apply a dual-signed trust rotation (stopped-service operation)."""
        validate_trust(new_snapshot)
        if new_snapshot["project_id"] != self.store.project_id:
            raise ApiError(400, "SCHEMA", "Trust snapshot is bound to a different project.")
        cur = self._require_trust()
        old = cur["snapshot"]
        if new_snapshot["previous_hash"] != B(old):
            raise ApiError(403, "TRUST_MISMATCH", "New snapshot does not chain to the current snapshot.")
        if not audit_mod.verify_trust_sig(
            old["receipt_root"]["public_key"], new_snapshot["old_signature"], new_snapshot
        ):
            raise ApiError(403, "SIGNATURE_INVALID", "Old-root signature on the new snapshot is invalid.")
        if not audit_mod.verify_trust_sig(
            new_snapshot["receipt_root"]["public_key"], new_snapshot["new_signature"], new_snapshot
        ):
            raise ApiError(403, "SIGNATURE_INVALID", "New-root signature on the new snapshot is invalid.")
        if not self.testing:
            fixture_pubs = fixture_public_keys()
            all_keys = (
                [new_snapshot["receipt_root"]]
                + [s["key"] for s in new_snapshot["sources"]]
                + new_snapshot["generators"]
            )
            if any(k["public_key"] in fixture_pubs for k in all_keys):
                raise ApiError(403, "TRUST_MISMATCH", "Published fixture keys are forbidden in production.")
        digest = B(new_snapshot)
        with self.store.tx() as conn:
            # All active jobs are fenced: trust change invalidates pending work.
            stale_jobs = conn.execute(
                "SELECT id, state, fence FROM jobs WHERE state IN ('QUEUED','FILTERING','SCORING','COMMITTING') ORDER BY id"
            ).fetchall()
            tip_seq, _ = self.store.audit_tip(conn)
            activation_seq = tip_seq + 1
            conn.execute(
                "INSERT INTO trust_snapshots(digest, canonical_json, activation_seq) VALUES (?,?,?)",
                (digest, store_object_json(new_snapshot), activation_seq),
            )
            receipt = self._append_event(
                conn,
                "KEY_ROTATED",
                B(new_snapshot),
                audit_mod.make_event_data(),
            )
            for job in stale_jobs:
                self._mark_stale(conn, dict(job))
        return {"trust_hash": digest, "receipt_hash": receipt["entry_hash"]}

    def _mark_stale(self, conn, job: dict) -> dict:
        new_fence = job["fence"] + 1
        receipt = self._append_event(
            conn,
            "JOB_STALE",
            audit_mod.lifecycle_subject(job["id"], job["state"], "STALE", new_fence),
            audit_mod.make_event_data(
                job_id=job["id"],
                stream_id=json.loads(job["request_json"])["stream_id"],
                from_state=job["state"],
                to_state="STALE",
                revision=json.loads(job["request_json"])["expected_revision"],
            ),
        )
        conn.execute(
            "UPDATE jobs SET state='STALE', fence=?, lease_owner=NULL, lease_until_ms=NULL,"
            " receipt_hash=?, updated_at_ms=? WHERE id=?",
            (new_fence, receipt["entry_hash"], receipt["body"]["at_ms"], job["id"]),
        )
        return receipt

    # ---- blobs -------------------------------------------------------------

    def put_blob(self, data: bytes, url_digest: str, uploader_role: str) -> tuple[int, dict]:
        if len(data) > MAX_BODY_BYTES:
            raise ApiError(413, "BODY_LIMIT", "Blob exceeds the body limit.")
        obj = decode_json(data)  # INVALID_JSON / DUPLICATE_KEY / SCHEMA
        validate_artifact(obj, strict_tickets=False)
        if J(obj) != data:
            raise ApiError(400, "NONCANONICAL", "Artifact body must be canonical RFC8785 bytes.")
        digest = D(data)
        if digest != url_digest:
            raise ApiError(422, "HASH_MISMATCH", "URL digest does not match the artifact bytes.")
        tag = "producer" if uploader_role == "producer" else "staff"
        self.store.cas_write(data)
        with self.store.tx() as conn:
            row = self.store.get_blob_row(digest)
            if row is not None and row["committed"]:
                roles = set(json.loads(row["roles"])) | {tag}
                conn.execute("UPDATE blobs SET roles=? WHERE digest=?", (json.dumps(sorted(roles)), digest))
                return 200, {"hash": digest, "kind": "tickets", "bytes": len(data)}
            conn.execute(
                "INSERT INTO blobs(digest, kind, byte_count, path, created_at_ms, uploader_role, roles, committed)"
                " VALUES (?,?,?,?,?,?,?,1)",
                (digest, "tickets", len(data), str(self.store.cas_path(digest)), self.now(), tag, json.dumps([tag])),
            )
        return 201, {"hash": digest, "kind": "tickets", "bytes": len(data)}

    def _commit_object_blob(self, conn, obj: dict, kind: str, roles: list[str]) -> str:
        digest = B(obj)
        data = J(obj)
        self.store.cas_write(data)
        row = self.store.get_blob_row(digest)
        if row is None:
            conn.execute(
                "INSERT INTO blobs(digest, kind, byte_count, path, created_at_ms, uploader_role, roles, committed)"
                " VALUES (?,?,?,?,?,?,?,1)",
                (digest, kind, len(data), str(self.store.cas_path(digest)), self.now(), "staff", json.dumps(sorted(roles))),
            )
        else:
            merged = set(json.loads(row["roles"])) | set(roles)
            conn.execute(
                "UPDATE blobs SET roles=?, committed=1 WHERE digest=?", (json.dumps(sorted(merged)), digest)
            )
        return digest

    def _tag_blob(self, conn, digest: str, roles: list[str]) -> None:
        row = self.store.get_blob_row(digest)
        if row is None:
            return
        merged = set(json.loads(row["roles"])) | set(roles)
        conn.execute("UPDATE blobs SET roles=? WHERE digest=?", (json.dumps(sorted(merged)), digest))

    def blob_allowed_roles(self, row: dict) -> set[str]:
        tags = set(json.loads(row["roles"]))
        if "reference" in tags:
            allowed = {"admin", "auditor"}
            if "corpus" in tags:
                allowed.add("consumer")
            return allowed
        if "corpus" in tags:
            return {"admin", "auditor", "consumer"}
        if "evidence" in tags:
            return {"admin", "producer", "consumer", "viewer", "auditor"}
        allowed = {"admin", "auditor"}
        if "candidate" in tags or row["uploader_role"] == "producer":
            allowed.add("producer")
        return allowed

    def get_blob(self, digest: str, role: str):
        row = self.store.get_blob_row(digest)
        if row is None or not row["committed"]:
            raise ApiError(404, "NOT_FOUND", "Blob not found.")
        if role not in self.blob_allowed_roles(row):
            raise ApiError(404, "NOT_FOUND", "Blob not found.")
        data = self.store.cas_read(digest)
        return decode_json(data)

    # ---- references / policies / streams -----------------------------------

    def _check_partition_overlap(self, a_records: list[dict], b_records: list[dict]) -> bool:
        """True when any cross-partition pair is an exact or near duplicate."""
        index: dict[object, list[tuple[set, int]]] = {}
        exact: set[bytes] = set()
        for rec in a_records:
            toks = tokenize(rec["title"], rec["body"])
            exact.add(J(toks))
            uset = token_set(toks)
            for feat in uset:
                index.setdefault(feat, []).append((uset, len(uset)))
        for rec in b_records:
            toks = tokenize(rec["title"], rec["body"])
            if J(toks) in exact:
                return True
            uset = token_set(toks)
            usize = len(uset)
            seen: set[int] = set()
            for feat in uset:
                for entry in index.get(feat, ()):
                    key = id(entry)
                    if key in seen:
                        continue
                    seen.add(key)
                    aset, asize = entry
                    if 39 * min(usize, asize) < 19 * (usize + asize):
                        continue
                    inter = len(uset & aset)
                    if near_duplicate(inter, usize + asize - inter):
                        return True
        return False

    def _partition_checks(self, artifact: dict) -> None:
        records = artifact["records"]
        if not (32 <= len(records) <= 2048):
            raise ApiError(422, "REFERENCE_INVALID", "Reference partitions must have 32-2048 records.")
        counts: dict[str, int] = {}
        for rec in records:
            counts[rec["category"]] = counts.get(rec["category"], 0) + 1
        if not counts or any(c < 2 for c in counts.values()):
            raise ApiError(422, "REFERENCE_INVALID", "Each partition needs at least two records per category.")
        # No internal near-duplicate pair.
        seen_sets: list[tuple[set, int]] = []
        seen_exact: set[bytes] = set()
        for rec in records:
            toks = tokenize(rec["title"], rec["body"])
            key = J(toks)
            if key in seen_exact:
                raise ApiError(422, "REFERENCE_INVALID", "Reference partition contains an exact duplicate.")
            uset = token_set(toks)
            usize = len(uset)
            for oset, osize in seen_sets:
                if 39 * min(usize, osize) < 19 * (usize + osize):
                    continue
                inter = len(uset & oset)
                if near_duplicate(inter, usize + osize - inter):
                    raise ApiError(422, "REFERENCE_INVALID", "Reference partition contains a near-duplicate pair.")
            seen_sets.append((uset, usize))
            seen_exact.add(key)

    def register_reference(self, body: dict, *, idem: dict | None = None) -> tuple[int, dict]:
        req = validate_reference_register_request(body)
        signed = req["origin"]
        obody = signed["body"]
        if obody["project_id"] != self.store.project_id:
            raise ApiError(422, "REFERENCE_INVALID", "Origin assertion is bound to a different project.")
        trust = self._require_trust()
        key = audit_mod.trust_source_key(trust["snapshot"], obody["source_id"], obody["key_id"])
        if key is None:
            raise ApiError(403, "TRUST_MISMATCH", "Origin signer is not pinned in the project trust snapshot.")
        now = self.now()
        if not audit_mod.key_usable_for_write(key, now):
            raise ApiError(403, "KEY_REVOKED", "Origin key is not usable.")
        if not audit_mod.key_valid_at(key, obody["collected_at_ms"]):
            raise ApiError(422, "REFERENCE_INVALID", "collected_at_ms is outside the origin key validity.")
        if obody["collected_at_ms"] > now:
            raise ApiError(422, "REFERENCE_INVALID", "collected_at_ms is in the future.")
        if not audit_mod.verify_origin(signed, key["public_key"]):
            raise ApiError(403, "SIGNATURE_INVALID", "Origin signature verification failed.")

        origin_hash = B(signed)
        with self.store.tx() as conn:
            row = conn.execute(
                'SELECT id, object_hash FROM "references" WHERE origin_hash=?', (origin_hash,)
            ).fetchone()
            if row is not None:
                existing = self._reference_object(conn, row["id"])
                self._consume_idem(conn, idem, 200, existing)
                return 200, existing

        # Validate partitions (outside the tx; blobs are immutable).
        train = self._load_artifact_blob(obody["train_hash"])
        holdout = self._load_artifact_blob(obody["holdout_hash"])
        for artifact in (train, holdout):
            try:
                validate_artifact(artifact, strict_tickets=True)
                for rec in artifact["records"]:
                    validate_ticket(rec)
            except ApiError as exc:
                raise ApiError(422, "REFERENCE_INVALID", "A reference partition failed ticket validation.") from exc
            self._partition_checks(artifact)
        train_cats = {r["category"] for r in train["records"]}
        holdout_cats = {r["category"] for r in holdout["records"]}
        if not train_cats or train_cats != holdout_cats:
            raise ApiError(422, "REFERENCE_INVALID", "Partitions must have identical nonempty category sets.")
        if {B({k: r[k] for k in ("title", "body", "category")}) for r in train["records"]} & {
            B({k: r[k] for k in ("title", "body", "category")}) for r in holdout["records"]
        }:
            raise ApiError(422, "REFERENCE_INVALID", "Partitions must have disjoint content.")
        if self._check_partition_overlap(train["records"], holdout["records"]):
            raise ApiError(422, "REFERENCE_INVALID", "Partitions are near-overlapping at the dedup threshold.")

        now = self.now()
        reference = {
            "v": "fv.reference/1",
            "id": self._alloc("fvref_"),
            "project_id": self.store.project_id,
            "train_hash": obody["train_hash"],
            "holdout_hash": obody["holdout_hash"],
            "origin": signed,
            "created_at_ms": now,
        }
        with self.store.tx() as conn:
            row = conn.execute(
                'SELECT id FROM "references" WHERE origin_hash=?', (origin_hash,)
            ).fetchone()
            if row is not None:
                existing = self._reference_object(conn, row["id"])
                self._consume_idem(conn, idem, 200, existing)
                return 200, existing
            self._commit_object_blob(conn, reference, "reference", ["evidence"])
            conn.execute(
                'INSERT INTO "references"(id, object_hash, train_hash, holdout_hash, origin_hash) VALUES (?,?,?,?,?)',
                (reference["id"], B(reference), obody["train_hash"], obody["holdout_hash"], origin_hash),
            )
            self._tag_blob(conn, obody["train_hash"], ["reference"])
            self._tag_blob(conn, obody["holdout_hash"], ["reference"])
            self._append_event(
                conn,
                "REFERENCE_REGISTERED",
                B(reference),
                audit_mod.make_event_data(),
            )
            self._consume_idem(conn, idem, 201, reference)
        return 201, reference

    def _load_artifact_blob(self, digest: str) -> dict:
        row = self.store.get_blob_row(digest)
        if row is None or not row["committed"]:
            raise ApiError(422, "REFERENCE_INVALID", f"Referenced blob {digest} is not uploaded.")
        return decode_json(self.store.cas_read(digest))

    def _reference_object(self, conn, ref_id: str) -> dict:
        row = conn.execute('SELECT object_hash FROM "references" WHERE id=?', (ref_id,)).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND", "Reference not found.")
        return decode_json(self.store.cas_read(row["object_hash"]))

    def get_reference(self, ref_id: str) -> dict:
        with self.store.tx() as conn:
            return self._reference_object(conn, ref_id)

    def put_policy(self, body: dict, *, idem: dict | None = None) -> tuple[int, dict]:
        policy = validate_policy(body)
        # The pinned reference must exist and match by both ID and object hash.
        ref_row = self.store.get_reference(policy["reference_id"])
        if ref_row is None:
            raise ApiError(422, "REFERENCE_INVALID", "Policy pins an unknown reference.")
        if ref_row["object_hash"] != policy["reference_hash"]:
            raise ApiError(422, "REFERENCE_INVALID", "Policy reference_hash does not match the registered reference.")
        # Categories must equal the reference category set.
        train = decode_json(self.store.cas_read(ref_row["train_hash"]))
        ref_cats = sorted({r["category"] for r in train["records"]})
        if policy["categories"] != ref_cats:
            raise ApiError(422, "REFERENCE_INVALID", "Policy categories must match the reference category set.")
        digest = B(policy)
        with self.store.tx() as conn:
            if self.store.get_policy(digest) is not None:
                self._consume_idem(conn, idem, 200, {"hash": digest})
                return 200, {"hash": digest}
            self._commit_object_blob(conn, policy, "policy", ["evidence"])
            conn.execute(
                "INSERT INTO policies(digest, reference_id, canonical_json) VALUES (?,?,?)",
                (digest, policy["reference_id"], store_object_json(policy)),
            )
            self._append_event(conn, "POLICY_REGISTERED", digest, audit_mod.make_event_data())
            self._consume_idem(conn, idem, 201, {"hash": digest})
        return 201, {"hash": digest}

    def get_policy_object(self, digest: str) -> dict:
        row = self.store.get_policy(digest)
        if row is None:
            raise ApiError(404, "NOT_FOUND", "Policy not found.")
        return decode_json(row["canonical_json"].encode("utf-8"))

    def create_stream(self, body: dict, *, idem: dict | None = None) -> tuple[int, dict]:
        req = validate_stream_create_request(body)
        policy_row = self.store.get_policy(req["policy_hash"])
        if policy_row is None:
            raise ApiError(404, "NOT_FOUND", "Policy not found.")
        ref_row = self.store.get_reference(req["reference_id"])
        if ref_row is None:
            raise ApiError(404, "NOT_FOUND", "Reference not found.")
        policy = decode_json(policy_row["canonical_json"].encode("utf-8"))
        reference = decode_json(self.store.cas_read(ref_row["object_hash"]))
        if policy["reference_id"] != reference["id"] or policy["reference_hash"] != B(reference):
            raise ApiError(422, "REFERENCE_INVALID", "Policy does not match the pinned reference.")
        if ref_row["object_hash"] != policy["reference_hash"]:
            raise ApiError(422, "REFERENCE_INVALID", "Reference hash mismatch.")

        train = decode_json(self.store.cas_read(reference["train_hash"]))
        genesis_links = [
            {
                "record_id": r["id"],
                "content_hash": B({k: r[k] for k in ("title", "body", "category")}),
                "origin": "human_attested",
                "source_hash": B(reference["origin"]),
            }
            for r in sorted(train["records"], key=lambda r: r["id"])
        ]
        stream_id = self._alloc("fvstr_")
        manifest = {
            "v": "fv.manifest/1",
            "project_id": self.store.project_id,
            "stream_id": stream_id,
            "revision": 0,
            "parent_release_hash": None,
            "reference_hash": B(reference),
            "policy_hash": B(policy),
            "corpus_hash": reference["train_hash"],
            "records": genesis_links,
            "generation_hash": None,
        }
        release = {
            "v": "fv.release/1",
            "kind": "genesis",
            "project_id": self.store.project_id,
            "stream_id": stream_id,
            "revision": 0,
            "manifest_hash": B(manifest),
            "decision_hash": None,
            "suite": SUITES[0],
            "policy_hash": B(policy),
            "reference_hash": B(reference),
        }
        stream = {
            "v": "fv.stream/1",
            "id": stream_id,
            "project_id": self.store.project_id,
            "state": "ACTIVE",
            "revision": 0,
            "policy_hash": B(policy),
            "reference_hash": B(reference),
            "head_release_hash": B(release),
        }
        with self.store.tx() as conn:
            seq = self.store.next_seq(conn, "streams")
            self._commit_object_blob(conn, manifest, "manifest", ["evidence"])
            self._commit_object_blob(conn, release, "release", ["evidence"])
            self._tag_blob(conn, reference["train_hash"], ["corpus"])
            receipt = self._append_event(
                conn,
                "STREAM_CREATED",
                B(release),
                audit_mod.make_event_data(stream_id=stream_id, to_state="ACTIVE", revision=0),
            )
            conn.execute(
                "INSERT INTO streams(id, seq, state, revision, policy_hash, reference_hash, head_release_hash, project_id)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (stream_id, seq, "ACTIVE", 0, B(policy), B(reference), B(release), self.store.project_id),
            )
            conn.execute(
                "INSERT INTO releases(digest, stream_id, revision, manifest_hash, receipt_hash) VALUES (?,?,?,?,?)",
                (B(release), stream_id, 0, B(manifest), receipt["entry_hash"]),
            )
            self._consume_idem(conn, idem, 201, stream)
        return 201, stream

    def get_stream_obj(self, stream_id: str) -> dict:
        row = self.store.get_stream(stream_id)
        if row is None:
            raise ApiError(404, "NOT_FOUND", "Stream not found.")
        return _stream_public(row)

    def list_streams(self, after: int, limit: int) -> dict:
        hi = self.store.conn.execute("SELECT COALESCE(MAX(seq),0) AS m FROM streams").fetchone()["m"]
        rows = self.store.conn.execute(
            "SELECT * FROM streams WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?",
            (after, hi, limit + 1),
        ).fetchall()
        items = [_stream_public(dict(r)) for r in rows[:limit]]
        next_cursor = self._make_cursor(rows[limit - 1]["seq"]) if len(rows) > limit else None
        return {"items": items, "next_cursor": next_cursor}

    def set_stream_state(self, stream_id: str, body: dict, *, idem: dict | None = None) -> dict:
        req = validate_stream_state_request(body)
        with self.store.tx() as conn:
            row = conn.execute("SELECT * FROM streams WHERE id=?", (stream_id,)).fetchone()
            if row is None:
                raise ApiError(404, "NOT_FOUND", "Stream not found.")
            stream = dict(row)
            if req["expected_revision"] != stream["revision"]:
                raise ApiError(409, "REVISION_CONFLICT", "Stream revision does not match.")
            if req["state"] == stream["state"]:
                raise ApiError(409, "TERMINAL_STATE", "Stream is already in the requested state.")
            new_revision = stream["revision"] + 1
            new_state = req["state"]
            event = "STREAM_PAUSED" if new_state == "PAUSED" else "STREAM_RESUMED"
            receipt = self._append_event(
                conn,
                event,
                audit_mod.stream_control_subject(stream_id, new_state, new_revision, req["reason"]),
                audit_mod.make_event_data(
                    stream_id=stream_id,
                    from_state=stream["state"],
                    to_state=new_state,
                    revision=new_revision,
                ),
            )
            conn.execute(
                "UPDATE streams SET state=?, revision=? WHERE id=?",
                (new_state, new_revision, stream_id),
            )
            if new_state == "PAUSED":
                pending = conn.execute(
                    "SELECT * FROM jobs WHERE state IN ('QUEUED','FILTERING','SCORING','COMMITTING')"
                    " AND json_extract(request_json,'$.stream_id')=? ORDER BY id",
                    (stream_id,),
                ).fetchall()
                for job in pending:
                    self._mark_stale(conn, dict(job))
            updated = _stream_public(dict(conn.execute("SELECT * FROM streams WHERE id=?", (stream_id,)).fetchone()))
            self._consume_idem(conn, idem, 200, updated)
            return updated

    # ---- jobs --------------------------------------------------------------

    def submit_job(self, body: dict, principal: dict, *, idem: dict | None = None) -> tuple[int, dict]:
        """Create a QUEUED job. Caller runs auth/idempotency before this."""
        request = validate_job_request(body)
        generation = request["generation"]
        gbody = generation["body"]
        trust = self._require_trust()
        now = self.now()

        # Project scoping first: a generation bound to another project is
        # answered NOT_FOUND so nothing about local streams is revealed
        # (TV-F--37). Same-project field bindings are checked below.
        if gbody["project_id"] != self.store.project_id:
            raise ApiError(404, "NOT_FOUND", "Stream not found.")
        # Generation signature / trust pin / field bindings / created window.
        if gbody["stream_id"] != request["stream_id"]:
            raise ApiError(422, "GENERATION_BINDING", "Generation stream_id does not match the request.")
        if gbody["expected_revision"] != request["expected_revision"]:
            raise ApiError(422, "GENERATION_BINDING", "Generation expected_revision does not match the request.")
        if gbody["candidate_hash"] != request["candidate_hash"]:
            raise ApiError(422, "GENERATION_BINDING", "Generation candidate_hash does not match the request.")
        gkey = audit_mod.trust_generator_key(trust["snapshot"], gbody["key_id"])
        if gkey is None:
            raise ApiError(403, "TRUST_MISMATCH", "Generator key is not pinned in the trust snapshot.")
        if not audit_mod.key_usable_for_write(gkey, now):
            raise ApiError(403, "KEY_REVOKED", "Generator key is revoked or expired.")
        if not (now - GEN_WINDOW_PAST_MS <= gbody["created_at_ms"] <= now + GEN_WINDOW_FUTURE_MS):
            raise ApiError(422, "GENERATION_BINDING", "Generation created_at_ms is outside the acceptance window.")
        if not audit_mod.key_valid_at(gkey, gbody["created_at_ms"]):
            raise ApiError(403, "KEY_REVOKED", "Generator key was not valid at the claimed signing time.")
        if not audit_mod.verify_generation(generation, gkey["public_key"]):
            raise ApiError(403, "SIGNATURE_INVALID", "Generation signature verification failed.")

        stream = self.store.get_stream(request["stream_id"])
        if stream is None:
            raise ApiError(404, "NOT_FOUND", "Stream not found.")
        if stream["state"] != "ACTIVE":
            raise ApiError(409, "STREAM_PAUSED", "The stream is paused.")
        if request["expected_revision"] != stream["revision"]:
            raise ApiError(409, "REVISION_CONFLICT", "Stream revision does not match.")
        policy = decode_json(
            self.store.conn.execute("SELECT canonical_json FROM policies WHERE digest=?", (stream["policy_hash"],))
            .fetchone()["canonical_json"]
            .encode("utf-8")
        )

        # Candidate blob checks possible at submission time.
        blob_row = self.store.get_blob_row(request["candidate_hash"])
        candidate_count = None
        if blob_row is not None and blob_row["committed"]:
            candidate = decode_json(self.store.cas_read(request["candidate_hash"]))
            validate_artifact(candidate, strict_tickets=False)
            if len(candidate["records"]) > MAX_CANDIDATE_RECORDS:
                raise ApiError(413, "RECORD_LIMIT", "Candidate artifact exceeds 1024 records.")
            validate_candidate_document(candidate["records"])
            parent_release_row = self.store.get_release(stream["head_release_hash"])
            if parent_release_row is not None:
                parent_manifest = decode_json(self.store.cas_read(parent_release_row["manifest_hash"]))
                parent_corpus = decode_json(self.store.cas_read(parent_manifest["corpus_hash"]))
                conflict = record_id_conflicts(candidate["records"], parent_corpus["records"])
                if conflict is not None:
                    raise ApiError(
                        400, "RECORD_ID_CONFLICT",
                        f"Candidate record {conflict} conflicts with parent corpus content.",
                    )
            candidate_count = len(candidate["records"])

        # Rate and queue limits are the final submission check.
        submitted = candidate_count if candidate_count is not None else 0
        round_no = 1
        predecessor = None
        if request["previous_job_id"] is not None:
            predecessor = self.store.get_job(request["previous_job_id"])
            if predecessor is None:
                raise ApiError(404, "NOT_FOUND", "Predecessor job not found.")
            preq = json.loads(predecessor["request_json"])
            if (
                predecessor["state"] != "REJECTED"
                or preq["stream_id"] != request["stream_id"]
                or preq["mode"] != request["mode"]
                or preq["expected_revision"] != request["expected_revision"]
                or preq["generation"]["body"]["key_id"] != gbody["key_id"]
                or predecessor["trust_hash"] != trust["digest"]
                or preq["candidate_hash"] == request["candidate_hash"]
            ):
                raise ApiError(409, "PREDECESSOR_INVALID", "The named predecessor cannot take a successor.")
            edge = self.store.conn.execute(
                "SELECT successor_job_id FROM retry_edges WHERE predecessor_job_id=?",
                (predecessor["id"],),
            ).fetchone()
            if edge is not None:
                raise ApiError(409, "SUCCESSOR_EXISTS", "The predecessor already has a successor.")
            round_no = predecessor["round"] + 1
            if round_no > policy["max_rounds"]:
                raise ApiError(409, "RETRY_EXHAUSTED", "Retry chain exceeds max_rounds.")

        total_candidates = (predecessor["total_candidates"] if predecessor else 0) + submitted
        if candidate_count is not None and total_candidates > policy["max_total_candidates"]:
            raise ApiError(409, "RETRY_EXHAUSTED", "Retry chain exceeds max_total_candidates.")

        self.rate_limit(f"mut:{self.store.project_id}", MUTATIONS_PER_MINUTE, 60000)
        self.check_queue_limit()
        if predecessor is None:
            self.check_chain_quota(principal["principal_id"], stream["reference_hash"])

        job_id = self._alloc("fvjob_")
        with self.store.tx() as conn:
            if predecessor is None:
                day = self.now() - (self.now() % 86400000)
                scope = f"chains:{principal['principal_id']}:{stream['reference_hash']}:{day}"
                conn.execute(
                    "INSERT INTO rate_limits(scope, window_start_ms, count) VALUES (?,?,1)"
                    " ON CONFLICT(scope) DO UPDATE SET count=count+1",
                    (scope, day),
                )
            seq = self.store.next_seq(conn, "jobs")
            receipt = self._append_event(
                conn,
                "JOB_QUEUED",
                audit_mod.lifecycle_subject(job_id, None, "QUEUED", 0),
                audit_mod.make_event_data(
                    job_id=job_id,
                    stream_id=request["stream_id"],
                    to_state="QUEUED",
                    revision=request["expected_revision"],
                ),
            )
            now2 = receipt["body"]["at_ms"]
            conn.execute(
                "INSERT INTO jobs(id, seq, request_hash, request_json, trust_hash, state, round,"
                " total_candidates, attempt, fence, lease_owner, lease_until_ms, created_at_ms,"
                " updated_at_ms, decision_hash, release_hash, receipt_hash, error_json, filter_json, owner)"
                " VALUES (?,?,?,?,?,?,?,?,0,0,NULL,NULL,?,?,NULL,NULL,NULL,NULL,NULL,?)",
                (
                    job_id,
                    seq,
                    B(request),
                    store_object_json(request),
                    trust["digest"],
                    "QUEUED",
                    round_no,
                    total_candidates,
                    now2,
                    now2,
                    principal["principal_id"],
                ),
            )
            if predecessor is not None:
                conn.execute(
                    "INSERT INTO retry_edges(predecessor_job_id, successor_job_id) VALUES (?,?)",
                    (predecessor["id"], job_id),
                )
            # Evidence-role the generation assertion; tag the candidate.
            self._commit_object_blob(conn, generation, "generation", ["evidence"])
            if blob_row is not None:
                self._tag_blob(conn, request["candidate_hash"], ["candidate"])
            row = dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())
            job_obj = _job_public(row)
            self._consume_idem(conn, idem, 202, job_obj)
        return 202, job_obj

    def get_job_obj(self, job_id: str) -> dict:
        row = self.store.get_job(job_id)
        if row is None:
            raise ApiError(404, "NOT_FOUND", "Job not found.")
        return _job_public(row)

    def list_jobs(self, stream_id: str, after: int, limit: int) -> dict:
        hi_row = self.store.conn.execute(
            "SELECT COALESCE(MAX(seq),0) AS m FROM jobs WHERE json_extract(request_json,'$.stream_id')=?",
            (stream_id,),
        ).fetchone()
        hi = hi_row["m"]
        rows = self.store.conn.execute(
            "SELECT * FROM jobs WHERE seq>? AND seq<=? AND json_extract(request_json,'$.stream_id')=?"
            " ORDER BY seq LIMIT ?",
            (after, hi, stream_id, limit + 1),
        ).fetchall()
        items = [_job_public(dict(r)) for r in rows[:limit]]
        next_cursor = self._make_cursor(rows[limit - 1]["seq"]) if len(rows) > limit else None
        return {"items": items, "next_cursor": next_cursor}

    def get_report(self, job_id: str) -> dict:
        row = self.store.get_job(job_id)
        if row is None:
            raise ApiError(404, "NOT_FOUND", "Job not found.")
        if row["state"] == "FAILED":
            raise ApiError(404, "NOT_FOUND", "Failed jobs have no report.")
        if row["decision_hash"] is None:
            raise ApiError(409, "NOT_READY", "The decision is not stored yet.")
        return decode_json(self.store.cas_read(row["decision_hash"]))

    def cancel_job(self, job_id: str, principal: dict, *, idem: dict | None = None) -> dict:
        with self.store.tx() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise ApiError(404, "NOT_FOUND", "Job not found.")
            job = dict(row)
            if principal["role"] == "producer" and job.get("owner") != principal["principal_id"]:
                raise ApiError(403, "FORBIDDEN", "Producers may cancel only their own jobs.")
            if job["state"] in ("ACCEPTED", "REJECTED", "FAILED", "STALE", "CANCELLED"):
                raise ApiError(409, "TERMINAL_STATE", "The job is already terminal.")
            new_fence = job["fence"] + 1
            receipt = self._append_event(
                conn,
                "JOB_CANCELLED",
                audit_mod.lifecycle_subject(job_id, job["state"], "CANCELLED", new_fence),
                audit_mod.make_event_data(
                    job_id=job_id,
                    stream_id=json.loads(job["request_json"])["stream_id"],
                    from_state=job["state"],
                    to_state="CANCELLED",
                    revision=json.loads(job["request_json"])["expected_revision"],
                ),
            )
            conn.execute(
                "UPDATE jobs SET state='CANCELLED', fence=?, lease_owner=NULL, lease_until_ms=NULL,"
                " receipt_hash=?, updated_at_ms=? WHERE id=?",
                (new_fence, receipt["entry_hash"], receipt["body"]["at_ms"], job_id),
            )
            out = _job_public(dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()))
            self._consume_idem(conn, idem, 200, out)
            return out

    # ---- worker RPCs (internal, not remotely routable) ---------------------

    def rpc_lease(self, job_id: str, worker_id: str) -> dict:
        now = self.now()
        with self.store.tx() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise ApiError(404, "NOT_FOUND", "Job not found.")
            job = dict(row)
            if job["state"] != "QUEUED":
                raise ApiError(409, "TERMINAL_STATE", "Job is not queued.")
            attempt = job["attempt"] + 1
            fence = job["fence"] + 1
            lease_until = now + LEASE_MS
            receipt = self._append_event(
                conn,
                "FILTER_STARTED",
                audit_mod.lifecycle_subject(job_id, "QUEUED", "FILTERING", fence),
                audit_mod.make_event_data(
                    job_id=job_id,
                    stream_id=json.loads(job["request_json"])["stream_id"],
                    from_state="QUEUED",
                    to_state="FILTERING",
                    revision=json.loads(job["request_json"])["expected_revision"],
                ),
            )
            conn.execute(
                "UPDATE jobs SET state='FILTERING', attempt=?, fence=?, lease_owner=?, lease_until_ms=?,"
                " updated_at_ms=? WHERE id=? AND state='QUEUED'",
                (attempt, fence, worker_id, lease_until, receipt["body"]["at_ms"], job_id),
            )
            return {"fence": fence, "lease_until_ms": lease_until, "attempt": attempt, "state": "FILTERING"}

    def rpc_heartbeat(self, job_id: str, worker_id: str, fence: int) -> dict:
        now = self.now()
        with self.store.tx() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise ApiError(404, "NOT_FOUND", "Job not found.")
            job = dict(row)
            if job["lease_owner"] != worker_id or job["fence"] != fence:
                raise ApiError(409, "LEASE_LOST", "Fence or worker mismatch.")
            if job["lease_until_ms"] is not None and now >= job["lease_until_ms"]:
                raise ApiError(409, "LEASE_LOST", "Lease has expired.")
            lease_until = now + LEASE_MS
            conn.execute(
                "UPDATE jobs SET lease_until_ms=? WHERE id=?", (lease_until, job_id)
            )
            return {"lease_until_ms": lease_until}

    def rpc_advance(self, job_id: str, worker_id: str, fence: int, to_state: str, filter_result: dict | None = None) -> dict:
        if to_state != "SCORING":
            raise ApiError(400, "SCHEMA", "advance permits only FILTERING->SCORING.")
        now = self.now()
        with self.store.tx() as conn:
            job = self._lease_check(conn, job_id, worker_id, fence, now)
            if job["state"] != "FILTERING":
                raise ApiError(409, "TERMINAL_STATE", "Job is not filtering.")
            receipt = self._append_event(
                conn,
                "SCORE_STARTED",
                audit_mod.lifecycle_subject(job_id, "FILTERING", "SCORING", fence),
                audit_mod.make_event_data(
                    job_id=job_id,
                    stream_id=json.loads(job["request_json"])["stream_id"],
                    from_state="FILTERING",
                    to_state="SCORING",
                    revision=json.loads(job["request_json"])["expected_revision"],
                ),
            )
            conn.execute(
                "UPDATE jobs SET state='SCORING', filter_json=?, updated_at_ms=? WHERE id=?",
                (json.dumps(filter_result) if filter_result is not None else job["filter_json"], receipt["body"]["at_ms"], job_id),
            )
            return {"state": "SCORING", "fence": fence}

    def _lease_check(self, conn, job_id: str, worker_id: str, fence: int, now: int) -> dict:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND", "Job not found.")
        job = dict(row)
        if job["state"] in ("ACCEPTED", "REJECTED", "FAILED", "STALE", "CANCELLED"):
            raise ApiError(409, "TERMINAL_STATE", "Job is terminal.")
        if job["lease_owner"] != worker_id or job["fence"] != fence:
            raise ApiError(409, "LEASE_LOST", "Fence or worker mismatch.")
        if job["lease_until_ms"] is not None and now >= job["lease_until_ms"]:
            raise ApiError(409, "LEASE_LOST", "Lease has expired.")
        return job

    def _job_inputs(self, job: dict) -> dict:
        request = json.loads(job["request_json"])
        stream = self.store.get_stream(request["stream_id"])
        if stream is None:
            raise EvaluationError("ARTIFACT_CORRUPT", "Stream is missing.")
        policy_row = self.store.get_policy(stream["policy_hash"])
        policy = decode_json(policy_row["canonical_json"].encode("utf-8"))
        # The decision is pinned to the release at the request's
        # expected_revision, not whatever head is current at scoring time.
        parent_release_row = self.store.conn.execute(
            "SELECT * FROM releases WHERE stream_id=? AND revision=?",
            (request["stream_id"], request["expected_revision"]),
        ).fetchone()
        if parent_release_row is None:
            raise EvaluationError("ARTIFACT_CORRUPT", "Pinned parent release is missing.")
        parent_release = decode_json(self.store.cas_read(parent_release_row["digest"]))
        manifest = decode_json(self.store.cas_read(parent_release_row["manifest_hash"]))
        reference = decode_json(self.store.cas_read(stream["reference_hash"]))
        artifacts = {}
        for digest in (manifest["corpus_hash"], reference["holdout_hash"], request["candidate_hash"]):
            artifacts[digest] = decode_json(self.store.cas_read(digest))
        return {
            "request": request,
            "parent": parent_release,
            "manifest": manifest,
            "policy": policy,
            "reference": reference,
            "artifacts": artifacts,
        }

    def compute_job_decision(self, job: dict) -> tuple[dict, dict | None]:
        """Run the deterministic pipeline for a job's pinned inputs.
        Returns (decision, proposed_corpus_artifact|None)."""
        inputs = self._job_inputs(job)
        decision = evaluate(inputs)
        corpus = None
        if decision["proposed_corpus_hash"] is not None:
            corpus = decode_json(self.store.cas_read(decision["proposed_corpus_hash"])) if self.store.cas_exists(
                decision["proposed_corpus_hash"]
            ) else None
            if corpus is None:
                # Rebuild the proposed corpus artifact deterministically.
                corpus = self._proposed_corpus(inputs, decision)
        return decision, corpus

    def _proposed_corpus(self, inputs: dict, decision: dict) -> dict:
        manifest = inputs["manifest"]
        parent = inputs["artifacts"][manifest["corpus_hash"]]
        candidate = inputs["artifacts"][inputs["request"]["candidate_hash"]]
        survivors = [r for r in candidate["records"] if r["id"] in set(decision["accepted_candidate_ids"])]
        records = (
            sorted(parent["records"] + survivors, key=lambda r: r["id"])
            if inputs["request"]["mode"] == "mix"
            else survivors
        )
        return {"v": ARTIFACT_V, "kind": "tickets", "records": records}

    def rpc_finish(self, job_id: str, worker_id: str, fence: int, decision: dict, corpus: dict | None) -> dict:
        now = self.now()
        # Re-execution and commit must be one serialized transaction.
        with self.store.tx() as conn:
            job = self._lease_check(conn, job_id, worker_id, fence, now)
            request = json.loads(job["request_json"])
            stream_row = conn.execute("SELECT * FROM streams WHERE id=?", (request["stream_id"],)).fetchone()
            if stream_row is None:
                return self._fail_job(conn, job, "INTERNAL", fence, now)
            stream = dict(stream_row)
            trust = self._require_trust()
            # Stale detection takes precedence over a computed verdict: a moved
            # head, paused stream, or rotated trust aborts before COMMITTING.
            if (
                stream["state"] != "ACTIVE"
                or stream["revision"] != request["expected_revision"]
                or job["trust_hash"] != trust["digest"]
            ):
                self._mark_stale(conn, job)
                return _job_public(dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()))

            # Re-execute the pipeline from pinned inputs; require byte equality.
            try:
                inputs = self._job_inputs(job)
                expected = evaluate(inputs)
            except (ApiError, EvaluationError) as exc:
                code = exc.code
                if code not in ("ARTIFACT_CORRUPT", "INTERNAL", "RESOURCE_LIMIT"):
                    # Malformed/insufficient artifacts fail the job as
                    # ARTIFACT_CORRUPT, never as a numerical zero.
                    code = "ARTIFACT_CORRUPT" if code in (
                        "SCHEMA", "UNKNOWN_FIELD", "NONCANONICAL", "RECORD_LIMIT",
                        "RECORD_ID_CONFLICT", "HASH_MISMATCH", "INSUFFICIENT_SAMPLE",
                        "UNSUPPORTED_VERSION", "GENERATION_BINDING", "DUPLICATE_KEY",
                        "INVALID_JSON",
                    ) else "INTERNAL"
                return self._fail_job(conn, job, code, fence, now)
            if J(expected) != J(decision):
                return self._fail_job(conn, job, "INTERNAL", fence, now)
            validate_decision(decision)

            # Persist artifacts before entering COMMITTING.
            self._commit_object_blob(conn, decision, "decision", ["evidence"])
            if corpus is not None and decision["proposed_corpus_hash"] is not None:
                if B(corpus) != decision["proposed_corpus_hash"]:
                    return self._fail_job(conn, job, "INTERNAL", fence, now)
                self._commit_object_blob(conn, corpus, "tickets", ["corpus"])
            self._tag_blob(conn, decision["candidate_hash"], ["candidate"])

            receipt = self._append_event(
                conn,
                "COMMIT_STARTED",
                audit_mod.lifecycle_subject(job_id, job["state"], "COMMITTING", fence),
                audit_mod.make_event_data(
                    job_id=job_id,
                    stream_id=request["stream_id"],
                    from_state=job["state"],
                    to_state="COMMITTING",
                    revision=request["expected_revision"],
                ),
            )
            conn.execute(
                "UPDATE jobs SET state='COMMITTING', decision_hash=?, updated_at_ms=? WHERE id=?",
                (B(decision), receipt["body"]["at_ms"], job_id),
            )

            if decision["verdict"] == "accept":
                return self._commit_accept(conn, job, stream, request, decision, inputs, fence, now)
            return self._commit_reject(conn, job, request, decision, fence, now)

    def _commit_accept(self, conn, job, stream, request, decision, inputs, fence, now) -> dict:
        corpus = self._proposed_corpus(inputs, decision)
        generation = request["generation"]
        synthetic_links = [
            {
                "record_id": r["id"],
                "content_hash": B({k: r[k] for k in ("title", "body", "category")}),
                "origin": "synthetic",
                "source_hash": B(generation),
            }
            for r in corpus["records"]
            if r["id"] in set(decision["accepted_candidate_ids"])
        ]
        parent_links = inputs["manifest"]["records"] if request["mode"] == "mix" else []
        manifest = {
            "v": "fv.manifest/1",
            "project_id": self.store.project_id,
            "stream_id": request["stream_id"],
            "revision": stream["revision"] + 1,
            "parent_release_hash": stream["head_release_hash"],
            "reference_hash": stream["reference_hash"],
            "policy_hash": stream["policy_hash"],
            "corpus_hash": decision["proposed_corpus_hash"],
            "records": sorted(parent_links + synthetic_links, key=lambda link: link["record_id"]),
            "generation_hash": B(generation),
        }
        release = {
            "v": "fv.release/1",
            "kind": "accepted",
            "project_id": self.store.project_id,
            "stream_id": request["stream_id"],
            "revision": stream["revision"] + 1,
            "manifest_hash": B(manifest),
            "decision_hash": B(decision),
            "suite": SUITES[0],
            "policy_hash": stream["policy_hash"],
            "reference_hash": stream["reference_hash"],
        }
        self._commit_object_blob(conn, manifest, "manifest", ["evidence"])
        self._commit_object_blob(conn, release, "release", ["evidence"])
        self._commit_object_blob(conn, corpus, "tickets", ["corpus"])
        self._commit_object_blob(conn, generation, "generation", ["evidence"])

        new_revision = stream["revision"] + 1
        receipt = self._append_event(
            conn,
            "JOB_ACCEPTED",
            B(release),
            audit_mod.make_event_data(
                job_id=job["id"],
                stream_id=request["stream_id"],
                from_state="COMMITTING",
                to_state="ACCEPTED",
                revision=new_revision,
            ),
        )
        conn.execute(
            "INSERT INTO releases(digest, stream_id, revision, manifest_hash, receipt_hash) VALUES (?,?,?,?,?)",
            (B(release), request["stream_id"], new_revision, B(manifest), receipt["entry_hash"]),
        )
        conn.execute(
            "UPDATE streams SET revision=?, head_release_hash=? WHERE id=? AND revision=?",
            (new_revision, B(release), request["stream_id"], stream["revision"]),
        )
        conn.execute(
            "UPDATE jobs SET state='ACCEPTED', decision_hash=?, release_hash=?, receipt_hash=?,"
            " lease_owner=NULL, lease_until_ms=NULL, updated_at_ms=? WHERE id=?",
            (B(decision), B(release), receipt["entry_hash"], receipt["body"]["at_ms"], job["id"]),
        )
        # Other pending jobs pinned to the old head become STALE.
        pending = conn.execute(
            "SELECT * FROM jobs WHERE state IN ('QUEUED','FILTERING','SCORING','COMMITTING')"
            " AND json_extract(request_json,'$.stream_id')=? AND id<>? ORDER BY id",
            (request["stream_id"], job["id"]),
        ).fetchall()
        for stale_job in pending:
            self._mark_stale(conn, dict(stale_job))
        return _job_public(dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job["id"],)).fetchone()))

    def _commit_reject(self, conn, job, request, decision, fence, now) -> dict:
        receipt = self._append_event(
            conn,
            "JOB_REJECTED",
            B(decision),
            audit_mod.make_event_data(
                job_id=job["id"],
                stream_id=request["stream_id"],
                from_state="COMMITTING",
                to_state="REJECTED",
                reasons=decision["reasons"],
                revision=request["expected_revision"],
            ),
        )
        conn.execute(
            "UPDATE jobs SET state='REJECTED', decision_hash=?, receipt_hash=?, lease_owner=NULL,"
            " lease_until_ms=NULL, updated_at_ms=? WHERE id=?",
            (B(decision), receipt["entry_hash"], receipt["body"]["at_ms"], job["id"]),
        )
        return _job_public(dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job["id"],)).fetchone()))

    def _fail_job(self, conn, job, code: str, fence: int, now: int) -> dict:
        error = {"code": code, "message": code, "retryable": False, "request_id": self._alloc("fvreq_")}
        receipt = self._append_event(
            conn,
            "JOB_FAILED",
            audit_mod.lifecycle_subject(job["id"], job["state"], "FAILED", fence),
            audit_mod.make_event_data(
                job_id=job["id"],
                stream_id=json.loads(job["request_json"])["stream_id"],
                from_state=job["state"],
                to_state="FAILED",
                reasons=[code],
                revision=json.loads(job["request_json"])["expected_revision"],
            ),
        )
        conn.execute(
            "UPDATE jobs SET state='FAILED', error_json=?, receipt_hash=?, lease_owner=NULL,"
            " lease_until_ms=NULL, updated_at_ms=? WHERE id=?",
            (json.dumps(error), receipt["entry_hash"], receipt["body"]["at_ms"], job["id"]),
        )
        return _job_public(dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job["id"],)).fetchone()))

    def rpc_recover(self) -> dict:
        """Requeue jobs whose lease expired (attempt < 3) or fail them
        (third failed attempt). Events emit in ascending job_id order."""
        now = self.now()
        requeued: list[str] = []
        failed: list[str] = []
        with self.store.tx() as conn:
            rows = conn.execute(
                "SELECT * FROM jobs WHERE state IN ('FILTERING','SCORING','COMMITTING')"
                " AND lease_until_ms IS NOT NULL AND lease_until_ms<=? ORDER BY id",
                (now,),
            ).fetchall()
            for row in rows:
                job = dict(row)
                if job["attempt"] < MAX_ATTEMPTS:
                    new_fence = job["fence"] + 1
                    receipt = self._append_event(
                        conn,
                        "LEASE_RECOVERED",
                        audit_mod.lifecycle_subject(job["id"], job["state"], "QUEUED", new_fence),
                        audit_mod.make_event_data(
                            job_id=job["id"],
                            stream_id=json.loads(job["request_json"])["stream_id"],
                            from_state=job["state"],
                            to_state="QUEUED",
                            revision=json.loads(job["request_json"])["expected_revision"],
                        ),
                    )
                    conn.execute(
                        "UPDATE jobs SET state='QUEUED', fence=?, lease_owner=NULL, lease_until_ms=NULL,"
                        " updated_at_ms=? WHERE id=?",
                        (new_fence, receipt["body"]["at_ms"], job["id"]),
                    )
                    requeued.append(job["id"])
                else:
                    self._fail_job(conn, job, "ATTEMPT_LIMIT", job["fence"], now)
                    failed.append(job["id"])
        return {"requeued": requeued, "failed": failed}

    def lease_next_job(self, worker_id: str) -> dict | None:
        row = self.store.conn.execute(
            "SELECT id FROM jobs WHERE state='QUEUED' ORDER BY seq LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        try:
            return self.rpc_lease(row["id"], worker_id) | {"job_id": row["id"]}
        except ApiError:
            return None

    def run_worker_once(self, worker_id: str) -> dict | None:
        """Lease the oldest queued job and drive it to a terminal state.

        The worker computes the deterministic decision outside the commit
        transaction; finish re-executes from pinned inputs inside it and
        requires byte equality. A leak or noncomputable rejection moves
        FILTERING->COMMITTING directly (SCORING must not run after a leak)."""
        lease = self.lease_next_job(worker_id)
        if lease is None:
            return None
        job_id, fence = lease["job_id"], lease["fence"]
        job = self.store.get_job(job_id)
        import time as _time

        cpu0 = _time.process_time()
        try:
            decision, corpus = self.compute_job_decision(job)
        except (ApiError, EvaluationError) as exc:
            if exc.code in ("ARTIFACT_CORRUPT", "INTERNAL", "RESOURCE_LIMIT"):
                code = exc.code
            elif exc.code in (
                "SCHEMA", "UNKNOWN_FIELD", "NONCANONICAL", "RECORD_LIMIT",
                "RECORD_ID_CONFLICT", "HASH_MISMATCH", "INSUFFICIENT_SAMPLE",
                "UNSUPPORTED_VERSION", "GENERATION_BINDING", "DUPLICATE_KEY",
                "INVALID_JSON",
            ):
                code = "ARTIFACT_CORRUPT"
            else:
                code = "INTERNAL"
            with self.store.tx() as conn:
                current = self._lease_check(conn, job_id, worker_id, fence, self.now())
                return self._fail_job(conn, current, code, fence, self.now())
        cpu_used = _time.process_time() - cpu0
        if cpu_used > self.limits.get("job_cpu_seconds", 120):
            with self.store.tx() as conn:
                current = self._lease_check(conn, job_id, worker_id, fence, self.now())
                return self._fail_job(conn, current, "RESOURCE_LIMIT", fence, self.now())
        if decision["metrics"] is not None:
            self.rpc_advance(job_id, worker_id, fence, "SCORING")
        return self.rpc_finish(job_id, worker_id, fence, decision, corpus)

    def worker_tick(self) -> dict:
        """One maintenance tick: recover expired leases and run the durable
        outbox (scheduled checkpoints). Returns counts."""
        recovered = self.rpc_recover()
        checkpoints = self.run_outbox()
        return {"recovered": recovered, "checkpoints": checkpoints}

    # ---- releases / consumption / export ------------------------------------

    def get_release_envelope(self, release_hash: str) -> dict:
        row = self.store.get_release(release_hash)
        if row is None:
            raise ApiError(404, "NOT_FOUND", "Release not found.")
        release = decode_json(self.store.cas_read(release_hash))
        entry = self.store.conn.execute(
            "SELECT body_json, entry_hash, signature FROM audit WHERE entry_hash=?",
            (row["receipt_hash"],),
        ).fetchone()
        if entry is None:
            raise ApiError(500, "INTERNAL", "Release receipt is missing.")
        receipt = {
            "body": decode_json(entry["body_json"].encode("utf-8")),
            "entry_hash": entry["entry_hash"],
            "signature": entry["signature"],
        }
        return {"release": release, "receipt": receipt}

    def consume(self, body: dict, principal: dict, *, idem: dict | None = None) -> tuple[int, dict]:
        req = validate_consumption_request(body)
        now = self.now()
        trust = self._require_trust()
        root = self._receipt_key_record(trust)
        if not audit_mod.key_usable_for_write(root, now):
            raise ApiError(403, "KEY_REVOKED", "The receipt root key is revoked or expired.")
        with self.store.tx() as conn:
            stream_row = conn.execute("SELECT * FROM streams WHERE id=?", (req["stream_id"],)).fetchone()
            if stream_row is None:
                raise ApiError(404, "NOT_FOUND", "Stream not found.")
            stream = dict(stream_row)
            if stream["state"] != "ACTIVE":
                raise ApiError(409, "STREAM_PAUSED", "The stream is paused.")
            if req["expected_revision"] != stream["revision"]:
                raise ApiError(409, "REVISION_CONFLICT", "Stream revision does not match.")
            if req["release_hash"] != stream["head_release_hash"]:
                raise ApiError(409, "REVISION_CONFLICT", "release_hash is not the current head.")
            release_row = self.store.get_release(req["release_hash"])
            if release_row is None:
                raise ApiError(404, "NOT_FOUND", "Release not found.")
            if release_row["manifest_hash"] != req["manifest_hash"]:
                raise ApiError(422, "HASH_MISMATCH", "manifest_hash does not match the release.")
            # Verify the release receipt and every artifact hash of the
            # immutable release corpus, including each RecordLink.
            entry = conn.execute(
                "SELECT seq FROM audit WHERE entry_hash=?", (release_row["receipt_hash"],)
            ).fetchone()
            if entry is None:
                raise ApiError(500, "ARTIFACT_CORRUPT", "Release receipt is missing from the audit chain.")
            self.store.cas_read(req["release_hash"])
            manifest = decode_json(self.store.cas_read(req["manifest_hash"]))
            corpus = decode_json(self.store.cas_read(manifest["corpus_hash"]))
            links = manifest["records"]
            if len(links) != len(corpus["records"]):
                raise ApiError(500, "ARTIFACT_CORRUPT", "Corpus does not match the manifest.")
            for link, rec in zip(links, corpus["records"]):
                if link["record_id"] != rec["id"] or link["content_hash"] != B(
                    {k: rec[k] for k in ("title", "body", "category")}
                ):
                    raise ApiError(500, "ARTIFACT_CORRUPT", "Corpus record does not match its manifest link.")
            consumption = {
                "v": "fv.consumption/1",
                "id": self._alloc("fvcon_"),
                "request": req,
                "at_ms": now,
            }
            receipt = self._append_event(
                conn,
                "CONSUMED",
                audit_mod.consumption_subject(consumption),
                audit_mod.make_event_data(stream_id=req["stream_id"], revision=stream["revision"]),
            )
            consumption["receipt_hash"] = receipt["entry_hash"]
            conn.execute(
                "INSERT INTO consumptions(id, stream_id, release_hash, body_json, receipt_hash) VALUES (?,?,?,?,?)",
                (consumption["id"], req["stream_id"], req["release_hash"], store_object_json(consumption), receipt["entry_hash"]),
            )
            out = {"consumption": consumption, "receipt": receipt}
            self._consume_idem(conn, idem, 201, out)
            return 201, out

    def create_checkpoint(self) -> dict:
        """Append a CHECKPOINTED receipt describing the current tip (separate
        scheduled transaction, driven via the durable outbox)."""
        with self.store.tx() as conn:
            tip_seq, tip_hash = self.store.audit_tip(conn)
            if tip_seq == 0:
                raise ApiError(409, "NOT_READY", "Nothing to checkpoint.")
            receipt = self._append_event(
                conn,
                "CHECKPOINTED",
                audit_mod.checkpoint_subject(tip_seq, tip_hash),
                audit_mod.make_event_data(),
            )
            conn.execute(
                "INSERT INTO checkpoints(seq, receipt_hash, tip_seq, tip_hash, exported_at_ms) VALUES (?,?,?,?,?)",
                (receipt["body"]["seq"], receipt["entry_hash"], tip_seq, tip_hash, self.now()),
            )
            return receipt

    def run_outbox(self) -> int:
        """Process pending checkpoint tasks; returns created checkpoint count."""
        rows = self.store.conn.execute(
            "SELECT audit_seq FROM outbox WHERE delivered_at_ms IS NULL AND kind='checkpoint' ORDER BY audit_seq"
        ).fetchall()
        created = 0
        for row in rows:
            latest = self.store.conn.execute(
                "SELECT MAX(tip_seq) AS m FROM checkpoints"
            ).fetchone()["m"]
            # A task is satisfied when an existing checkpoint already covers
            # the event that enqueued it — not merely the current tip.
            if latest is not None and latest >= row["audit_seq"]:
                self.store.conn.execute(
                    "UPDATE outbox SET delivered_at_ms=? WHERE audit_seq=?", (self.now(), row["audit_seq"])
                )
                continue
            self.create_checkpoint()
            created += 1
            self.store.conn.execute(
                "UPDATE outbox SET delivered_at_ms=? WHERE audit_seq=?", (self.now(), row["audit_seq"])
            )
        return created

    def export_bundle(self, release_hash: str) -> dict:
        rel_row = self.store.get_release(release_hash)
        if rel_row is None:
            raise ApiError(404, "NOT_FOUND", "Release not found.")
        rel_receipt_seq = self.store.conn.execute(
            "SELECT seq FROM audit WHERE entry_hash=?", (rel_row["receipt_hash"],)
        ).fetchone()["seq"]
        ckpt = self.store.conn.execute(
            "SELECT * FROM checkpoints WHERE tip_seq>=? ORDER BY tip_seq LIMIT 1", (rel_receipt_seq,)
        ).fetchone()
        if ckpt is None:
            raise ApiError(409, "NOT_READY", "No checkpoint covers this release yet.")
        tip_seq = ckpt["tip_seq"]

        release = decode_json(self.store.cas_read(release_hash))
        manifest = decode_json(self.store.cas_read(rel_row["manifest_hash"]))
        decision = (
            decode_json(self.store.cas_read(release["decision_hash"])) if release["decision_hash"] else None
        )
        reference = decode_json(self.store.cas_read(release["reference_hash"]))
        policy = self.get_policy_object(release["policy_hash"])

        # Ancestors oldest-first: every prior release of the stream.
        ancestors = []
        rows = self.store.conn.execute(
            "SELECT digest, manifest_hash FROM releases WHERE stream_id=? AND revision<? ORDER BY revision ASC",
            (release["stream_id"], release["revision"]),
        ).fetchall()
        for r in rows:
            a_rel = decode_json(self.store.cas_read(r["digest"]))
            a_man = decode_json(self.store.cas_read(r["manifest_hash"]))
            a_dec = (
                decode_json(self.store.cas_read(a_rel["decision_hash"])) if a_rel["decision_hash"] else None
            )
            ancestors.append({"release": a_rel, "manifest": a_man, "decision": a_dec})

        gen_hashes = {a["manifest"]["generation_hash"] for a in ancestors} | {manifest["generation_hash"]}
        generations = sorted(
            (decode_json(self.store.cas_read(h)) for h in gen_hashes if h),
            key=lambda g: B(g),
        )
        receipts = self.store.audit_range(0, tip_seq)
        ckpt_entry = self.store.audit_entry(ckpt["seq"])
        trust_rows = self.store.conn.execute(
            "SELECT canonical_json FROM trust_snapshots ORDER BY activation_seq"
        ).fetchall()
        trust_snapshots = [decode_json(r["canonical_json"].encode("utf-8")) for r in trust_rows]
        keys: dict[str, dict] = {}
        for snap in trust_snapshots:
            keys[snap["receipt_root"]["id"]] = snap["receipt_root"]
            for s in snap["sources"]:
                keys[s["key"]["id"]] = s["key"]
            for g in snap["generators"]:
                keys[g["id"]] = g
        return {
            "v": "fv.sunlight-export/1",
            "release": release,
            "manifest": manifest,
            "decision": decision,
            "reference": reference,
            "policy": policy,
            "generations": generations,
            "receipts": receipts,
            "ancestors": ancestors,
            "checkpoint": ckpt_entry,
            "keys": sorted(keys.values(), key=lambda k: k["id"]),
            "trust_snapshots": trust_snapshots,
        }

    def list_audit(self, after: int, limit: int) -> dict:
        tip_seq, tip_hash = self.store.audit_tip()
        items = self.store.audit_range(after, limit + 1)
        items = [r for r in items if r["body"]["seq"] <= tip_seq]
        page = items[:limit]
        next_cursor = self._make_cursor(page[-1]["body"]["seq"]) if len(items) > limit else None
        return {"items": page, "next_cursor": next_cursor, "tip": {"seq": tip_seq, "entry_hash": tip_hash}}

    def get_keys(self) -> dict:
        trust = self._require_trust()
        snap = trust["snapshot"]
        keys = [snap["receipt_root"]] + [s["key"] for s in snap["sources"]] + snap["generators"]
        return {"keys": keys, "root_key_id": snap["receipt_root"]["id"]}

    # ---- tokens --------------------------------------------------------------

    def token_digest(self, token_literal: str) -> str:
        raw = b64u_decode(token_literal, 32)
        return "sha256:" + hmac.new(self.pepper, raw, sha256).hexdigest()

    def issue_token(self, principal_id: str, role: str, ttl_seconds: int, token_literal: str | None = None) -> dict:
        from .canonical import b64u_encode as _u

        if not valid_id(principal_id, "fvact_"):
            raise ApiError(400, "SCHEMA", "Invalid principal ID.")
        if role not in ("admin", "producer", "consumer", "viewer", "auditor"):
            raise ApiError(400, "SCHEMA", "Invalid role.")
        if not (1 <= ttl_seconds <= 300):
            raise ApiError(400, "SCHEMA", "TTL must be 1-300 seconds.")
        token_literal = token_literal or _u(secrets.token_bytes(32))
        digest = self.token_digest(token_literal)
        expires = self.now() + ttl_seconds * 1000
        record = {
            "token_digest": digest,
            "principal_id": principal_id,
            "role": role,
            "expires_at_ms": expires,
            "revoked_at_ms": None,
        }
        with self.store.tx() as conn:
            conn.execute(
                "INSERT INTO tokens(token_digest, principal_id, role, expires_at_ms, revoked_at_ms)"
                " VALUES (?,?,?,?,NULL)",
                (digest, principal_id, role, expires),
            )
            self._append_event(conn, "TOKEN_ISSUED", B(record), audit_mod.make_event_data())
        return {"token": token_literal, "record": record}

    def revoke_token(self, digest: str) -> dict:
        with self.store.tx() as conn:
            row = conn.execute("SELECT * FROM tokens WHERE token_digest=?", (digest,)).fetchone()
            if row is None:
                raise ApiError(404, "NOT_FOUND", "Token not found.")
            if row["revoked_at_ms"] is not None:
                return {"token_digest": digest, "revoked_at_ms": row["revoked_at_ms"]}
            now = self.now()
            conn.execute("UPDATE tokens SET revoked_at_ms=? WHERE token_digest=?", (now, digest))
            record = {
                "token_digest": digest,
                "principal_id": row["principal_id"],
                "role": row["role"],
                "expires_at_ms": row["expires_at_ms"],
                "revoked_at_ms": now,
            }
            self._append_event(conn, "TOKEN_REVOKED", B(record), audit_mod.make_event_data())
            return {"token_digest": digest, "revoked_at_ms": now}

    def authenticate(self, token_literal: str) -> dict:
        """Resolve a bearer token to {principal_id, role}. Raises 401."""
        try:
            digest = self.token_digest(token_literal)
        except ValueError:
            raise ApiError(401, "UNAUTHENTICATED", "Malformed bearer token.")
        row = self.store.get_token(digest)
        if row is None:
            raise ApiError(401, "UNAUTHENTICATED", "Unknown token.")
        now = self.now()
        if row["revoked_at_ms"] is not None or now >= row["expires_at_ms"]:
            raise ApiError(401, "TOKEN_EXPIRED", "Token expired or revoked.")
        return {"principal_id": row["principal_id"], "role": row["role"], "token_digest": digest}

    def list_tokens(self) -> dict:
        """Public TokenRecord list — digests and validity, never literals."""
        rows = self.store.conn.execute(
            "SELECT token_digest, principal_id, role, expires_at_ms, revoked_at_ms FROM tokens ORDER BY token_digest"
        ).fetchall()
        return {
            "tokens": [
                {
                    "token_digest": r["token_digest"],
                    "principal_id": r["principal_id"],
                    "role": r["role"],
                    "expires_at_ms": r["expires_at_ms"],
                    "revoked_at_ms": r["revoked_at_ms"],
                }
                for r in rows
            ]
        }

    # ---- backup / restore / migrate -----------------------------------------

    def backup_create(self, out_path: Path) -> dict:
        """Consistent backup: journal via the SQLite backup API, the
        referenced CAS set, and a signed tip descriptor."""
        import shutil

        out = Path(out_path)
        if out.exists():
            raise ApiError(400, "SCHEMA", "Backup output path already exists.")
        out.mkdir(parents=True)
        db_target = out / "journal.sqlite3"
        dest = sqlite3.connect(str(db_target))
        try:
            self.store.conn.backup(dest)
        finally:
            dest.close()
        cas_out = out / "cas" / "sha256"
        if self.store.cas_root.exists():
            shutil.copytree(self.store.cas_root, cas_out)
        else:
            cas_out.mkdir(parents=True)
        tip_seq, tip_hash = self.store.audit_tip()
        tip = {"seq": tip_seq, "entry_hash": tip_hash}
        descriptor = {"tip": tip, "project_id": self.store.project_id, "created_at_ms": self.now()}
        trust = self._require_trust()
        root = self._receipt_key_record(trust)
        priv = self._resolve_key(root["id"])
        if priv is not None:
            descriptor["signature"] = audit_mod.sign_receipt(priv, B(tip))
        (out / "tip.json").write_bytes(J(descriptor))
        return {"backup_hash": B(descriptor), "tip_seq": tip_seq, "tip_hash": tip_hash}

    def migrate(self, to_version: int) -> dict:
        """Schema migration. Version 1 is the only schema; --to 1 on a v1
        store is a verified no-op and emits no MIGRATED event (nothing was
        applied). Other targets are unsupported."""
        row = self.store.conn.execute("SELECT MAX(version) AS v FROM schema_meta").fetchone()
        current = int(row["v"])
        if to_version != current or to_version != 1:
            raise ApiError(400, "SCHEMA", f"Unsupported migration target {to_version} (current {current}).")
        tip_seq, tip_hash = self.store.audit_tip()
        return {"from_version": current, "to_version": to_version, "receipt_hash": None}

    # ---- cursors / rate limits ----------------------------------------------

    def _make_cursor(self, seq: int | None) -> str | None:
        if seq is None:
            return None
        payload = J({"s": seq, "p": self.store.project_id})
        mac = hmac.new(self.pepper, b"fv.cursor.v1\n" + payload, sha256).digest()
        return b64u_encode(payload + mac)

    def parse_cursor(self, cursor: str) -> int:
        try:
            raw = b64u_decode(cursor)
        except ValueError as exc:
            raise ApiError(400, "SCHEMA", "Invalid cursor.") from exc
        if len(raw) < 33:
            raise ApiError(400, "SCHEMA", "Invalid cursor.")
        payload, mac = raw[:-32], raw[-32:]
        expected = hmac.new(self.pepper, b"fv.cursor.v1\n" + payload, sha256).digest()
        if not hmac.compare_digest(mac, expected):
            raise ApiError(400, "SCHEMA", "Invalid cursor.")
        obj = decode_json(payload)
        if obj.get("p") != self.store.project_id:
            raise ApiError(400, "SCHEMA", "Invalid cursor.")
        return obj["s"]

    def rate_limit(self, scope: str, per_window: int, window_ms: int) -> None:
        now = self.now()
        window = now - (now % window_ms)
        with self.store.tx() as conn:
            row = conn.execute("SELECT window_start_ms, count FROM rate_limits WHERE scope=?", (scope,)).fetchone()
            if row is None or row["window_start_ms"] != window:
                conn.execute(
                    "INSERT INTO rate_limits(scope, window_start_ms, count) VALUES (?,?,1)"
                    " ON CONFLICT(scope) DO UPDATE SET window_start_ms=?, count=1",
                    (scope, window, window),
                )
                return
            if row["count"] >= per_window:
                retry = max(1, (window + window_ms - now) // 1000)
                err = ApiError(429, "RATE_LIMIT", "Rate limit exceeded.")
                err.retry_after = retry
                raise err
            conn.execute("UPDATE rate_limits SET count=count+1 WHERE scope=?", (scope,))

    def check_queue_limit(self) -> None:
        limit = self.limits.get("queued_jobs", QUEUE_LIMIT_DEFAULT)
        if self.store.queued_jobs() >= limit:
            raise ApiError(429, "QUEUE_LIMIT", "Too many queued jobs.")

    def check_chain_quota(self, principal_id: str, reference_hash: str) -> None:
        now = self.now()
        day = now - (now % 86400000)
        scope = f"chains:{principal_id}:{reference_hash}:{day}"
        with self.store.tx() as conn:
            row = conn.execute("SELECT count FROM rate_limits WHERE scope=?", (scope,)).fetchone()
            if row is not None and row["count"] >= CHAINS_PER_DAY:
                raise ApiError(429, "RATE_LIMIT", "Daily retry-chain quota exceeded.")
