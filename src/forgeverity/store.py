"""Persistence: per-project SQLite journal (WAL) plus a digest-addressed CAS.

Blob creation and database commit are coordinated by a write-before-reference
rule: staging file -> fsync -> hash check -> atomic rename -> fsync directory,
and only then may a SQLite transaction mark the digest committed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
from pathlib import Path

from .canonical import D, J, decode_json
from .errors import ApiError
from .ids import PREFIXES, valid_id

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER PRIMARY KEY,
    applied_at_ms INTEGER NOT NULL,
    migration_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blobs (
    digest TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    byte_count INTEGER NOT NULL,
    path TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    uploader_role TEXT NOT NULL,
    roles TEXT NOT NULL,
    committed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS "references" (
    id TEXT PRIMARY KEY,
    object_hash TEXT NOT NULL UNIQUE,
    train_hash TEXT NOT NULL,
    holdout_hash TEXT NOT NULL,
    origin_hash TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS policies (
    digest TEXT PRIMARY KEY,
    reference_id TEXT NOT NULL,
    canonical_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS streams (
    id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL UNIQUE,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL,
    policy_hash TEXT NOT NULL,
    reference_hash TEXT NOT NULL,
    head_release_hash TEXT NOT NULL,
    project_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL UNIQUE,
    request_hash TEXT NOT NULL,
    request_json TEXT NOT NULL,
    trust_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    round INTEGER NOT NULL,
    total_candidates INTEGER NOT NULL,
    attempt INTEGER NOT NULL,
    fence INTEGER NOT NULL,
    lease_owner TEXT,
    lease_until_ms INTEGER,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    decision_hash TEXT,
    release_hash TEXT,
    receipt_hash TEXT,
    error_json TEXT,
    filter_json TEXT,
    owner TEXT
);
CREATE TABLE IF NOT EXISTS retry_edges (
    predecessor_job_id TEXT PRIMARY KEY,
    successor_job_id TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS releases (
    digest TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    manifest_hash TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    UNIQUE(stream_id, revision)
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY,
    entry_id TEXT NOT NULL UNIQUE,
    entry_hash TEXT NOT NULL UNIQUE,
    body_json TEXT NOT NULL,
    signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
    principal TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (principal, method, path, key)
);
CREATE TABLE IF NOT EXISTS consumptions (
    id TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL,
    release_hash TEXT NOT NULL,
    body_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
    seq INTEGER PRIMARY KEY,
    receipt_hash TEXT NOT NULL,
    tip_seq INTEGER NOT NULL,
    tip_hash TEXT NOT NULL,
    exported_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token_digest TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    role TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    revoked_at_ms INTEGER
);
CREATE TABLE IF NOT EXISTS trust_snapshots (
    digest TEXT PRIMARY KEY,
    canonical_json TEXT NOT NULL,
    activation_seq INTEGER NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS outbox (
    audit_seq INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    delivered_at_ms INTEGER
);
CREATE TABLE IF NOT EXISTS rate_limits (
    scope TEXT PRIMARY KEY,
    window_start_ms INTEGER NOT NULL,
    count INTEGER NOT NULL
);
"""

MIGRATION_HASH_INPUT = SCHEMA_SQL.encode("utf-8")


def project_dir(state_dir: Path, project_id: str) -> Path:
    if not valid_id(project_id, "fvprj_"):
        raise ApiError(400, "SCHEMA", "Invalid project ID.")
    return Path(state_dir) / "projects" / project_id


class ProjectStore:
    """One project's SQLite journal + CAS namespace."""

    def __init__(self, root: Path, project_id: str):
        self.project_id = project_id
        self.root = Path(root)
        self.db_path = self.root / "journal.sqlite3"
        self.cas_root = self.root / "cas" / "sha256"
        self.staging = self.root / "staging"
        self.requests_dir = self.root / "requests"
        self.checkpoints_dir = self.root / "checkpoints"
        self.backups_dir = self.root / "backups"
        self.root.mkdir(parents=True, exist_ok=True)
        for d in (self.cas_root, self.staging, self.requests_dir, self.checkpoints_dir, self.backups_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    def _init_schema(self) -> None:
        # executescript issues its own implicit COMMIT, so it cannot run
        # inside tx(); schema DDL is idempotent and applied standalone.
        self.conn.executescript(SCHEMA_SQL)
        with self.tx() as conn:
            row = conn.execute("SELECT version FROM schema_meta ORDER BY version DESC LIMIT 1").fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO schema_meta(version, applied_at_ms, migration_hash) VALUES (?,?,?)",
                    (SCHEMA_VERSION, 0, D(MIGRATION_HASH_INPUT)),
                )
            elif row["version"] != SCHEMA_VERSION:
                raise ApiError(503, "STORAGE_UNAVAILABLE", f"Unsupported schema version {row['version']}.")

    def close(self) -> None:
        self.conn.close()

    @contextlib.contextmanager
    def tx(self):
        """Explicit immediate write transaction."""
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    # ---- CAS ---------------------------------------------------------------

    def cas_path(self, digest: str) -> Path:
        if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
            raise ApiError(400, "SCHEMA", "Invalid digest.")
        hexpart = digest[7:]
        return self.cas_root / hexpart[:2] / hexpart

    def cas_write(self, data: bytes) -> str:
        """Durably write bytes to the CAS; returns the digest. Uncommitted
        until a transaction marks it."""
        digest = D(data)
        path = self.cas_path(digest)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            staging = self.staging / (hexpart_safe(digest) + ".tmp")
            fd = os.open(str(staging), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(staging, path)
            except BaseException:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(staging)
                raise
            dirfd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        return digest

    def cas_read(self, digest: str) -> bytes:
        path = self.cas_path(digest)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ApiError(500, "ARTIFACT_CORRUPT", f"Blob {digest} is absent from storage.") from exc
        if D(data) != digest:
            raise ApiError(500, "ARTIFACT_CORRUPT", f"Blob {digest} failed its integrity check.")
        return data

    def cas_exists(self, digest: str) -> bool:
        return self.cas_path(digest).exists()

    # ---- audit -------------------------------------------------------------

    def audit_tip(self, conn=None) -> tuple[int, str | None]:
        c = conn or self.conn
        row = c.execute("SELECT seq, entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return (row["seq"], row["entry_hash"]) if row else (0, None)

    def append_audit(self, conn, receipt: dict) -> None:
        body = receipt["body"]
        conn.execute(
            "INSERT INTO audit(seq, entry_id, entry_hash, body_json, signature) VALUES (?,?,?,?,?)",
            (body["seq"], body["entry_id"], receipt["entry_hash"], J(body).decode("utf-8"), receipt["signature"]),
        )

    def audit_entry(self, seq: int) -> dict | None:
        row = self.conn.execute("SELECT body_json, entry_hash, signature FROM audit WHERE seq=?", (seq,)).fetchone()
        if row is None:
            return None
        return {
            "body": decode_json(row["body_json"].encode("utf-8")),
            "entry_hash": row["entry_hash"],
            "signature": row["signature"],
        }

    def audit_range(self, after_seq: int, limit: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT body_json, entry_hash, signature FROM audit WHERE seq>? ORDER BY seq ASC LIMIT ?",
            (after_seq, limit),
        ).fetchall()
        return [
            {"body": decode_json(r["body_json"].encode("utf-8")), "entry_hash": r["entry_hash"], "signature": r["signature"]}
            for r in rows
        ]

    # ---- generic helpers ---------------------------------------------------

    def next_seq(self, conn, table: str) -> int:
        row = conn.execute(f"SELECT COALESCE(MAX(seq),0)+1 AS n FROM {table}").fetchone()
        return int(row["n"])

    def get_blob_row(self, digest: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM blobs WHERE digest=?", (digest,)).fetchone()
        return dict(row) if row else None

    def get_stream(self, stream_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM streams WHERE id=?", (stream_id,)).fetchone()
        return dict(row) if row else None

    def get_job(self, job_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def get_release(self, digest: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM releases WHERE digest=?", (digest,)).fetchone()
        return dict(row) if row else None

    def get_policy(self, digest: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM policies WHERE digest=?", (digest,)).fetchone()
        return dict(row) if row else None

    def get_reference(self, ref_id: str) -> dict | None:
        row = self.conn.execute('SELECT * FROM "references" WHERE id=?', (ref_id,)).fetchone()
        return dict(row) if row else None

    def get_token(self, token_digest: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM tokens WHERE token_digest=?", (token_digest,)).fetchone()
        return dict(row) if row else None

    def current_trust(self) -> dict | None:
        row = self.conn.execute(
            "SELECT digest, canonical_json FROM trust_snapshots ORDER BY activation_seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return {"digest": row["digest"], "snapshot": decode_json(row["canonical_json"].encode("utf-8"))}

    def queued_jobs(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS n FROM jobs WHERE state='QUEUED'").fetchone()
        return int(row["n"])

    # ---- restore -------------------------------------------------------------

    STALE_MARKER = "STALE-RESTORE"

    def restored_stale(self) -> bool:
        return (self.root / self.STALE_MARKER).exists()

    def mark_stale_restore(self) -> None:
        (self.root / self.STALE_MARKER).write_text("stale\n")

    @staticmethod
    def restore_backup(backup_dir: Path, dest_project_root: Path, pinned_tip: dict | None = None) -> dict:
        """Restore a backup directory into a fresh project root.

        Verifies the complete audit chain (contiguous seq, exact previous_hash
        links, recomputed entry hashes) and every referenced blob's bytes
        before the project can serve. When the operator pins a newer tip than
        the backup covers, the restored project is marked stale — current
        verification/readiness fails until an operator clears it."""
        from .audit import entry_hash as _entry_hash

        backup_dir = Path(backup_dir)
        src_db = backup_dir / "journal.sqlite3"
        if not src_db.exists():
            raise ApiError(500, "ARTIFACT_CORRUPT", "Backup journal is missing.")
        dest_project_root = Path(dest_project_root)
        dest_project_root.mkdir(parents=True, exist_ok=True)

        # Verify the backup's audit chain before copying anything.
        src = sqlite3.connect(str(src_db))
        src.row_factory = sqlite3.Row
        try:
            rows = src.execute("SELECT seq, entry_hash, body_json FROM audit ORDER BY seq").fetchall()
            prev = None
            for i, r in enumerate(rows):
                body = json.loads(r["body_json"])
                if r["seq"] != i + 1 or body["seq"] != i + 1:
                    raise ApiError(500, "ARTIFACT_CORRUPT", "Backup audit chain has a sequence gap.")
                if body["previous_hash"] != prev:
                    raise ApiError(500, "ARTIFACT_CORRUPT", "Backup audit chain link is broken.")
                if _entry_hash(body) != r["entry_hash"]:
                    raise ApiError(500, "ARTIFACT_CORRUPT", "Backup audit entry hash mismatch.")
                prev = r["entry_hash"]
            tip_seq = len(rows)
            tip_hash = prev
            blob_rows = src.execute("SELECT digest, path FROM blobs WHERE committed=1").fetchall()
        finally:
            src.close()

        # Copy journal and CAS.
        import shutil

        shutil.copy2(src_db, dest_project_root / "journal.sqlite3")
        src_cas = backup_dir / "cas" / "sha256"
        dst_cas = dest_project_root / "cas" / "sha256"
        if src_cas.exists():
            shutil.copytree(src_cas, dst_cas, dirs_exist_ok=True)
        # Verify every committed blob's bytes.
        for b in blob_rows:
            hexpart = b["digest"][7:]
            path = dst_cas / hexpart[:2] / hexpart
            if not path.exists() or D(path.read_bytes()) != b["digest"]:
                raise ApiError(500, "ARTIFACT_CORRUPT", f"Backup blob {b['digest']} is missing or corrupt.")

        stale = False
        if pinned_tip is not None and (
            pinned_tip.get("seq", 0) > tip_seq or pinned_tip.get("entry_hash") != tip_hash
        ):
            stale = True
            (dest_project_root / ProjectStore.STALE_MARKER).write_text("stale\n")
        return {"tip_seq": tip_seq, "tip_hash": tip_hash, "stale": stale, "project_root": str(dest_project_root)}


def hexpart_safe(digest: str) -> str:
    return digest.split(":", 1)[1]


def valid_digest_string(digest: str) -> bool:
    if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:"):
        return False
    try:
        bytes.fromhex(digest[7:])
        return True
    except ValueError:
        return False


def dump_row_object(row_json: str):
    return decode_json(row_json.encode("utf-8"))


def store_object_json(obj) -> str:
    return J(obj).decode("utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def load_json_file(path: Path):
    data = Path(path).read_bytes()
    return decode_json(data)
