"""forgeverity CLI (spec section 10). Executable `forgeverity`;
`python -m forgeverity` behaves identically. Machine output is one canonical
JSON object on stdout; diagnostics go to stderr. No private key or token
literal is ever accepted on argv."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import __version__, audit as audit_mod, keys as keys_mod
from .canonical import B, D, J, b64u_decode, decode_json
from .client import HttpClient
from .errors import ApiError
from .forgedistill import ForgeDistillAdapter
from .gate import evaluate
from .ids import new_id, valid_id
from .schema import (
    validate_artifact,
    validate_config,
    validate_decision,
    validate_job_request,
)
from .service import Service, WallClock
from .store import ProjectStore, project_dir
from .verify import verify as sdk_verify

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_REJECTED = 3
EXIT_AUTH = 4
EXIT_CONFLICT = 5
EXIT_UNAVAILABLE = 6
EXIT_CORRUPT = 7
EXIT_RETRY_EXHAUSTED = 8
EXIT_SIGINT = 130

_CODE_EXIT = {
    "UNAUTHENTICATED": 4, "TOKEN_EXPIRED": 4, "FORBIDDEN": 4, "KEY_REVOKED": 4,
    "SIGNATURE_INVALID": 4, "TRUST_MISMATCH": 4,
    "REVISION_CONFLICT": 5, "STREAM_PAUSED": 5, "IDEMPOTENCY_CONFLICT": 5,
    "TERMINAL_STATE": 5, "NOT_READY": 5, "SUCCESSOR_EXISTS": 5,
    "PREDECESSOR_INVALID": 5, "LEASE_LOST": 5,
    "RETRY_EXHAUSTED": 8,
    "ARTIFACT_CORRUPT": 7,
    "RATE_LIMIT": 6, "QUEUE_LIMIT": 6, "INTERNAL": 6, "SIGNING_UNAVAILABLE": 6,
    "CLOCK_UNSAFE": 6, "STORAGE_UNAVAILABLE": 6, "WORKER_UNAVAILABLE": 6,
    "RESOURCE_LIMIT": 6, "ATTEMPT_LIMIT": 6,
}

CONFIG_NAME = ".devin/forgeverity.json"


def _out(obj) -> None:
    sys.stdout.buffer.write(J(obj) + b"\n")
    sys.stdout.buffer.flush()


def _diag(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def _usage(msg: str) -> int:
    _out({"error": {"code": "SCHEMA", "message": msg[:256], "retryable": False, "request_id": new_id("fvreq_")}})
    return EXIT_USAGE


def _exit_for(exc: ApiError) -> int:
    return _CODE_EXIT.get(exc.code, EXIT_USAGE)


def _die(exc: ApiError) -> int:
    _out(exc.body(new_id("fvreq_")))
    return _exit_for(exc)


# ---- config / wiring ----------------------------------------------------------


def _project_root(args) -> Path:
    return Path(getattr(args, "config", None) or CONFIG_NAME).resolve().parent.parent


def _load_config(args) -> tuple[dict, Path]:
    cfg_path = Path(getattr(args, "config", None) or CONFIG_NAME)
    if not cfg_path.exists():
        raise ApiError(400, "SCHEMA", f"Config {cfg_path} not found; run forgeverity init.")
    cfg = validate_config(decode_json(cfg_path.read_bytes()))
    root = cfg_path.resolve().parent.parent
    return cfg, root


def _state_dir(cfg: dict, root: Path) -> Path:
    return (root / cfg["state_dir"]).resolve()


def _service(cfg: dict, root: Path) -> Service:
    store = ProjectStore(project_dir(_state_dir(cfg, root), cfg["project_id"]), cfg["project_id"])
    svc = Service(store, key_resolver=_key_resolver(root), testing=False)
    # Out-of-band trust provisioning: the configured trust file installs the
    # initial snapshot on first use.
    if store.current_trust() is None:
        trust_path = root / cfg["trust_file"]
        if trust_path.exists():
            svc.initialize_trust(decode_json(trust_path.read_bytes()))
    return svc


def _key_resolver(root: Path):
    def resolve(key_id: str):
        for base in (root / "secrets" / "keys", Path.home() / ".forgeverity" / "keys"):
            for kf in base.glob("*.json"):
                try:
                    record, pem = keys_mod.load_key(kf)
                except Exception:
                    continue
                if record["id"] == key_id:
                    return keys_mod.load_private(pem)
        return None
    return resolve


def _find_key_file(root: Path, key_id: str) -> tuple[dict, bytes]:
    for base in (root / "secrets" / "keys", Path.home() / ".forgeverity" / "keys"):
        for kf in base.glob("*.json"):
            try:
                record, pem = keys_mod.load_key(kf)
            except Exception:
                continue
            if record["id"] == key_id:
                return record, pem
    raise ApiError(404, "NOT_FOUND", f"Key {key_id} not found in a secrets directory.")


def _client(cfg: dict, args) -> HttpClient:
    token_env = cfg["api"]["token_env"]
    token = os.environ.get(token_env)
    if not token:
        raise ApiError(401, "UNAUTHENTICATED", f"Token env {token_env} is not set.")
    return HttpClient(cfg["api"]["base_url"], token, cfg["project_id"])


def _idem(args) -> str:
    key = getattr(args, "idempotency_key", None)
    if key is not None:
        if not valid_id(key, "fvreq_"):
            raise ApiError(400, "SCHEMA", "--idempotency-key must match fvreq_.")
        return key
    return new_id("fvreq_")


def _read(path: str):
    return decode_json(Path(path).read_bytes())


def _artifact_root(path: str) -> dict:
    """Load a directory of digest-named canonical JSON artifacts."""
    out = {}
    for f in sorted(Path(path).iterdir()):
        if not f.is_file():
            continue
        try:
            val = decode_json(f.read_bytes())
        except ApiError:
            continue
        out[B(val)] = val
    return out


# ---- commands -----------------------------------------------------------------


def cmd_init(args) -> int:
    root = Path(args.directory)
    project = args.project
    if not valid_id(project, "fvprj_"):
        return _usage("--project must be a fvprj_ ID.")
    (root / ".devin").mkdir(parents=True, exist_ok=True)
    (root / "secrets" / "keys").mkdir(parents=True, exist_ok=True)
    cfg = {
        "v": "fv.config/1",
        "project_id": project,
        "state_dir": ".forgeverity/state",
        "api": {"base_url": "http://127.0.0.1:8742", "token_env": "FORGEVERITY_TOKEN", "timeout_ms": 30000},
        "trust_file": ".devin/forgeverity-trust.json",
        "receipt_key_id": new_id("fvkey_"),
        "generator": {"executable": "/opt/forgedistill/bin/forgedistill", "args": ["export-tickets"], "timeout_ms": 300000, "key_id": new_id("fvkey_")},
        "limits": {"body_bytes": 33554432, "queued_jobs": 32, "workers": 1, "worker_memory_mib": 512, "job_cpu_seconds": 120, "job_wall_seconds": 300},
        "retention": {"rejected_candidate_days": 7, "unreferenced_blob_hours": 24},
        "telemetry": {"enabled": False, "metrics_bind": "127.0.0.1:9742", "log_level": "info"},
    }
    cfg_path = root / CONFIG_NAME
    if cfg_path.exists():
        return _usage(f"Config {cfg_path} already exists.")
    fd = os.open(str(cfg_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(J(cfg) + b"\n")
    os.chmod(cfg_path, 0o600)
    state = project_dir(_state_dir(cfg, root), project)
    ProjectStore(state, project).close()
    _out({"config_path": str(cfg_path), "state_path": str(state), "project_id": project})
    return 0


def cmd_config_validate(args) -> int:
    cfg = _read(args.file)
    validate_config(cfg)
    _out({"valid": True, "config_hash": B(cfg)})
    return 0


def cmd_key_generate(args) -> int:
    now = int(time.time() * 1000)
    priv = keys_mod.generate_private()
    record = keys_mod.generate_key_record(priv, args.purpose, now - 1000, now + 365 * 86400_000)
    keys_mod.save_key(args.out, record, keys_mod.private_pem(priv))
    _out({"key": record, "secret_path": args.out})
    return 0


def cmd_key_rotate(args) -> int:
    cfg, root = _load_config(args)
    svc = _service(cfg, root)
    current = svc.store.current_trust()
    if current is None:
        raise ApiError(409, "NOT_READY", "No trust snapshot installed; provision one out of band.")
    old_snap = current["snapshot"]
    old_rec, old_pem = _find_key_file(root, args.old_key)
    new_rec, new_pem = _find_key_file(root, args.new_key)
    snapshot = audit_mod.make_trust_snapshot(
        project_id=cfg["project_id"],
        receipt_root=new_rec,
        sources=old_snap["sources"],
        generators=old_snap["generators"],
        previous_hash=B(old_snap),
        new_priv=keys_mod.load_private(new_pem),
        old_priv=keys_mod.load_private(old_pem),
    )
    result = svc.rotate_trust(snapshot)
    Path(args.trust).write_bytes(J(snapshot))
    _out(result)
    return 0


def cmd_trust_init(args) -> int:
    """Local bootstrap helper: build and install the initial trust snapshot.
    (Spec provision is out of band; this command assembles the file.)"""
    cfg, root = _load_config(args)
    svc = _service(cfg, root)
    receipt_rec, receipt_pem = _find_key_file(root, args.receipt_key)
    sources = []
    for pair in args.source_key or []:
        sid, kid = pair.split("=", 1)
        rec, _ = _find_key_file(root, kid)
        sources.append({"source_id": sid, "key": rec})
    generators = [_find_key_file(root, kid)[0] for kid in args.generator_key or []]
    snapshot = audit_mod.make_trust_snapshot(
        project_id=cfg["project_id"],
        receipt_root=receipt_rec,
        sources=sources,
        generators=generators,
        previous_hash=None,
        new_priv=keys_mod.load_private(receipt_pem),
    )
    out_path = Path(args.out or (root / cfg["trust_file"]))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(J(snapshot))
    digest = svc.initialize_trust(snapshot)
    _out({"trust_hash": digest, "trust_path": str(out_path)})
    return 0


def cmd_token_issue(args) -> int:
    cfg, root = _load_config(args)
    svc = _service(cfg, root)
    if not (1 <= args.ttl_seconds <= 300):
        return _usage("--ttl-seconds must be 1-300.")
    result = svc.issue_token(args.principal, args.role, args.ttl_seconds)
    out = Path(args.out)
    fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(result["token"] + "\n")
    record = result["record"]
    _out({"token_digest": record["token_digest"], "expires_at_ms": record["expires_at_ms"], "secret_path": str(out)})
    return 0


def cmd_token_revoke(args) -> int:
    cfg, root = _load_config(args)
    svc = _service(cfg, root)
    _out(svc.revoke_token(args.digest))
    return 0


def cmd_reference_register(args) -> int:
    cfg, root = _load_config(args)
    client = _client(cfg, args)
    train = validate_artifact(_read(args.train), strict_tickets=True)
    holdout = validate_artifact(_read(args.holdout), strict_tickets=True)
    for artifact in (train, holdout):
        client.put_blob(B(artifact), J(artifact))
    rec, pem = _find_key_file(root, args.key_id)
    signed = audit_mod.make_origin_assertion(
        {
            "project_id": cfg["project_id"],
            "source_id": args.source,
            "train_hash": B(train),
            "holdout_hash": B(holdout),
            "collected_at_ms": int(time.time() * 1000),
            "key_id": rec["id"],
        },
        keys_mod.load_private(pem),
    )
    status, ref = client.register_reference({"origin": signed}, idem_key=_idem(args))
    _out(ref)
    return 0 if status in (200, 201) else _exit_for(ApiError(status, "INTERNAL"))


def cmd_policy_register(args) -> int:
    cfg, root = _load_config(args)
    client = _client(cfg, args)
    status, result = client.put_policy(_read(args.file), idem_key=_idem(args))
    _out(result)
    return 0


def cmd_stream_create(args) -> int:
    cfg, _ = _load_config(args)
    client = _client(cfg, args)
    status, stream = client.create_stream({"policy_hash": args.policy, "reference_id": args.reference}, idem_key=_idem(args))
    _out(stream)
    return 0


def cmd_stream_show(args) -> int:
    cfg, _ = _load_config(args)
    _out(_client(cfg, args).get_stream(args.stream_id))
    return 0


def cmd_stream_state(args) -> int:
    cfg, _ = _load_config(args)
    body = {"expected_revision": args.expected_revision, "state": args.state, "reason": args.reason}
    _out(_client(cfg, args).set_stream_state(args.stream_id, body, idem_key=_idem(args)))
    return 0


def cmd_check(args) -> int:
    doc = _read(args.request)
    if "request" in doc:
        request = validate_job_request(doc["request"])
        parent_pin = doc.get("parent_release_hash")
    else:
        request = validate_job_request(doc)
        parent_pin = None
    artifacts = _artifact_root(args.artifact_root)
    if parent_pin is not None:
        parent = artifacts.get(parent_pin)
        if parent is None:
            raise ApiError(422, "HASH_MISMATCH", "Parent release not in artifact root.")
    else:
        # A bare JobRequest cannot pin its parent; resolve the unique release
        # on the stream with the highest revision at or below the expected one.
        candidates = [
            v for v in artifacts.values()
            if isinstance(v, dict) and v.get("v") == "fv.release/1" and v.get("stream_id") == request["stream_id"]
        ]
        candidates.sort(key=lambda r: r["revision"])
        parent = next(
            (r for r in reversed(candidates) if r["revision"] <= request["expected_revision"]),
            None,
        )
        if parent is None:
            raise ApiError(422, "HASH_MISMATCH", "No parent release in artifact root; pin parent_release_hash.")
    manifest = artifacts.get(parent["manifest_hash"])
    policy = artifacts.get(parent["policy_hash"])
    reference = artifacts.get(parent["reference_hash"])
    if manifest is None or policy is None or reference is None:
        raise ApiError(422, "HASH_MISMATCH", "Pinned objects missing from artifact root.")
    decision = evaluate({"request": request, "parent": parent, "manifest": manifest, "policy": policy, "reference": reference, "artifacts": artifacts})
    validate_decision(decision)
    if args.out:
        Path(args.out).write_bytes(J(decision))
    _out({**decision, "release_created": False})
    return EXIT_OK if decision["verdict"] == "accept" else EXIT_REJECTED


def cmd_submit(args) -> int:
    cfg, _ = _load_config(args)
    client = _client(cfg, args)
    request = validate_job_request(_read(args.request))
    if args.candidate:
        artifact = validate_artifact(_read(args.candidate), strict_tickets=False)
        if B(artifact) != request["candidate_hash"]:
            raise ApiError(422, "HASH_MISMATCH", "Candidate file does not match request.candidate_hash.")
        client.put_blob(B(artifact), J(artifact))
    status, job = client.submit_job(request, idem_key=_idem(args))
    if not args.wait:
        _out(job)
        return 0
    return _wait_job(client, job["id"], getattr(args, "timeout_ms", 30000))


def _wait_job(client: HttpClient, job_id: str, timeout_ms: int) -> int:
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        job = client.get_job(job_id)
        if job["state"] in ("ACCEPTED", "REJECTED", "FAILED", "STALE", "CANCELLED"):
            _out(job)
            return {
                "ACCEPTED": 0, "REJECTED": EXIT_REJECTED, "FAILED": EXIT_UNAVAILABLE,
                "STALE": EXIT_CONFLICT, "CANCELLED": EXIT_CONFLICT,
            }[job["state"]]
        if time.monotonic() > deadline:
            _out({"job_id": job_id, "outcome": "unknown"})
            return EXIT_UNAVAILABLE
        time.sleep(0.2)


def cmd_loop(args) -> int:
    cfg, root = _load_config(args)
    client = _client(cfg, args)
    stream = client.get_stream(args.stream)
    if stream["revision"] != args.expected_revision:
        raise ApiError(409, "REVISION_CONFLICT", "Stream revision does not match.")
    policy = client.get_policy(stream["policy_hash"])
    if not (1 <= args.rounds <= policy["max_rounds"]):
        return _usage("--rounds exceeds the pinned policy's max_rounds.")
    gen_key_id = cfg["generator"]["key_id"]
    _grec, gpem = _find_key_file(root, gen_key_id)
    adapter = ForgeDistillAdapter(cfg["generator"]["executable"], cfg["generator"]["args"], cfg["generator"]["timeout_ms"])
    previous_job_id = None
    feedback: list[str] = []
    final_job = None
    for round_no in range(1, args.rounds + 1):
        out = adapter.generate_round(
            project_id=cfg["project_id"],
            stream_id=args.stream,
            expected_revision=args.expected_revision,
            round_no=round_no,
            seed=str(round_no),
            count=policy["min_candidates"],
            categories=policy["categories"],
            feedback=feedback,
            key_id=gen_key_id,
            key_pem=gpem,
            created_at_ms=int(time.time() * 1000),
        )
        client.put_blob(out["candidate_hash"], J(out["artifact"]))
        request = {
            "stream_id": args.stream,
            "expected_revision": args.expected_revision,
            "candidate_hash": out["candidate_hash"],
            "generation": out["generation"],
            "mode": args.mode,
            "previous_job_id": previous_job_id,
        }
        _status, job = client.submit_job(request, idem_key=_idem(args))
        final_job = _poll(client, job["id"], getattr(args, "timeout_ms", 30000))
        if final_job["state"] == "ACCEPTED":
            if args.out:
                Path(args.out).write_bytes(J(final_job))
            _out({"job": final_job, "receipt_hash": final_job["receipt_hash"]})
            return EXIT_OK
        if final_job["state"] == "REJECTED":
            report = client.get_report(job["id"])
            feedback = report["reasons"]
            previous_job_id = job["id"]
            continue
        if final_job["state"] == "FAILED" and final_job.get("error", {}).get("code") == "ATTEMPT_LIMIT":
            _out({"job": final_job, "receipt_hash": None})
            return EXIT_RETRY_EXHAUSTED
        _out({"job": final_job, "receipt_hash": None})
        return {"STALE": EXIT_CONFLICT, "CANCELLED": EXIT_CONFLICT}.get(final_job["state"], EXIT_UNAVAILABLE)
    if final_job is not None and final_job["state"] == "REJECTED":
        _out({"job": final_job, "receipt_hash": None})
        return EXIT_RETRY_EXHAUSTED if args.rounds >= policy["max_rounds"] else EXIT_REJECTED
    return EXIT_REJECTED


def _poll(client: HttpClient, job_id: str, timeout_ms: int) -> dict:
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        job = client.get_job(job_id)
        if job["state"] in ("ACCEPTED", "REJECTED", "FAILED", "STALE", "CANCELLED"):
            return job
        if time.monotonic() > deadline:
            raise ApiError(503, "WORKER_UNAVAILABLE", "Timed out waiting for a terminal state.")
        time.sleep(0.2)


def cmd_job_show(args) -> int:
    cfg, _ = _load_config(args)
    _out(_client(cfg, args).get_job(args.job_id))
    return 0


def cmd_job_cancel(args) -> int:
    cfg, _ = _load_config(args)
    _out(_client(cfg, args).cancel_job(args.job_id, idem_key=_idem(args)))
    return 0


def cmd_report(args) -> int:
    cfg, _ = _load_config(args)
    decision = _client(cfg, args).get_report(args.job_id)
    if args.out:
        Path(args.out).write_bytes(J(decision))
    _out(decision)
    return 0


def cmd_consume(args) -> int:
    cfg, _ = _load_config(args)
    client = _client(cfg, args)
    env = client.get_release(args.release)
    release = env["release"]
    if release["stream_id"] != args.stream:
        raise ApiError(409, "REVISION_CONFLICT", "Release is not on the named stream.")
    request = {
        "stream_id": args.stream,
        "expected_revision": args.expected_revision,
        "release_hash": args.release,
        "manifest_hash": release["manifest_hash"],
        "consumer_label": args.consumer,
    }
    _status, out = client.consume(request, idem_key=_idem(args))
    manifest = client.get_blob(release["manifest_hash"])
    corpus = client.get_blob(manifest["corpus_hash"])
    if B(corpus) != manifest["corpus_hash"]:
        raise ApiError(500, "ARTIFACT_CORRUPT", "Corpus bytes failed verification.")
    if len(manifest["records"]) != len(corpus["records"]):
        raise ApiError(500, "ARTIFACT_CORRUPT", "Corpus does not match the manifest.")
    for link, rec in zip(manifest["records"], corpus["records"]):
        if link["record_id"] != rec["id"] or link["content_hash"] != B(
            {k: rec[k] for k in ("title", "body", "category")}
        ):
            raise ApiError(500, "ARTIFACT_CORRUPT", "Corpus record does not match its manifest link.")
    target = Path(args.out)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent or "."), prefix=".fv-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(J(corpus))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except Exception:
        os.unlink(tmp)
        raise
    _out({**out, "corpus_path": str(target)})
    return 0


def _pinned_root(trust_doc: dict) -> dict:
    """--trust accepts a TrustSnapshot or a bare receipt-root KeyRecord."""
    if trust_doc.get("v") == "fv.trust/1":
        return trust_doc["receipt_root"]
    if isinstance(trust_doc.get("public_key"), str) and trust_doc.get("purpose") == "receipt":
        return trust_doc
    raise ApiError(400, "SCHEMA", "--trust must be a TrustSnapshot or receipt-root KeyRecord.")


def cmd_verify(args) -> int:
    bundle = _read(args.bundle_path)
    pinned_root = _pinned_root(_read(args.trust))
    artifacts = _artifact_root(args.artifacts) if args.artifacts else {}
    inputs = {"bundle": bundle, "pinned_root": pinned_root, "mode": "current" if args.online else "historical", "artifacts": artifacts, "replay": bool(args.replay)}
    if args.online:
        cfg, _ = _load_config(args)
        inputs["client"] = _client(cfg, args)
    res = sdk_verify(inputs)
    _out(res)
    if res.get("valid"):
        return 0
    code = res.get("code", "SCHEMA")
    return 4 if code in ("SIGNATURE_INVALID", "TRUST_MISMATCH") else 7


def cmd_export_sunlight(args) -> int:
    cfg, _ = _load_config(args)
    client = _client(cfg, args)
    bundle = client.get_export(args.release)
    if args.out:
        Path(args.out).write_bytes(J(bundle))
    _out({"bundle": bundle, "bundle_hash": B(bundle)})
    return 0


def cmd_audit_verify(args) -> int:
    bundle = _read(args.bundle)
    pinned_root = _pinned_root(_read(args.trust))
    res = sdk_verify({"bundle": bundle, "pinned_root": pinned_root, "mode": "historical"})
    if not res.get("valid"):
        _out(res)
        return 4 if res.get("code") in ("SIGNATURE_INVALID", "TRUST_MISMATCH") else 7
    _out({"valid": True, "last_seq": len(bundle["receipts"]), "last_hash": bundle["receipts"][-1]["entry_hash"] if bundle["receipts"] else None})
    return 0


def cmd_checkpoint(args) -> int:
    cfg, root = _load_config(args)
    svc = _service(cfg, root)
    receipt = svc.create_checkpoint()
    if args.out:
        Path(args.out).write_bytes(J(receipt))
    _out(receipt)
    return 0


def cmd_serve(args) -> int:
    cfg, root = _load_config(args)
    svc = _service(cfg, root)
    from .api import ApiServer

    server = ApiServer({cfg["project_id"]: svc}, bind=args.bind, port=args.port)
    _out({"status": "listening", "bind": args.bind, "port": server.port, "schema_version": 1})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return EXIT_SIGINT
    return 0


def cmd_worker(args) -> int:
    cfg, root = _load_config(args)
    if not (1 <= args.concurrency <= 4):
        return _usage("--concurrency must be 1-4.")
    svc = _service(cfg, root)
    worker_ids = [new_id("fvwrk_") for _ in range(args.concurrency)]
    _out({"status": "running", "worker_id": worker_ids[0], "concurrency": args.concurrency, "schema_version": 1})
    stop = threading.Event()

    def loop(wid: str) -> None:
        while not stop.is_set():
            try:
                if svc.run_worker_once(wid) is None:
                    svc.worker_tick()
                    stop.wait(0.2)
            except ApiError as exc:
                _diag(f"worker error: {exc.code}")
                stop.wait(0.5)

    threads = [threading.Thread(target=loop, args=(w,), daemon=True) for w in worker_ids]
    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()
        return EXIT_SIGINT


def cmd_backup(args) -> int:
    cfg, root = _load_config(args)
    svc = _service(cfg, root)
    _out(svc.backup_create(Path(args.out)))
    return 0


def cmd_migrate(args) -> int:
    cfg, root = _load_config(args)
    svc = _service(cfg, root)
    # The migration sequence takes a consistent backup before the schema
    # transaction; --backup is that destination (spec 10.1 table).
    svc.backup_create(Path(args.backup))
    _out(svc.migrate(args.to))
    return 0


# ---- parser -------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="forgeverity")
    p.add_argument("--config", default=None)
    p.add_argument("--json", action="store_true")
    p.add_argument("--timeout-ms", type=int, default=30000)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init")
    s.add_argument("--directory", required=True)
    s.add_argument("--project", required=True)
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("config"); ssub = s.add_subparsers(dest="sub", required=True)
    s2 = ssub.add_parser("validate"); s2.add_argument("--file", required=True); s2.set_defaults(fn=cmd_config_validate)

    s = sub.add_parser("key"); ssub = s.add_subparsers(dest="sub", required=True)
    s2 = ssub.add_parser("generate")
    s2.add_argument("--purpose", required=True, choices=["receipt", "origin", "generator"])
    s2.add_argument("--out", required=True)
    s2.set_defaults(fn=cmd_key_generate)
    s2 = ssub.add_parser("rotate")
    s2.add_argument("--old-key", required=True); s2.add_argument("--new-key", required=True); s2.add_argument("--trust", required=True)
    s2.set_defaults(fn=cmd_key_rotate)

    s = sub.add_parser("trust"); ssub = s.add_subparsers(dest="sub", required=True)
    s2 = ssub.add_parser("init")
    s2.add_argument("--receipt-key", required=True)
    s2.add_argument("--source-key", action="append", help="SOURCE_ID=KEY_ID")
    s2.add_argument("--generator-key", action="append")
    s2.add_argument("--out", default=None)
    s2.set_defaults(fn=cmd_trust_init)

    s = sub.add_parser("token"); ssub = s.add_subparsers(dest="sub", required=True)
    s2 = ssub.add_parser("issue")
    s2.add_argument("--principal", required=True); s2.add_argument("--role", required=True, choices=["admin", "producer", "consumer", "viewer", "auditor"])
    s2.add_argument("--ttl-seconds", type=int, required=True); s2.add_argument("--out", required=True)
    s2.set_defaults(fn=cmd_token_issue)
    s2 = ssub.add_parser("revoke"); s2.add_argument("--digest", required=True); s2.set_defaults(fn=cmd_token_revoke)

    s = sub.add_parser("reference"); ssub = s.add_subparsers(dest="sub", required=True)
    s2 = ssub.add_parser("register")
    s2.add_argument("--train", required=True); s2.add_argument("--holdout", required=True)
    s2.add_argument("--source", required=True); s2.add_argument("--key-id", required=True)
    s2.add_argument("--idempotency-key", default=None)
    s2.set_defaults(fn=cmd_reference_register)

    s = sub.add_parser("policy"); ssub = s.add_subparsers(dest="sub", required=True)
    s2 = ssub.add_parser("register"); s2.add_argument("--file", required=True); s2.add_argument("--idempotency-key", default=None); s2.set_defaults(fn=cmd_policy_register)

    s = sub.add_parser("stream"); ssub = s.add_subparsers(dest="sub", required=True)
    s2 = ssub.add_parser("create"); s2.add_argument("--policy", required=True); s2.add_argument("--reference", required=True); s2.add_argument("--idempotency-key", default=None); s2.set_defaults(fn=cmd_stream_create)
    s2 = ssub.add_parser("show"); s2.add_argument("stream_id"); s2.set_defaults(fn=cmd_stream_show)
    s2 = ssub.add_parser("state")
    s2.add_argument("stream_id"); s2.add_argument("--expected-revision", type=int, required=True)
    s2.add_argument("--state", required=True, choices=["ACTIVE", "PAUSED"]); s2.add_argument("--reason", required=True)
    s2.add_argument("--idempotency-key", default=None)
    s2.set_defaults(fn=cmd_stream_state)

    s = sub.add_parser("check")
    s.add_argument("--request", required=True); s.add_argument("--artifact-root", required=True); s.add_argument("--out", default=None)
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("submit")
    s.add_argument("--request", required=True); s.add_argument("--candidate", default=None); s.add_argument("--wait", action="store_true")
    s.add_argument("--idempotency-key", default=None)
    s.set_defaults(fn=cmd_submit)

    s = sub.add_parser("loop")
    s.add_argument("--stream", required=True); s.add_argument("--expected-revision", type=int, required=True)
    s.add_argument("--mode", required=True, choices=["mix", "replace"]); s.add_argument("--rounds", type=int, required=True)
    s.add_argument("--out", default=None); s.add_argument("--idempotency-key", default=None)
    s.set_defaults(fn=cmd_loop)

    s = sub.add_parser("job"); ssub = s.add_subparsers(dest="sub", required=True)
    s2 = ssub.add_parser("show"); s2.add_argument("job_id"); s2.set_defaults(fn=cmd_job_show)
    s2 = ssub.add_parser("cancel"); s2.add_argument("job_id"); s2.add_argument("--idempotency-key", default=None); s2.set_defaults(fn=cmd_job_cancel)

    s = sub.add_parser("report"); s.add_argument("job_id"); s.add_argument("--out", default=None); s.set_defaults(fn=cmd_report)

    s = sub.add_parser("consume")
    s.add_argument("--stream", required=True); s.add_argument("--expected-revision", type=int, required=True)
    s.add_argument("--release", required=True); s.add_argument("--consumer", required=True); s.add_argument("--out", required=True)
    s.add_argument("--idempotency-key", default=None)
    s.set_defaults(fn=cmd_consume)

    s = sub.add_parser("verify")
    s.add_argument("bundle_path"); s.add_argument("--trust", required=True); s.add_argument("--artifacts", default=None)
    s.add_argument("--replay", action="store_true"); s.add_argument("--online", action="store_true")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("export"); ssub = s.add_subparsers(dest="sub", required=True)
    s2 = ssub.add_parser("sunlight"); s2.add_argument("--release", required=True); s2.add_argument("--out", default=None); s2.set_defaults(fn=cmd_export_sunlight)

    s = sub.add_parser("audit"); ssub = s.add_subparsers(dest="sub", required=True)
    s2 = ssub.add_parser("verify"); s2.add_argument("--bundle", required=True); s2.add_argument("--trust", required=True); s2.set_defaults(fn=cmd_audit_verify)

    s = sub.add_parser("checkpoint"); s.add_argument("--out", default=None); s.set_defaults(fn=cmd_checkpoint)

    s = sub.add_parser("serve"); s.add_argument("--bind", default="127.0.0.1"); s.add_argument("--port", type=int, default=8742); s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("worker"); s.add_argument("--concurrency", type=int, default=1); s.set_defaults(fn=cmd_worker)

    s = sub.add_parser("backup"); s.add_argument("--out", required=True); s.set_defaults(fn=cmd_backup)

    s = sub.add_parser("migrate"); s.add_argument("--to", type=int, required=True); s.add_argument("--backup", required=True); s.set_defaults(fn=cmd_migrate)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except ApiError as exc:
        return _die(exc)
    except FileNotFoundError as exc:
        return _die(ApiError(400, "SCHEMA", str(exc)))
    except json.JSONDecodeError as exc:
        return _die(ApiError(400, "INVALID_JSON", str(exc)))
    except KeyboardInterrupt:
        return EXIT_SIGINT


if __name__ == "__main__":
    raise SystemExit(main())
