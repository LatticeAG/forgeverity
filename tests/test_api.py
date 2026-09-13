"""HTTP API catalog tests (spec section 9.3 example list) and negative
transport behavior. Each independent fixture fork runs on its own service so
sequence numbers and timestamps match the §9.2 snapshot exactly."""

from __future__ import annotations

import pytest

import vectors as V
from conftest import api, build_accepted, build_stream, make_service, seed_token

ADMIN = V.TOKEN_LITERALS["admin"]
PRODUCER = V.TOKEN_LITERALS["producer"]
CONSUMER = V.TOKEN_LITERALS["consumer"]
VIEWER = V.TOKEN_LITERALS["viewer"]

CAP = {
    "protocol": "fv.http/1",
    "suites": ["tickets-lexical-1"],
    "max_body_bytes": 33554432,
    "max_candidate_records": 1024,
    "max_corpus_records": 4096,
    "sample_size": 128,
}


def _fresh(tmp_path, name="p"):
    svc = make_service(tmp_path / name)
    svc.initialize_trust(V.TRUST)
    for role, literal in V.TOKEN_LITERALS.items():
        seed_token(svc, literal, role, V.PRINCIPAL[role])
    return svc


def _idem(n):
    return V.ID("fvreq_", n)


def test_healthz_readyz_and_not_ready(tmp_path):
    svc = make_service(tmp_path / "nr")  # no trust, no tokens
    status, body, _ = api(svc, "GET", "/healthz")
    assert (status, body) == (200, {"status": "alive"})
    status, body, _ = api(svc, "GET", "/readyz")
    assert status == 503 and body == {"status": "not_ready", "reason": "STORAGE_UNAVAILABLE"}

    svc2 = _fresh(tmp_path, "r")
    status, body, _ = api(svc2, "GET", "/readyz")
    assert (status, body) == (200, {"status": "ready", "schema_version": 1})


def test_catalog_acceptance_fork(tmp_path):
    """Every §9.3 example on the accept path, verbatim."""
    svc = _fresh(tmp_path, "a")

    status, body, _ = api(svc, "GET", "/v1/capabilities", token=VIEWER)
    assert (status, body) == (200, CAP)

    status, body, _ = api(svc, "PUT", "/v1/blobs/" + V.B(V.C), raw_body=V.J(V.C), token=PRODUCER)
    assert (status, body) == (201, {"hash": V.B(V.C), "kind": "tickets", "bytes": len(V.J(V.C))})
    status, body, _ = api(svc, "GET", "/v1/blobs/" + V.B(V.C), token=PRODUCER)
    assert (status, body) == (200, V.C)
    # Repeat PUT replays 200 with the same response.
    status, body, _ = api(svc, "PUT", "/v1/blobs/" + V.B(V.C), raw_body=V.J(V.C), token=PRODUCER)
    assert status == 200 and body["hash"] == V.B(V.C)

    # Reference partitions are uploaded by admin (staff class).
    for artifact in (V.A, V.H):
        status, _, _ = api(svc, "PUT", "/v1/blobs/" + V.B(artifact), raw_body=V.J(artifact), token=ADMIN)
        assert status == 201

    status, body, _ = api(svc, "POST", "/v1/references", {"origin": V.O}, token=ADMIN, idem_key=_idem(10))
    assert (status, body) == (201, V.R)
    status, body, _ = api(svc, "GET", "/v1/references/" + V.REF, token=VIEWER)
    assert (status, body) == (200, V.R)
    # Identical origin re-registration returns 200 with the existing reference.
    status, body, _ = api(svc, "POST", "/v1/references", {"origin": V.O}, token=ADMIN, idem_key=_idem(11))
    assert (status, body) == (200, V.R)

    status, body, _ = api(svc, "POST", "/v1/policies", V.P, token=ADMIN, idem_key=_idem(12))
    assert (status, body) == (201, {"hash": V.B(V.P)})
    status, body, _ = api(svc, "GET", "/v1/policies/" + V.B(V.P), token=VIEWER)
    assert (status, body) == (200, V.P)
    # Duplicate policy registration returns 200 without a second audit event.
    tip_before = svc.store.audit_tip()[0]
    status, body, _ = api(svc, "POST", "/v1/policies", V.P, token=ADMIN, idem_key=_idem(13))
    assert (status, body) == (200, {"hash": V.B(V.P)})
    assert svc.store.audit_tip()[0] == tip_before

    status, body, _ = api(
        svc, "POST", "/v1/streams",
        {"policy_hash": V.B(V.P), "reference_id": V.REF}, token=ADMIN, idem_key=_idem(14),
    )
    assert (status, body) == (201, V.S0)

    status, body, _ = api(svc, "POST", "/v1/jobs", V.Q, token=PRODUCER, idem_key=_idem(15))
    assert (status, body) == (202, V.J0)
    svc.run_worker_once(V.WORKER)

    status, body, _ = api(svc, "GET", f"/v1/jobs?stream_id={V.STREAM}&after=0&limit=50", token=VIEWER)
    assert (status, body) == (200, {"items": [V.J1], "next_cursor": None})
    status, body, _ = api(svc, "GET", "/v1/jobs/" + V.JOB, token=VIEWER)
    assert (status, body) == (200, V.J1)
    status, body, _ = api(svc, "GET", "/v1/jobs/" + V.JOB + "/report", token=VIEWER)
    assert (status, body) == (200, V.DC)

    status, body, _ = api(svc, "GET", "/v1/releases/" + V.B(V.L1), token=VIEWER)
    assert (status, body) == (200, {"release": V.L1, "receipt": V.E8})

    # Audit page at tip 8 — the spec's example snapshot.
    status, body, _ = api(svc, "GET", "/v1/audit?after=7&limit=50", token=VIEWER)
    assert (status, body) == (
        200,
        {"items": [V.E8], "next_cursor": None, "tip": {"seq": 8, "entry_hash": V.E8["entry_hash"]}},
    )

    # Export requires a checkpoint; GET export must not create one.
    status, body, _ = api(svc, "GET", "/v1/releases/" + V.B(V.L1) + "/export", token=VIEWER)
    assert status == 409 and body["error"]["code"] == "NOT_READY"
    svc.create_checkpoint()
    status, body, _ = api(svc, "GET", "/v1/releases/" + V.B(V.L1) + "/export", token=VIEWER)
    assert (status, body) == (200, V.EXPORT)

    # After the checkpoint, the same page includes it.
    status, body, _ = api(svc, "GET", "/v1/audit?after=7&limit=50", token=VIEWER)
    assert body["items"] == [V.E8, V.CHECK]

    status, body, _ = api(svc, "GET", "/v1/keys", token=VIEWER)
    assert (status, body) == (200, {"keys": V.KEYS, "root_key_id": V.RK})

    status, body, _ = api(svc, "GET", "/v1/streams?after=0&limit=50", token=VIEWER)
    assert (status, body) == (200, {"items": [V.S1], "next_cursor": None})
    status, body, _ = api(svc, "GET", "/v1/streams/" + V.STREAM, token=VIEWER)
    assert (status, body) == (200, V.S1)

    # Pause fork on this instance: revision bumps to 2, head unchanged.
    status, body, _ = api(
        svc, "POST", f"/v1/streams/{V.STREAM}/state",
        {"expected_revision": 1, "state": "PAUSED", "reason": "Reference review"},
        token=ADMIN, idem_key=_idem(16),
    )
    assert (status, body) == (200, {**V.S1, "state": "PAUSED", "revision": 2})


def test_catalog_consumption_fork(tmp_path):
    svc = _fresh(tmp_path, "b")
    build_accepted(svc)
    status, body, _ = api(svc, "POST", "/v1/consumptions", V.CONQ, token=CONSUMER, idem_key=_idem(20))
    assert (status, body) == (201, {"consumption": V.CON, "receipt": V.ECON})


def test_catalog_cancellation_fork(tmp_path):
    svc = _fresh(tmp_path, "c")
    build_stream(svc)
    svc.put_blob(V.J(V.C), V.B(V.C), "producer")
    api(svc, "POST", "/v1/jobs", V.Q, token=PRODUCER, idem_key=_idem(30))
    status, body, _ = api(
        svc, "POST", f"/v1/jobs/{V.JOB}/cancel", {}, token=PRODUCER, idem_key=_idem(31)
    )
    assert (status, body) == (200, V.JCANCEL)


def test_example_revision_conflict_error(tmp_path):
    """The spec's exact error example: POST jobs at expected_revision=0 after
    head revision 1 returns this byte-exact body."""
    svc = _fresh(tmp_path, "d")
    build_accepted(svc)
    status, body, _ = api(
        svc, "POST", "/v1/jobs", V.Q,
        token=PRODUCER, idem_key=_idem(40), request_id=V.REQUEST,
    )
    assert status == 409
    assert body == {
        "error": {
            "code": "REVISION_CONFLICT",
            "message": "Stream revision does not match.",
            "request_id": "fvreq_000000000000000000001",
            "retryable": False,
        }
    }


def test_missing_headers_and_auth(tmp_path):
    svc = _fresh(tmp_path, "e")
    from forgeverity.api import RequestCtx, handle

    ctx = RequestCtx(
        "GET", "/v1/capabilities",
        {"X-FV-Project": svc.store.project_id, "Authorization": f"Bearer {VIEWER}"},
        b"", {svc.store.project_id: svc}, None,
    )
    status, body, _ = handle(ctx)
    assert status == 400 and body["error"]["code"] == "SCHEMA"

    # Missing bearer token.
    ctx = RequestCtx(
        "GET", "/v1/capabilities",
        {"X-FV-Project": svc.store.project_id, "X-Request-ID": V.REQUEST},
        b"", {svc.store.project_id: svc}, None,
    )
    status, body, _ = handle(ctx)
    assert status == 401 and body["error"]["code"] == "UNAUTHENTICATED"

    # Unknown token.
    ctx = RequestCtx(
        "GET", "/v1/capabilities",
        {"X-FV-Project": svc.store.project_id, "X-Request-ID": V.REQUEST,
         "Authorization": "Bearer " + V.U(b"\x99" * 32)},
        b"", {svc.store.project_id: svc}, None,
    )
    status, body, _ = handle(ctx)
    assert status == 401 and body["error"]["code"] == "UNAUTHENTICATED"


def test_role_enforcement_before_idempotency(tmp_path):
    svc = _fresh(tmp_path, "f")
    # consumer may not POST jobs even with a valid idempotency key.
    status, body, _ = api(
        svc, "POST", "/v1/jobs", V.Q, token=CONSUMER, idem_key=_idem(50)
    )
    assert status == 403 and body["error"]["code"] == "FORBIDDEN"
    # producer may not create a stream.
    status, body, _ = api(
        svc, "POST", "/v1/streams",
        {"policy_hash": V.B(V.P), "reference_id": V.REF},
        token=PRODUCER, idem_key=_idem(51),
    )
    assert status == 403 and body["error"]["code"] == "FORBIDDEN"
    # Missing idempotency key on POST.
    status, body, _ = api(svc, "POST", "/v1/jobs", V.Q, token=PRODUCER)
    assert status == 400 and body["error"]["code"] == "SCHEMA"


def test_holdout_blob_acl(tmp_path):
    svc = _fresh(tmp_path, "g")
    build_stream(svc)  # reference + policy + stream; tags A as corpus
    # Producer cannot read the holdout partition (reference-bound, no corpus).
    status, body, _ = api(svc, "GET", "/v1/blobs/" + V.B(V.H), token=PRODUCER)
    assert status == 404 and body["error"]["code"] == "NOT_FOUND"
    # Auditor reads everything.
    status, body, _ = api(svc, "GET", "/v1/blobs/" + V.B(V.H), token=V.TOKEN_LITERALS["auditor"])
    assert (status, body) == (200, V.H)
    # Consumer reads the train partition (corpus-bound).
    status, body, _ = api(svc, "GET", "/v1/blobs/" + V.B(V.A), token=CONSUMER)
    assert (status, body) == (200, V.A)
    # Viewer cannot read the holdout either.
    status, body, _ = api(svc, "GET", "/v1/blobs/" + V.B(V.H), token=VIEWER)
    assert status == 404


def test_jobs_list_requires_stream_id_and_cursor_rules(tmp_path):
    svc = _fresh(tmp_path, "h")
    build_stream(svc)
    status, body, _ = api(svc, "GET", "/v1/jobs", token=VIEWER)
    assert status == 400 and body["error"]["code"] == "SCHEMA"
    status, body, _ = api(svc, "GET", f"/v1/jobs?stream_id={V.STREAM}", token=VIEWER)
    assert status == 200 and body["items"] == []
    # Invalid cursor is 400 SCHEMA.
    status, body, _ = api(svc, "GET", f"/v1/jobs?stream_id={V.STREAM}&cursor=bogus", token=VIEWER)
    assert status == 400 and body["error"]["code"] == "SCHEMA"
    # cursor combined with after is rejected.
    status, body, _ = api(
        svc, "GET", f"/v1/jobs?stream_id={V.STREAM}&cursor=x&after=0", token=VIEWER
    )
    assert status == 400


def test_report_lifecycle_states(tmp_path):
    svc = _fresh(tmp_path, "i")
    build_stream(svc)
    svc.put_blob(V.J(V.C), V.B(V.C), "producer")
    api(svc, "POST", "/v1/jobs", V.Q, token=PRODUCER, idem_key=_idem(70))
    # QUEUED job has no decision yet: 409 NOT_READY.
    status, body, _ = api(svc, "GET", f"/v1/jobs/{V.JOB}/report", token=VIEWER)
    assert status == 409 and body["error"]["code"] == "NOT_READY"
    # FAILED job: 404 even if internals persisted something.
    svc.limits["job_cpu_seconds"] = 0
    svc.run_worker_once(V.WORKER)
    status, body, _ = api(svc, "GET", f"/v1/jobs/{V.JOB}/report", token=VIEWER)
    assert status == 404 and body["error"]["code"] == "NOT_FOUND"


def test_put_noncanonical_and_mismatch(tmp_path):
    svc = _fresh(tmp_path, "j")
    # Non-canonical body (schema-valid, wrong key order) is 400 NONCANONICAL
    # before digest equality.
    raw = (
        b'{"v":"fv.artifact/1","records":[{"body":"help","category":"billing",'
        b'"id":"fvrec_000000000000000000001","title":"t"}],"kind":"tickets"}'
    )
    status, body, _ = api(svc, "PUT", "/v1/blobs/" + V.B(V.C), raw_body=raw, token=PRODUCER)
    assert status == 400 and body["error"]["code"] == "NONCANONICAL"
    # Canonical bytes under the wrong digest is 422 HASH_MISMATCH.
    status, body, _ = api(svc, "PUT", "/v1/blobs/" + V.B(V.C), raw_body=V.J(V.A), token=ADMIN)
    assert status == 422 and body["error"]["code"] == "HASH_MISMATCH"


def test_token_expiry_and_revocation(tmp_path):
    svc = _fresh(tmp_path, "k")
    rec = svc.issue_token(V.PRINCIPAL["viewer"], "viewer", 1)
    svc.revoke_token(svc.token_digest(rec["token"]))
    status, body, _ = api(svc, "GET", "/v1/capabilities", token=rec["token"])
    assert status == 401 and body["error"]["code"] == "TOKEN_EXPIRED"


def test_unknown_endpoint_and_bad_path_ids(tmp_path):
    svc = _fresh(tmp_path, "l")
    status, body, _ = api(svc, "DELETE", "/v1/streams/" + V.STREAM, token=VIEWER)
    assert status == 404 and body["error"]["code"] == "NOT_FOUND"
    status, body, _ = api(svc, "GET", "/v1/jobs/badid", token=VIEWER)
    assert status == 400 and body["error"]["code"] == "SCHEMA"
    status, body, _ = api(svc, "GET", "/v1/blobs/not-a-digest", token=VIEWER)
    assert status == 400 and body["error"]["code"] == "SCHEMA"
