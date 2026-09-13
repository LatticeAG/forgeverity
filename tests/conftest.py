"""Shared conformance harness.

A fixture service runs against the spec's deterministic allocator and a
tip-derived clock: the event at seq N is stamped T+N-1, exactly as in the
§9.2 executable fixture.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import vectors as V  # noqa: E402

from forgeverity.service import Service  # noqa: E402
from forgeverity.store import ProjectStore  # noqa: E402


def fixture_allocator():
    """ID(prefix, n) with an independent counter per prefix."""
    counters: dict[str, int] = {}

    def alloc(prefix: str) -> str:
        counters[prefix] = counters.get(prefix, 0) + 1
        return V.ID(prefix, counters[prefix])

    return alloc


class TipClock:
    """now() = T + current audit tip seq; event at seq N lands at T+N-1."""

    def __init__(self, store: ProjectStore):
        self.store = store
        self.offset = 0

    def __call__(self) -> int:
        return V.T + self.store.audit_tip()[0] + self.offset


def make_service(tmp_path, *, project=V.PROJECT, clock=None, limits=None, testing=True):
    store = ProjectStore(tmp_path / "project", project)
    svc = Service(
        store,
        clock=clock or TipClock(store),
        id_allocator=fixture_allocator(),
        key_resolver=lambda key_id: V.PRIV.get(key_id),
        testing=testing,
        limits=limits or {},
    )
    return svc


def init_trust(svc):
    return svc.initialize_trust(V.TRUST)


def producer_principal():
    return {"principal_id": V.PRINCIPAL["producer"], "role": "producer", "token_digest": "sha256:" + "0" * 64}


def consumer_principal():
    return {"principal_id": V.PRINCIPAL["consumer"], "role": "consumer", "token_digest": "sha256:" + "1" * 64}


def build_reference(svc):
    """Register the fixture reference: blobs A/H, reference R (E1)."""
    svc.put_blob(V.J(V.A), V.B(V.A), "admin")
    svc.put_blob(V.J(V.H), V.B(V.H), "admin")
    status, ref = svc.register_reference({"origin": V.O})
    assert status == 201 and ref == V.R
    return ref


def build_stream(svc):
    """Reference + policy + stream: E1..E3, returns S0."""
    build_reference(svc)
    status, out = svc.put_policy(V.P)
    assert status == 201 and out == {"hash": V.B(V.P)}
    status, stream = svc.create_stream({"policy_hash": V.B(V.P), "reference_id": V.REF})
    assert status == 201 and stream == V.S0
    return stream


def build_accepted(svc):
    """Full happy path through JOB_ACCEPTED: E1..E8, returns J1."""
    build_stream(svc)
    svc.put_blob(V.J(V.C), V.B(V.C), "producer")
    status, job = svc.submit_job(V.Q, producer_principal())
    assert status == 202 and job == V.J0
    final = svc.run_worker_once(V.WORKER)
    assert final == V.J1
    return final


def seed_token(svc, literal: str, role: str, principal_id: str):
    """Insert a token row directly (no audit event) for API tests."""
    digest = svc.token_digest(literal)
    svc.store.conn.execute(
        "INSERT INTO tokens(token_digest, principal_id, role, expires_at_ms, revoked_at_ms)"
        " VALUES (?,?,?,?,NULL)",
        (digest, principal_id, role, V.T + 10**9),
    )
    return digest


def api(svc, method, path, body=None, token=None, idem_key=None, request_id=None,
        raw_body=None, headers_extra=None):
    """Drive one request through api.handle() and return (status, obj, headers)."""
    from forgeverity.api import RequestCtx, handle

    headers = {
        "X-FV-Project": svc.store.project_id,
        "X-Request-ID": request_id or V.REQUEST,
        "Content-Type": "application/json",
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if idem_key is not None:
        headers["Idempotency-Key"] = idem_key
    headers.update(headers_extra or {})
    data = raw_body if raw_body is not None else (V.J(body) if body is not None else b"")
    ctx = RequestCtx(method, path, headers, data, {svc.store.project_id: svc}, None)
    return handle(ctx)


@pytest.fixture
def svc(tmp_path):
    s = make_service(tmp_path)
    init_trust(s)
    return s
