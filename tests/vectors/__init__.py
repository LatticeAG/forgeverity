"""Executable test fixture, per spec section 9.2.

Every constant is derived in code from the shared primitives; none of these
values may be replaced by copies from implementation code. The local J/D/B/U
helpers below intentionally use only the standard library so the fixture does
not depend on the implementation under test (RFC8785 and the standard JSON
encoding coincide for this ASCII/integer fixture).
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def J(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def D(x):
    return "sha256:" + hashlib.sha256(x).hexdigest()


def B(x):
    return D(J(x))


def ID(prefix, n):
    return prefix + str(n).zfill(21)


def U(x):
    return base64.urlsafe_b64encode(x).decode().rstrip("=")


T = 1789257600000
PROJECT, SOURCE, REF = ID("fvprj_", 1), ID("fvsrc_", 1), ID("fvref_", 1)
STREAM, JOB, REQUEST = ID("fvstr_", 1), ID("fvjob_", 1), ID("fvreq_", 1)
JOB2 = ID("fvjob_", 2)
WORKER = ID("fvwrk_", 1)
CONSUMER_LABEL = "training-test"
RK, OK, GK = ID("fvkey_", 1), ID("fvkey_", 2), ID("fvkey_", 3)
SEEDS = {
    RK: bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    OK: bytes.fromhex("01" * 32),
    GK: bytes.fromhex("02" * 32),
}
PRIV = {k: Ed25519PrivateKey.from_private_bytes(v) for k, v in SEEDS.items()}
KEYS = [
    {
        "id": k,
        "public_key": U(PRIV[k].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "purpose": purpose,
        "valid_from_ms": T - 1,
        "valid_until_ms": T + 86400000,
        "revoked_at_ms": None,
    }
    for k, purpose in [(RK, "receipt"), (OK, "origin"), (GK, "generator")]
]


def signed(body, domain, key):
    return {"body": body, "signature": U(PRIV[key].sign(domain.encode() + J(body)))}


TB = {
    "v": "fv.trust/1",
    "project_id": PROJECT,
    "receipt_root": KEYS[0],
    "sources": [{"source_id": SOURCE, "key": KEYS[1]}],
    "generators": [KEYS[2]],
    "previous_hash": None,
}
TRUST = {
    **TB,
    "old_signature": None,
    "new_signature": U(PRIV[RK].sign(b"forgeverity.trust.v1\n" + J(TB))),
}


def tickets(prefix, offset):
    return {
        "v": "fv.artifact/1",
        "kind": "tickets",
        "records": [
            {
                "id": ID("fvrec_", offset + i),
                "title": f"{prefix}{i} issue report",
                "body": " ".join(f"{prefix}{i}token{j}" for j in range(8)),
                "category": "billing" if i % 2 == 0 else "login",
            }
            for i in range(1, 33)
        ],
    }


A, H, C = tickets("anchor", 0), tickets("holdout", 100), tickets("candidate", 200)
O = signed(
    {
        "v": "fv.origin/1",
        "project_id": PROJECT,
        "source_id": SOURCE,
        "train_hash": B(A),
        "holdout_hash": B(H),
        "origin": "human_attested",
        "collected_at_ms": T - 1,
        "key_id": OK,
    },
    "forgeverity.origin.v1\n",
    OK,
)
R = {
    "v": "fv.reference/1",
    "id": REF,
    "project_id": PROJECT,
    "train_hash": B(A),
    "holdout_hash": B(H),
    "origin": O,
    "created_at_ms": T,
}
P = {
    "v": "fv.policy/1",
    "suite": "tickets-lexical-1",
    "reference_id": REF,
    "reference_hash": B(R),
    "categories": ["billing", "login"],
    "min_candidates": 32,
    "max_filter_bps": 1000,
    "min_vendi_reference_bps": 8500,
    "min_vendi_parent_bps": 9000,
    "max_self_bleu_increase_bps": 500,
    "min_category_coverage_bps": 8000,
    "max_synthetic_bps": 5000,
    "max_rounds": 3,
    "max_total_candidates": 3072,
}
G = signed(
    {
        "v": "fv.generation/1",
        "project_id": PROJECT,
        "stream_id": STREAM,
        "expected_revision": 0,
        "candidate_hash": B(C),
        "generator": "ForgeDistill",
        "generator_version": "1.0.0",
        "generator_config_hash": B({"profile": "ticket-fixture"}),
        "model_artifact_hash": D(b"fixture-model"),
        "parent_model_hash": None,
        "prompt_hash": D(b"fixture-prompt"),
        "seed": "17",
        "created_at_ms": T + 3,
        "key_id": GK,
    },
    "forgeverity.generation.v1\n",
    GK,
)
Q = {
    "stream_id": STREAM,
    "expected_revision": 0,
    "candidate_hash": B(C),
    "generation": G,
    "mode": "mix",
    "previous_job_id": None,
}


def links(artifact, origin, source):
    return [
        {
            "record_id": r["id"],
            "content_hash": B({k: r[k] for k in ("title", "body", "category")}),
            "origin": origin,
            "source_hash": source,
        }
        for r in artifact["records"]
    ]


M0 = {
    "v": "fv.manifest/1",
    "project_id": PROJECT,
    "stream_id": STREAM,
    "revision": 0,
    "parent_release_hash": None,
    "reference_hash": B(R),
    "policy_hash": B(P),
    "corpus_hash": B(A),
    "records": links(A, "human_attested", B(O)),
    "generation_hash": None,
}
L0 = {
    "v": "fv.release/1",
    "kind": "genesis",
    "project_id": PROJECT,
    "stream_id": STREAM,
    "revision": 0,
    "manifest_hash": B(M0),
    "decision_hash": None,
    "suite": "tickets-lexical-1",
    "policy_hash": B(P),
    "reference_hash": B(R),
}
S0 = {
    "v": "fv.stream/1",
    "id": STREAM,
    "project_id": PROJECT,
    "state": "ACTIVE",
    "revision": 0,
    "policy_hash": B(P),
    "reference_hash": B(R),
    "head_release_hash": B(L0),
}
CORPUS = {"v": "fv.artifact/1", "kind": "tickets", "records": A["records"] + C["records"]}
METRIC = {
    "sample_count": 32,
    "vendi": {"numerator": "676", "denominator": "25"},
    "self_bleu_bps": 1348,
}
METRICS = {
    "reference": METRIC,
    "parent": METRIC,
    "proposed": METRIC,
    "vendi_reference_bps": 10000,
    "vendi_parent_bps": 10000,
    "self_bleu_increase_bps": 0,
    "category_coverage_bps": 10000,
    "synthetic_bps": 5000,
    "filter_bps": 0,
    "collapse_proxy_bps": 0,
}
DC = {
    "v": "fv.decision/1",
    "suite": "tickets-lexical-1",
    "policy_hash": B(P),
    "reference_hash": B(R),
    "parent_release_hash": B(L0),
    "candidate_hash": B(C),
    "generation_hash": B(G),
    "mode": "mix",
    "submitted_count": 32,
    "accepted_candidate_ids": [r["id"] for r in C["records"]],
    "excluded": [],
    "proposed_corpus_hash": B(CORPUS),
    "metrics": METRICS,
    "verdict": "accept",
    "reasons": [],
}
M1 = {
    **M0,
    "revision": 1,
    "parent_release_hash": B(L0),
    "corpus_hash": B(CORPUS),
    "records": M0["records"] + links(C, "synthetic", B(G)),
    "generation_hash": B(G),
}
L1 = {
    **L0,
    "kind": "accepted",
    "revision": 1,
    "manifest_hash": B(M1),
    "decision_hash": B(DC),
}
S1 = {**S0, "revision": 1, "head_release_hash": B(L1)}


def event(seq, previous, name, subject, job=None, stream=None, before=None, after=None, revision=None):
    body = {
        "v": "fv.audit/1",
        "entry_id": ID("fvent_", seq),
        "project_id": PROJECT,
        "seq": seq,
        "previous_hash": previous,
        "at_ms": T + seq - 1,
        "event": name,
        "subject_hash": subject,
        "data": {
            "job_id": job,
            "stream_id": stream,
            "from_state": before,
            "to_state": after,
            "reasons": [],
            "revision": revision,
        },
        "key_id": RK,
    }
    digest = D(b"forgeverity.audit.v1\n" + J(body))
    return {
        "body": body,
        "entry_hash": digest,
        "signature": U(PRIV[RK].sign(b"forgeverity.receipt.v1\n" + bytes.fromhex(digest[7:]))),
    }


E1 = event(1, None, "REFERENCE_REGISTERED", B(R))
E2 = event(2, E1["entry_hash"], "POLICY_REGISTERED", B(P))
E3 = event(3, E2["entry_hash"], "STREAM_CREATED", B(L0), stream=STREAM, after="ACTIVE", revision=0)
EVENTS = [E1, E2, E3]
for seq, name, before, after, fence in [
    (4, "JOB_QUEUED", None, "QUEUED", 0),
    (5, "FILTER_STARTED", "QUEUED", "FILTERING", 1),
    (6, "SCORE_STARTED", "FILTERING", "SCORING", 1),
    (7, "COMMIT_STARTED", "SCORING", "COMMITTING", 1),
]:
    subject = B({"job_id": JOB, "from_state": before, "to_state": after, "fence": fence})
    EVENTS.append(event(seq, EVENTS[-1]["entry_hash"], name, subject, JOB, STREAM, before, after, 0))
E8 = event(8, EVENTS[-1]["entry_hash"], "JOB_ACCEPTED", B(L1), JOB, STREAM, "COMMITTING", "ACCEPTED", 1)
EVENTS.append(E8)
J0 = {
    "v": "fv.job/1",
    "id": JOB,
    "request": Q,
    "state": "QUEUED",
    "trust_hash": B(TRUST),
    "round": 1,
    "total_candidates": 32,
    "attempt": 0,
    "fence": 0,
    "created_at_ms": T + 3,
    "updated_at_ms": T + 3,
    "decision_hash": None,
    "release_hash": None,
    "receipt_hash": None,
    "error": None,
}
J1 = {
    **J0,
    "state": "ACCEPTED",
    "attempt": 1,
    "fence": 1,
    "updated_at_ms": T + 7,
    "decision_hash": B(DC),
    "release_hash": B(L1),
    "receipt_hash": E8["entry_hash"],
}
CONQ = {
    "stream_id": STREAM,
    "expected_revision": 1,
    "release_hash": B(L1),
    "manifest_hash": B(M1),
    "consumer_label": CONSUMER_LABEL,
}
CONBODY = {"v": "fv.consumption/1", "id": ID("fvcon_", 1), "request": CONQ, "at_ms": T + 8}
ECON = event(9, E8["entry_hash"], "CONSUMED", B(CONBODY), stream=STREAM, revision=1)
CON = {**CONBODY, "receipt_hash": ECON["entry_hash"]}
CHECK = event(9, E8["entry_hash"], "CHECKPOINTED", B({"seq": 8, "entry_hash": E8["entry_hash"]}))
EXPORT = {
    "v": "fv.sunlight-export/1",
    "release": L1,
    "manifest": M1,
    "decision": DC,
    "reference": R,
    "policy": P,
    "generations": [G],
    "receipts": EVENTS,
    "ancestors": [{"release": L0, "manifest": M0, "decision": None}],
    "checkpoint": CHECK,
    "keys": KEYS,
    "trust_snapshots": [TRUST],
}
ECANCEL = event(
    5,
    EVENTS[3]["entry_hash"],
    "JOB_CANCELLED",
    B({"job_id": JOB, "from_state": "QUEUED", "to_state": "CANCELLED", "fence": 1}),
    JOB,
    STREAM,
    "QUEUED",
    "CANCELLED",
    0,
)
JCANCEL = {
    **J0,
    "state": "CANCELLED",
    "fence": 1,
    "updated_at_ms": T + 4,
    "receipt_hash": ECANCEL["entry_hash"],
}

# Tokens issued to fixture principals for API tests (256-bit literals).
TOKEN_LITERALS = {
    "admin": U(bytes.fromhex("aa" * 32)),
    "producer": U(bytes.fromhex("bb" * 32)),
    "consumer": U(bytes.fromhex("cc" * 32)),
    "viewer": U(bytes.fromhex("dd" * 32)),
    "auditor": U(bytes.fromhex("ee" * 32)),
}
PRINCIPAL = {role: ID("fvact_", i + 1) for i, role in enumerate(TOKEN_LITERALS)}
