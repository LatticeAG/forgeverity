"""Offline/online export-bundle verification (spec sections 8, 9.4, 12).

verify({bundle, pinned_root, mode, artifacts, replay?}) never trusts keys
merely because a bundle includes them: the caller pins the project receipt
root (and optionally a checkpoint tip) out of band. Historical verification
checks signatures, the exact hash chain, key validity at event time, schemas,
and artifact hashes; freshness is "unproven" offline. Current mode needs an
authenticated client for fresh state/key reads and never silently downgrades.
"""

from __future__ import annotations

from . import audit as audit_mod
from .canonical import B, J
from .errors import ApiError, VerifyError
from .gate import evaluate
from .schema import (
    GATE_REASONS,
    validate_decision,
    validate_export_bundle,
    validate_key_record,
)


def _v(code: str, msg: str | None = None):
    return VerifyError(code, msg)


def _schema_to_verify(exc: ApiError) -> VerifyError:
    code = exc.code if exc.code in (
        "SCHEMA",
        "HASH_MISMATCH",
        "SIGNATURE_INVALID",
        "TRUST_MISMATCH",
        "UNSUPPORTED_VERSION",
        "REPLAY_MISMATCH",
    ) else "SCHEMA"
    return VerifyError(code, exc.message)


def _keys_by_id(trust_snapshots: list[dict]) -> dict[str, dict]:
    """All KeyRecords from the verified trust chain, by key ID."""
    out: dict[str, dict] = {}
    for snap in trust_snapshots:
        out[snap["receipt_root"]["id"]] = snap["receipt_root"]
        for s in snap["sources"]:
            out[s["key"]["id"]] = s["key"]
        for g in snap["generators"]:
            out[g["id"]] = g
    return out


def _receipt_root_at(snapshots: list[dict], activation_seqs: list[int], seq: int) -> dict:
    """Receipt root of the snapshot active at audit seq."""
    chosen = snapshots[0]
    for snap, act in zip(snapshots, activation_seqs):
        if act <= seq:
            chosen = snap
    return chosen["receipt_root"]


def verify(inputs: dict) -> dict:
    """SDK verify. Returns {valid, freshness, release_hash, replay} or
    {valid:false, code}. Operational failures raise ApiError/ErrorResponse."""
    try:
        return _verify(inputs)
    except VerifyError as exc:
        return {"valid": False, "code": exc.code}
    except ApiError:
        raise


def _verify(inputs: dict) -> dict:
    if not isinstance(inputs, dict):
        raise _v("SCHEMA", "verify input must be an object.")
    bundle = inputs.get("bundle")
    pinned_root = inputs.get("pinned_root")
    mode = inputs.get("mode", "historical")
    artifacts = inputs.get("artifacts") or {}
    replay = bool(inputs.get("replay", False))
    checkpoint_pin = inputs.get("checkpoint_pin")
    client = inputs.get("client")

    if mode not in ("historical", "current"):
        raise _v("SCHEMA", "mode must be historical or current.")
    try:
        validate_key_record(pinned_root)
    except ApiError as exc:
        raise _schema_to_verify(exc)
    try:
        validate_export_bundle(bundle)
    except ApiError as exc:
        raise _schema_to_verify(exc)

    snapshots = bundle["trust_snapshots"]
    if not audit_mod.verify_trust_chain(snapshots, pinned_root):
        raise _v("TRUST_MISMATCH", "Trust snapshot chain does not verify under the pinned root.")
    keymap = _keys_by_id(snapshots)

    # Activation sequence for each snapshot: snapshot[0] -> 0; later snapshots
    # activate at their KEY_ROTATED audit seq (the event whose subject is
    # B(snapshot)). Resolve from the receipts list.
    activation_seqs = [0]
    receipts = bundle["receipts"]
    for snap in snapshots[1:]:
        act = None
        for r in receipts:
            if r["body"]["event"] == "KEY_ROTATED" and r["body"]["subject_hash"] == B(snap):
                act = r["body"]["seq"]
        if act is None:
            raise _v("TRUST_MISMATCH", "A trust snapshot lacks its KEY_ROTATED event.")
        activation_seqs.append(act)

    # Receipt chain: contiguous seq from 1, exact previous_hash links.
    prev_hash = None
    for i, receipt in enumerate(receipts):
        body = receipt["body"]
        if body["seq"] != i + 1:
            raise _v("SCHEMA", "Audit sequence gap.")
        if body["previous_hash"] != prev_hash:
            raise _v("HASH_MISMATCH", "Audit previous_hash link broken.")
        if audit_mod.entry_hash(body) != receipt["entry_hash"]:
            raise _v("HASH_MISMATCH", "Audit entry hash mismatch.")
        root = _receipt_root_at(snapshots, activation_seqs, body["seq"])
        if body["key_id"] != root["id"]:
            raise _v("TRUST_MISMATCH", "Receipt signed by a non-root key.")
        if not audit_mod.key_valid_at(root, body["at_ms"]):
            raise _v("TRUST_MISMATCH", "Receipt key not valid at event time.")
        if not audit_mod.verify_receipt_sig(root["public_key"], receipt["signature"], receipt["entry_hash"]):
            raise _v("SIGNATURE_INVALID", "Receipt signature invalid.")
        prev_hash = receipt["entry_hash"]
    tip_seq = len(receipts)
    tip_hash = prev_hash

    # Checkpoint receipt: its previous_hash must equal the tip and its subject
    # must be B(TipDescriptor) of that tip.
    ckpt = bundle["checkpoint"]
    cbody = ckpt["body"]
    if cbody["event"] != "CHECKPOINTED":
        raise _v("SCHEMA", "checkpoint is not a CHECKPOINTED receipt.")
    if cbody["previous_hash"] != tip_hash:
        raise _v("TRUST_MISMATCH", "Checkpoint does not extend the supplied chain tip.")
    if cbody["subject_hash"] != audit_mod.checkpoint_subject(tip_seq, tip_hash):
        raise _v("HASH_MISMATCH", "Checkpoint tip descriptor mismatch.")
    if audit_mod.entry_hash(cbody) != ckpt["entry_hash"]:
        raise _v("HASH_MISMATCH", "Checkpoint entry hash mismatch.")
    croot = _receipt_root_at(snapshots, activation_seqs, cbody["seq"])
    if cbody["key_id"] != croot["id"] or not audit_mod.key_valid_at(croot, cbody["at_ms"]):
        raise _v("TRUST_MISMATCH", "Checkpoint key invalid at event time.")
    if not audit_mod.verify_receipt_sig(croot["public_key"], ckpt["signature"], ckpt["entry_hash"]):
        raise _v("SIGNATURE_INVALID", "Checkpoint signature invalid.")

    # Out-of-band pinned checkpoint detects rollback before its sequence.
    if checkpoint_pin is not None:
        pseq, phash = checkpoint_pin["seq"], checkpoint_pin["entry_hash"]
        if pseq > tip_seq:
            raise _v("TRUST_MISMATCH", "Pinned checkpoint is not covered by the chain.")
        if receipts[pseq - 1]["entry_hash"] != phash:
            raise _v("TRUST_MISMATCH", "Pinned checkpoint hash does not match the chain.")

    # Signed metadata DAG.
    release = bundle["release"]
    manifest = bundle["manifest"]
    decision = bundle["decision"]
    reference = bundle["reference"]
    policy = bundle["policy"]

    if release["manifest_hash"] != B(manifest):
        raise _v("HASH_MISMATCH", "Release manifest hash mismatch.")
    if release["policy_hash"] != B(policy) or manifest["policy_hash"] != B(policy):
        raise _v("HASH_MISMATCH", "Policy hash mismatch.")
    if release["reference_hash"] != B(reference) or manifest["reference_hash"] != B(reference):
        raise _v("HASH_MISMATCH", "Reference hash mismatch.")
    if (release["decision_hash"] is None) != (decision is None):
        raise _v("HASH_MISMATCH", "Release/decision link mismatch.")
    if decision is not None and release["decision_hash"] != B(decision):
        raise _v("HASH_MISMATCH", "Decision hash mismatch.")
    if release["kind"] == "genesis" and release["decision_hash"] is not None:
        raise _v("SCHEMA", "Genesis release cannot carry a decision.")
    if release["kind"] == "accepted" and (decision is None or decision["verdict"] != "accept"):
        raise _v("SCHEMA", "Accepted release requires an accept DecisionCore.")

    # The creating receipt (JOB_ACCEPTED or STREAM_CREATED) must be in the
    # chain and bind this release.
    creating = None
    for r in receipts:
        if r["body"]["subject_hash"] == B(release) and r["body"]["event"] in ("JOB_ACCEPTED", "STREAM_CREATED"):
            creating = r
    if creating is None:
        raise _v("TRUST_MISMATCH", "No chain event records this release.")

    # Ancestors oldest-first, hash-consistent, chain-linked through
    # manifest.parent_release_hash, ending at the parent release.
    prev_release_hash = None
    for anc in bundle["ancestors"]:
        if prev_release_hash is not None and anc["manifest"]["parent_release_hash"] != prev_release_hash:
            raise _v("HASH_MISMATCH", "Ancestor ordering is broken.")
        if anc["release"]["manifest_hash"] != B(anc["manifest"]):
            raise _v("HASH_MISMATCH", "Ancestor manifest hash mismatch.")
        if (anc["release"]["decision_hash"] is None) != (anc["decision"] is None):
            raise _v("HASH_MISMATCH", "Ancestor decision link mismatch.")
        if anc["decision"] is not None and anc["release"]["decision_hash"] != B(anc["decision"]):
            raise _v("HASH_MISMATCH", "Ancestor decision hash mismatch.")
        prev_release_hash = B(anc["release"])
    if bundle["ancestors"] and manifest["parent_release_hash"] != B(bundle["ancestors"][-1]["release"]):
        raise _v("HASH_MISMATCH", "Manifest parent link mismatch.")

    # Generations: digest-sorted, signatures verified under pinned generator
    # keys valid at the claimed signing time.
    gens = bundle["generations"]
    if sorted(gens, key=lambda g: B(g)) != gens:
        raise _v("SCHEMA", "Generations are not digest-sorted.")
    for g in gens:
        gb = g["body"]
        key = None
        for snap in snapshots:
            k = audit_mod.trust_generator_key(snap, gb["key_id"])
            if k is not None:
                key = k
        if key is None:
            raise _v("TRUST_MISMATCH", "Generator key is not pinned.")
        if not audit_mod.key_valid_at(key, gb["created_at_ms"]):
            raise _v("TRUST_MISMATCH", "Generator key invalid at signing time.")
        if not audit_mod.verify_generation(g, key["public_key"]):
            raise _v("SIGNATURE_INVALID", "Generation signature invalid.")

    # Origin assertion under the pinned source key.
    okey = None
    for snap in snapshots:
        k = audit_mod.trust_source_key(snap, reference["origin"]["body"]["source_id"], reference["origin"]["body"]["key_id"])
        if k is not None:
            okey = k
    if okey is None:
        raise _v("TRUST_MISMATCH", "Origin source key is not pinned.")
    if not audit_mod.verify_origin(reference["origin"], okey["public_key"]):
        raise _v("SIGNATURE_INVALID", "Origin signature invalid.")

    # Artifact hashes: every supplied artifact must match its digest.
    for digest, value in artifacts.items():
        if B(value) != digest:
            raise _v("HASH_MISMATCH", f"Artifact {digest} does not match its bytes.")

    # Corpus cross-check when supplied.
    corpus = artifacts.get(manifest["corpus_hash"])
    if corpus is not None:
        if len(corpus["records"]) != len(manifest["records"]):
            raise _v("HASH_MISMATCH", "Corpus does not match the manifest.")
        for link, rec in zip(manifest["records"], corpus["records"]):
            if link["record_id"] != rec["id"]:
                raise _v("HASH_MISMATCH", "Corpus record order does not match the manifest.")
            if link["content_hash"] != B({"title": rec["title"], "body": rec["body"], "category": rec["category"]}):
                raise _v("HASH_MISMATCH", "Corpus record content does not match the manifest.")

    replay_state = "not_requested"
    if replay:
        replay_state = _replay(bundle, manifest, decision, artifacts)

    if mode == "current":
        if client is None:
            raise ApiError(503, "WORKER_UNAVAILABLE", "Current verification requires an authenticated client.")
        _current_checks(client, bundle, release, keymap)
        freshness = "current"
    else:
        freshness = "unproven"

    return {
        "valid": True,
        "freshness": freshness,
        "release_hash": B(release),
        "replay": replay_state,
    }


def _replay(bundle: dict, manifest: dict, decision: dict | None, artifacts: dict) -> str:
    """Recompute the deterministic decision from supplied inputs."""
    if decision is None:
        raise _v("SCHEMA", "Replay requires an accepted release with a decision.")
    if not bundle["ancestors"]:
        raise _v("SCHEMA", "Replay requires the parent release ancestry.")
    parent = bundle["ancestors"][-1]["release"]
    parent_manifest = bundle["ancestors"][-1]["manifest"]
    request = None
    for r in bundle["receipts"]:
        pass  # request reconstructed below from the decision's bindings
    candidate_hash = decision["candidate_hash"]
    generation = None
    for g in bundle["generations"]:
        if B(g) == decision["generation_hash"]:
            generation = g
    if generation is None:
        raise _v("SCHEMA", "The decision's generation is not in the bundle.")
    request = {
        "stream_id": parent["stream_id"],
        "expected_revision": generation["body"]["expected_revision"],
        "candidate_hash": candidate_hash,
        "generation": generation,
        "mode": decision["mode"],
        "previous_job_id": None,
    }
    needed = [parent_manifest["corpus_hash"], bundle["reference"]["holdout_hash"], candidate_hash]
    for digest in needed:
        if digest not in artifacts:
            raise _v("SCHEMA", f"Replay input {digest} is not supplied.")
    recomputed = evaluate(
        {
            "request": request,
            "parent": parent,
            "manifest": parent_manifest,
            "policy": bundle["policy"],
            "reference": bundle["reference"],
            "artifacts": artifacts,
        }
    )
    if J(recomputed) != J(decision):
        raise _v("REPLAY_MISMATCH", "Recomputed decision does not match.")
    return "matched"


def _current_checks(client, bundle: dict, release: dict, keymap: dict) -> None:
    """Fresh state/key reads for current-mode verification."""
    try:
        stream = client.get_stream(release["stream_id"])
        keys = client.get_keys()
    except ApiError:
        raise
    except Exception as exc:
        raise ApiError(503, "WORKER_UNAVAILABLE", "Online state read failed.") from exc
    if stream["head_release_hash"] != B(release) or stream["state"] != "ACTIVE":
        raise _v("TRUST_MISMATCH", "Release is not the active stream head.")
    live = {k["id"]: k for k in keys["keys"]}
    for kid, key in keymap.items():
        cur = live.get(kid)
        if cur is not None and cur.get("revoked_at_ms") is not None:
            raise _v("TRUST_MISMATCH", f"Key {kid} is currently revoked.")
