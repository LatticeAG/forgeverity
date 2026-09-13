"""Decision reducer and pure evaluator (spec sections 6.3-6.7, 9.4).

Reason order is fixed: HOLDOUT_LEAK short-circuits; then TOO_FEW_VALID,
FILTER_BUDGET, CORPUS_LIMIT, REPLACE_FORBIDDEN; then the numerical gates
SYNTHETIC_LIMIT, REFERENCE_DIVERSITY, PARENT_DIVERSITY, REPETITION,
CATEGORY_LOSS. Equality passes; strict excess or strict shortfall fails.
"""

from __future__ import annotations

from fractions import Fraction

from .canonical import B
from .errors import ApiError, EvaluationError
from .filter import (
    MAX_CANDIDATE_RECORDS,
    MAX_RECORDS_ARTIFACT,
    filter_candidates,
    record_id_conflicts,
    validate_candidate_document,
)
from .metrics import (
    SAMPLE_MAX,
    SAMPLE_MIN_PRODUCTION,
    category_counts,
    coverage,
    metric_set,
    record_hash,
)
from .schema import (
    DECISION_V,
    SUITES,
    validate_artifact,
    validate_job_request,
    validate_manifest,
    validate_policy,
    validate_reference,
    validate_release,
)

CORPUS_MAX = MAX_RECORDS_ARTIFACT


def _ratio_bps(ratio: Fraction) -> int:
    return (10000 * ratio.numerator) // ratio.denominator


def reduce_gate(
    policy: dict,
    *,
    submitted_count: int,
    valid_count: int,
    excluded_count: int,
    proposed_count: int,
    synthetic_count: int,
    mode: str,
    sample_size_ok: bool = True,
    vendi_reference_ratio: Fraction | None = None,
    vendi_parent_ratio: Fraction | None = None,
    self_bleu_increase_bps: int | None = None,
    category_min_ratio: Fraction | None = None,
    metric_sets: dict | None = None,
    proposed_corpus_hash: str | None = None,
) -> dict:
    """The section-6.7 reducer. Returns a decision projection with verdict,
    ordered reasons, metrics (or null), and proposed_corpus_hash (or null)."""
    reasons: list[str] = []
    if valid_count < policy["min_candidates"]:
        reasons.append("TOO_FEW_VALID")
    if excluded_count * 10000 > policy["max_filter_bps"] * submitted_count:
        reasons.append("FILTER_BUDGET")
    if proposed_count > CORPUS_MAX:
        reasons.append("CORPUS_LIMIT")
    if mode == "replace":
        reasons.append("REPLACE_FORBIDDEN")

    if "TOO_FEW_VALID" in reasons or "CORPUS_LIMIT" in reasons or not sample_size_ok:
        return {
            "verdict": "reject",
            "reasons": reasons,
            "metrics": None,
            "proposed_corpus_hash": None,
        }

    # Materialized proposal: numerical gates evaluate on exact rationals.
    vendi_reference_ratio = vendi_reference_ratio if vendi_reference_ratio is not None else Fraction(1)
    vendi_parent_ratio = vendi_parent_ratio if vendi_parent_ratio is not None else Fraction(1)
    self_bleu_increase_bps = self_bleu_increase_bps if self_bleu_increase_bps is not None else 0
    category_min_ratio = category_min_ratio if category_min_ratio is not None else Fraction(1)

    if synthetic_count * 10000 > policy["max_synthetic_bps"] * proposed_count:
        reasons.append("SYNTHETIC_LIMIT")
    if vendi_reference_ratio * 10000 < Fraction(policy["min_vendi_reference_bps"]):
        reasons.append("REFERENCE_DIVERSITY")
    if vendi_parent_ratio * 10000 < Fraction(policy["min_vendi_parent_bps"]):
        reasons.append("PARENT_DIVERSITY")
    if self_bleu_increase_bps > policy["max_self_bleu_increase_bps"]:
        reasons.append("REPETITION")
    if category_min_ratio * 10000 < Fraction(policy["min_category_coverage_bps"]):
        reasons.append("CATEGORY_LOSS")

    synthetic_bps = (10000 * synthetic_count) // proposed_count if proposed_count else 0
    filter_bps = (10000 * excluded_count) // submitted_count if submitted_count else 0
    vendi_reference_bps = _ratio_bps(vendi_reference_ratio)
    vendi_parent_bps = _ratio_bps(vendi_parent_ratio)
    category_coverage_bps = min(10000, _ratio_bps(category_min_ratio))
    collapse_proxy_bps = min(
        10000,
        max(
            0,
            10000 - vendi_reference_bps,
            10000 - vendi_parent_bps,
            self_bleu_increase_bps,
            10000 - category_coverage_bps,
        ),
    )

    sets = metric_sets or {}
    metrics = {
        "reference": sets["reference"],
        "parent": sets["parent"],
        "proposed": sets["proposed"],
        "vendi_reference_bps": vendi_reference_bps,
        "vendi_parent_bps": vendi_parent_bps,
        "self_bleu_increase_bps": self_bleu_increase_bps,
        "category_coverage_bps": category_coverage_bps,
        "synthetic_bps": synthetic_bps,
        "filter_bps": filter_bps,
        "collapse_proxy_bps": collapse_proxy_bps,
    }
    return {
        "verdict": "accept" if not reasons else "reject",
        "reasons": reasons,
        "metrics": metrics,
        "proposed_corpus_hash": proposed_corpus_hash,
    }


def decision_projection(decision: dict) -> dict:
    return {"verdict": decision["verdict"], "reasons": decision["reasons"]}


def _require(cond: bool, status: int, code: str, msg: str) -> None:
    if not cond:
        raise ApiError(status, code, msg)


def _artifact(artifacts: dict, digest: str, what: str) -> dict:
    obj = artifacts.get(digest)
    if obj is None:
        raise EvaluationError("ARTIFACT_CORRUPT", f"Missing {what} artifact {digest}.")
    if B(obj) != digest:
        raise EvaluationError("ARTIFACT_CORRUPT", f"{what} artifact digest does not match its bytes.")
    return obj


def evaluate(inputs: dict) -> dict:
    """Pure evaluator: {request,parent,manifest,policy,reference,artifacts}
    -> DecisionCore. Validates every pin; cannot create receipts, mutate
    streams, or grant acceptance by itself."""
    allowed = {"request", "parent", "manifest", "policy", "reference", "artifacts"}
    if not isinstance(inputs, dict) or set(inputs) - allowed:
        raise ApiError(400, "SCHEMA", "evaluate input must be the closed evaluate object.")
    request = validate_job_request(inputs.get("request"))
    parent = validate_release(inputs.get("parent"))
    manifest = validate_manifest(inputs.get("manifest"))
    policy = validate_policy(inputs.get("policy"))
    reference = validate_reference(inputs.get("reference"))
    artifacts = inputs.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ApiError(400, "SCHEMA", "artifacts must be a digest-keyed map.")
    for digest_key in artifacts:
        if not isinstance(digest_key, str):
            raise ApiError(400, "SCHEMA", "artifact keys must be digests.")

    # Pin validation.
    _require(policy["reference_id"] == reference["id"], 422, "GENERATION_BINDING", "Policy pins a different reference ID.")
    _require(policy["reference_hash"] == B(reference), 422, "HASH_MISMATCH", "Policy reference_hash does not match the reference.")
    _require(manifest["policy_hash"] == B(policy), 422, "HASH_MISMATCH", "Manifest policy_hash mismatch.")
    _require(manifest["reference_hash"] == B(reference), 422, "HASH_MISMATCH", "Manifest reference_hash mismatch.")
    _require(parent["manifest_hash"] == B(manifest), 422, "HASH_MISMATCH", "Parent release manifest_hash mismatch.")
    _require(parent["policy_hash"] == B(policy), 422, "HASH_MISMATCH", "Parent release policy_hash mismatch.")
    _require(parent["reference_hash"] == B(reference), 422, "HASH_MISMATCH", "Parent release reference_hash mismatch.")
    _require(parent["suite"] == SUITES[0], 422, "UNSUPPORTED_VERSION", "Unsupported suite.")
    _require(manifest["stream_id"] == request["stream_id"], 422, "GENERATION_BINDING", "Request stream does not match the manifest.")
    _require(parent["stream_id"] == request["stream_id"], 422, "GENERATION_BINDING", "Request stream does not match the release.")
    _require(manifest["project_id"] == reference["project_id"], 422, "GENERATION_BINDING", "Project mismatch.")
    _require(manifest["revision"] == parent["revision"], 422, "GENERATION_BINDING", "Manifest/release revision mismatch.")
    _require(request["expected_revision"] >= parent["revision"], 422, "GENERATION_BINDING", "expected_revision precedes the parent release.")

    generation = request["generation"]
    gbody = generation["body"]
    _require(gbody["project_id"] == manifest["project_id"], 422, "GENERATION_BINDING", "Generation project mismatch.")
    _require(gbody["stream_id"] == request["stream_id"], 422, "GENERATION_BINDING", "Generation stream mismatch.")
    _require(gbody["expected_revision"] == request["expected_revision"], 422, "GENERATION_BINDING", "Generation revision mismatch.")
    _require(gbody["candidate_hash"] == request["candidate_hash"], 422, "GENERATION_BINDING", "Generation candidate_hash mismatch.")

    parent_corpus = validate_artifact(_artifact(artifacts, manifest["corpus_hash"], "parent corpus"), strict_tickets=True)
    holdout = validate_artifact(_artifact(artifacts, reference["holdout_hash"], "holdout"), strict_tickets=True)
    candidate = _artifact(artifacts, request["candidate_hash"], "candidate")
    candidate = validate_artifact(candidate, strict_tickets=False)

    # Manifest records must match the parent corpus exactly (sorted, complete).
    links = manifest["records"]
    precords = parent_corpus["records"]
    _require(len(links) == len(precords), 422, "HASH_MISMATCH", "Manifest record count does not match the corpus.")
    for link, rec in zip(links, precords):
        _require(
            link["record_id"] == rec["id"] and link["content_hash"] == record_hash(rec),
            422,
            "HASH_MISMATCH",
            "Manifest record link does not match corpus content.",
        )

    crecords = candidate["records"]
    validate_candidate_document(crecords)
    if len(crecords) > MAX_CANDIDATE_RECORDS:
        raise ApiError(413, "RECORD_LIMIT", "Candidate artifact exceeds 1024 records.")
    conflict = record_id_conflicts(crecords, precords)
    if conflict is not None:
        raise ApiError(400, "RECORD_ID_CONFLICT", f"Record {conflict} conflicts with parent corpus content.")

    submitted_count = len(crecords)
    result = filter_candidates(crecords, precords, holdout["records"], policy["categories"])
    excluded_count = len(result.excluded)

    base = {
        "v": DECISION_V,
        "suite": SUITES[0],
        "policy_hash": B(policy),
        "reference_hash": B(reference),
        "parent_release_hash": B(parent),
        "candidate_hash": request["candidate_hash"],
        "generation_hash": B(generation),
        "mode": request["mode"],
        "submitted_count": submitted_count,
    }

    if result.holdout_leak:
        return {
            **base,
            "accepted_candidate_ids": [],
            "excluded": [],
            "proposed_corpus_hash": None,
            "metrics": None,
            "verdict": "reject",
            "reasons": ["HOLDOUT_LEAK"],
        }

    survivors = result.survivors
    accepted_ids = [r["id"] for r in survivors]  # already record-ID sorted
    if request["mode"] == "mix":
        proposed = sorted(precords + survivors, key=lambda r: r["id"])
        parent_synthetic = sum(1 for link in links if link["origin"] == "synthetic")
        synthetic_count = parent_synthetic + len(survivors)
    else:  # replace: diagnostic proposal is only the filtered survivors
        proposed = survivors
        synthetic_count = len(survivors)
    proposed_count = len(proposed)

    m = min(SAMPLE_MAX, len(holdout["records"]), len(precords), proposed_count)
    sample_size_ok = m >= SAMPLE_MIN_PRODUCTION

    # Early-null cases never materialize metrics or a corpus hash.
    pre_reasons: list[str] = []
    if len(survivors) < policy["min_candidates"]:
        pre_reasons.append("TOO_FEW_VALID")
    early_null = bool(pre_reasons) or proposed_count > CORPUS_MAX or not sample_size_ok

    if early_null:
        reduced = reduce_gate(
            policy,
            submitted_count=submitted_count,
            valid_count=len(survivors),
            excluded_count=excluded_count,
            proposed_count=proposed_count,
            synthetic_count=synthetic_count,
            mode=request["mode"],
            sample_size_ok=sample_size_ok,
            proposed_corpus_hash=None,
        )
        return {
            **base,
            "accepted_candidate_ids": accepted_ids,
            "excluded": result.excluded,
            "proposed_corpus_hash": None,
            "metrics": None,
            "verdict": reduced["verdict"],
            "reasons": reduced["reasons"],
        }

    corpus_artifact = {"v": "fv.artifact/1", "kind": "tickets", "records": proposed}
    proposed_corpus_hash = B(corpus_artifact)

    reference_set = metric_set(holdout["records"], m)
    parent_set = metric_set(precords, m)
    proposed_set = metric_set(proposed, m)

    from fractions import Fraction as _F

    v_ref = _F(int(reference_set["vendi"]["numerator"]), int(reference_set["vendi"]["denominator"]))
    v_par = _F(int(parent_set["vendi"]["numerator"]), int(parent_set["vendi"]["denominator"]))
    v_prop = _F(int(proposed_set["vendi"]["numerator"]), int(proposed_set["vendi"]["denominator"]))
    vendi_reference_ratio = v_prop / v_ref
    vendi_parent_ratio = v_prop / v_par
    self_bleu_increase_bps = proposed_set["self_bleu_bps"] - reference_set["self_bleu_bps"]

    holdout_counts = category_counts(holdout["records"])
    proposed_counts = category_counts(proposed)
    _cov_bps, min_ratio = coverage(holdout_counts, proposed_counts)

    reduced = reduce_gate(
        policy,
        submitted_count=submitted_count,
        valid_count=len(survivors),
        excluded_count=excluded_count,
        proposed_count=proposed_count,
        synthetic_count=synthetic_count,
        mode=request["mode"],
        sample_size_ok=True,
        vendi_reference_ratio=vendi_reference_ratio,
        vendi_parent_ratio=vendi_parent_ratio,
        self_bleu_increase_bps=self_bleu_increase_bps,
        category_min_ratio=min_ratio,
        metric_sets={"reference": reference_set, "parent": parent_set, "proposed": proposed_set},
        proposed_corpus_hash=proposed_corpus_hash,
    )

    return {
        **base,
        "accepted_candidate_ids": accepted_ids,
        "excluded": result.excluded,
        "proposed_corpus_hash": proposed_corpus_hash,
        "metrics": reduced["metrics"],
        "verdict": reduced["verdict"],
        "reasons": reduced["reasons"],
    }
