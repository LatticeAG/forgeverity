"""Normative validators for the section-5 closed type algebra.

Every object is closed (unknown keys are UNKNOWN_FIELD), version/suite
literals are checked after shape and before remaining field errors
(UNSUPPORTED_VERSION), and all other violations are SCHEMA. Reference-content
failures are remapped to REFERENCE_INVALID by the registration path.
"""

from __future__ import annotations

import re
from math import gcd

from .canonical import INT_MAX, INT_MIN, b64u_decode
from .errors import ApiError
from .ids import id_regex

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
PRINTABLE_RE = re.compile(r"^[\x20-\x7e]*$")
TEXT_ALLOWED_RE = re.compile(r"^[\x20-\x7e\n]*$")

SUITES = ("tickets-lexical-1",)
JOB_STATES = (
    "QUEUED",
    "FILTERING",
    "SCORING",
    "COMMITTING",
    "ACCEPTED",
    "REJECTED",
    "FAILED",
    "STALE",
    "CANCELLED",
)
STREAM_STATES = ("ACTIVE", "PAUSED")
MODES = ("mix", "replace")
FILTER_CODES = (
    "SHAPE",
    "TEXT",
    "CATEGORY",
    "DUP_CANDIDATE",
    "DUP_PARENT",
    "NEAR_CANDIDATE",
    "NEAR_PARENT",
)
GATE_REASONS = (
    "HOLDOUT_LEAK",
    "TOO_FEW_VALID",
    "FILTER_BUDGET",
    "CORPUS_LIMIT",
    "REPLACE_FORBIDDEN",
    "SYNTHETIC_LIMIT",
    "REFERENCE_DIVERSITY",
    "PARENT_DIVERSITY",
    "REPETITION",
    "CATEGORY_LOSS",
)
EVENT_NAMES = (
    "REFERENCE_REGISTERED",
    "POLICY_REGISTERED",
    "STREAM_CREATED",
    "STREAM_PAUSED",
    "STREAM_RESUMED",
    "JOB_QUEUED",
    "FILTER_STARTED",
    "SCORE_STARTED",
    "COMMIT_STARTED",
    "JOB_ACCEPTED",
    "JOB_REJECTED",
    "JOB_FAILED",
    "JOB_STALE",
    "JOB_CANCELLED",
    "LEASE_RECOVERED",
    "CONSUMED",
    "KEY_ROTATED",
    "CHECKPOINTED",
    "MIGRATED",
    "TOKEN_ISSUED",
    "TOKEN_REVOKED",
)
KEY_PURPOSES = ("receipt", "origin", "generator")
ROLES = ("admin", "producer", "consumer", "viewer", "auditor")
ORIGINS = ("human_attested", "synthetic")

ARTIFACT_V = "fv.artifact/1"
ORIGIN_V = "fv.origin/1"
REFERENCE_V = "fv.reference/1"
POLICY_V = "fv.policy/1"
GENERATION_V = "fv.generation/1"
MANIFEST_V = "fv.manifest/1"
STREAM_V = "fv.stream/1"
DECISION_V = "fv.decision/1"
RELEASE_V = "fv.release/1"
JOB_V = "fv.job/1"
AUDIT_V = "fv.audit/1"
CONSUMPTION_V = "fv.consumption/1"
TRUST_V = "fv.trust/1"
EXPORT_V = "fv.sunlight-export/1"
EXPORT_ACK_V = "fv.export-ack/1"
GENERATE_V = "fv.generate/1"
GENERATED_V = "fv.generated/1"
CONFIG_V = "fv.config/1"


def _fail(code: str, msg: str) -> ApiError:
    status = {"UNKNOWN_FIELD": 400, "SCHEMA": 400, "UNSUPPORTED_VERSION": 422}[code]
    return ApiError(status, code, msg)


def _obj(v: object, name: str) -> dict:
    if not isinstance(v, dict):
        raise _fail("SCHEMA", f"{name} must be an object.")
    return v


def _unknown(obj: dict, allowed: set[str], name: str) -> None:
    extra = sorted(set(obj) - allowed)
    if extra:
        raise _fail("UNKNOWN_FIELD", f"{name} has unknown field {extra[0]!r}.")


def _literal(obj: dict, key: str, expected: str, name: str) -> None:
    if key in obj and obj[key] != expected:
        raise _fail("UNSUPPORTED_VERSION", f"{name}.{key} must be {expected!r}.")


def _required(obj: dict, required: set[str], name: str) -> None:
    for key in sorted(required - set(obj)):
        raise _fail("SCHEMA", f"{name} is missing required field {key!r}.")


def _check(obj: object, name: str, allowed: set[str], required: set[str], literals: dict[str, str] | None = None) -> dict:
    o = _obj(obj, name)
    _unknown(o, allowed, name)
    for key, expected in (literals or {}).items():
        _literal(o, key, expected, name)
    _required(o, required, name)
    return o


def _int(v: object, name: str, lo: int = INT_MIN, hi: int = INT_MAX) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < lo or v > hi:
        raise _fail("SCHEMA", f"{name} must be an integer in [{lo},{hi}].")
    return v


def _str(v: object, name: str, lo: int = 0, hi: int | None = None, pattern: re.Pattern | None = None) -> str:
    if not isinstance(v, str):
        raise _fail("SCHEMA", f"{name} must be a string.")
    if len(v) < lo or (hi is not None and len(v) > hi):
        raise _fail("SCHEMA", f"{name} length must be in [{lo},{hi}].")
    if pattern is not None and not pattern.match(v):
        raise _fail("SCHEMA", f"{name} has an invalid form.")
    return v


def _enum(v: object, name: str, options: tuple[str, ...]) -> str:
    if not isinstance(v, str) or v not in options:
        raise _fail("SCHEMA", f"{name} must be one of {options}.")
    return v


def _digest(v: object, name: str) -> str:
    if not isinstance(v, str) or not DIGEST_RE.match(v):
        raise _fail("SCHEMA", f"{name} must be a sha256 digest.")
    return v


def _id(v: object, name: str, prefix: str) -> str:
    if not isinstance(v, str) or not id_regex(prefix).match(v):
        raise _fail("SCHEMA", f"{name} must be an ID with prefix {prefix}.")
    return v


def _b64(v: object, name: str, nbytes: int) -> str:
    if not isinstance(v, str):
        raise _fail("SCHEMA", f"{name} must be a base64url string.")
    try:
        b64u_decode(v, nbytes)
    except ValueError as exc:
        raise _fail("SCHEMA", f"{name} is not canonical base64url of {nbytes} bytes.") from exc
    return v


def _key(v: object, name: str) -> str:
    return _b64(v, name, 32)


def _sig(v: object, name: str) -> str:
    return _b64(v, name, 64)


def _rational(v: object, name: str) -> dict:
    o = _check(v, name, {"numerator", "denominator"}, {"numerator", "denominator"})
    for field in ("numerator", "denominator"):
        s = o[field]
        if not isinstance(s, str) or not re.match(r"^(0|[1-9][0-9]*)$", s):
            raise _fail("SCHEMA", f"{name}.{field} must be a decimal integer string without leading zeros.")
    num, den = int(o["numerator"]), int(o["denominator"])
    if den <= 0:
        raise _fail("SCHEMA", f"{name}.denominator must be positive.")
    if num > INT_MAX or den > INT_MAX:
        raise _fail("SCHEMA", f"{name} exceeds the safe integer range.")
    if gcd(num, den) != 1:
        raise _fail("SCHEMA", f"{name} must be reduced to coprime terms.")
    return o


def _list(v: object, name: str, lo: int = 0, hi: int | None = None) -> list:
    if not isinstance(v, list):
        raise _fail("SCHEMA", f"{name} must be an array.")
    if len(v) < lo or (hi is not None and len(v) > hi):
        raise _fail("SCHEMA", f"{name} length must be in [{lo},{hi}].")
    return v


def _json_value(v: object, name: str, depth: int = 0) -> object:
    if depth > 16:
        raise _fail("SCHEMA", f"{name} exceeds JSON depth 16.")
    if v is None or isinstance(v, (bool, int, str)):
        if isinstance(v, int) and not isinstance(v, bool) and not (INT_MIN <= v <= INT_MAX):
            raise _fail("SCHEMA", f"{name} integer out of range.")
        return v
    if isinstance(v, list):
        for item in v:
            _json_value(item, name, depth + 1)
        return v
    if isinstance(v, dict):
        for key, item in v.items():
            if not isinstance(key, str):
                raise _fail("SCHEMA", f"{name} object key must be a string.")
            _json_value(item, name, depth + 1)
        return v
    raise _fail("SCHEMA", f"{name} must be a JSON value.")


def _category(v: object, name: str) -> str:
    return _str(v, name, 1, 32, CATEGORY_RE)


def _categories(v: object, name: str, lo: int = 1, hi: int = 32) -> list:
    items = _list(v, name, lo, hi)
    out = [_category(item, f"{name}[{i}]") for i, item in enumerate(items)]
    if len(set(out)) != len(out) or out != sorted(out):
        raise _fail("SCHEMA", f"{name} must be strictly ASCII-sorted and unique.")
    return out


def text_charset_ok(text: str) -> bool:
    return bool(TEXT_ALLOWED_RE.match(text))


def _ticket(v: object, name: str = "Ticket") -> dict:
    o = _check(v, name, {"id", "title", "body", "category"}, {"id", "title", "body", "category"})
    _id(o["id"], f"{name}.id", "fvrec_")
    _str(o["title"], f"{name}.title", 1, 160)
    _str(o["body"], f"{name}.body", 1, 8192)
    _category(o["category"], f"{name}.category")
    return o


def _ingest_record(v: object, name: str) -> dict:
    o = _check(v, name, {"id", "title", "body", "category"}, {"id"})
    _id(o["id"], f"{name}.id", "fvrec_")
    for field in ("title", "body", "category"):
        if field in o:
            _json_value(o[field], f"{name}.{field}")
    return o


def validate_artifact(v: object, *, strict_tickets: bool) -> dict:
    """Validate an fv.artifact/1 envelope. Records must be sorted by record ID
    with no repeats; an invalid or out-of-order ID invalidates the document."""
    name = "TicketArtifact" if strict_tickets else "IngestArtifact"
    o = _check(v, name, {"v", "kind", "records"}, {"v", "kind", "records"}, {"v": ARTIFACT_V, "kind": "tickets"})
    records = _list(o["records"], f"{name}.records", 1, 4096)
    prev = None
    for i, rec in enumerate(records):
        r = _ingest_record(rec, f"{name}.records[{i}]") if not strict_tickets else _ticket(rec, f"{name}.records[{i}]")
        rid = r["id"]
        if prev is not None and rid <= prev:
            raise _fail("SCHEMA", f"{name}.records must be sorted by record ID with no repeats.")
        prev = rid
        if strict_tickets:
            _ticket_text(r, f"{name}.records[{i}]")
    return o


def _ticket_text(o: dict, name: str) -> None:
    if not text_charset_ok(o["title"]) or not text_charset_ok(o["body"]):
        raise _fail("SCHEMA", f"{name} text must be LF plus ASCII 0x20-0x7E.")


def validate_ticket(v: object) -> dict:
    o = _ticket(v)
    if not text_charset_ok(o["title"]) or not text_charset_ok(o["body"]):
        raise _fail("SCHEMA", "Ticket text must be LF plus ASCII 0x20-0x7E.")
    return o


def validate_origin_body(v: object) -> dict:
    o = _check(
        v,
        "OriginAssertion",
        {"v", "project_id", "source_id", "train_hash", "holdout_hash", "origin", "collected_at_ms", "key_id"},
        {"v", "project_id", "source_id", "train_hash", "holdout_hash", "origin", "collected_at_ms", "key_id"},
        {"v": ORIGIN_V},
    )
    _id(o["project_id"], "OriginAssertion.project_id", "fvprj_")
    _id(o["source_id"], "OriginAssertion.source_id", "fvsrc_")
    _digest(o["train_hash"], "OriginAssertion.train_hash")
    _digest(o["holdout_hash"], "OriginAssertion.holdout_hash")
    if o["origin"] != "human_attested":
        raise _fail("SCHEMA", "OriginAssertion.origin must be human_attested.")
    _int(o["collected_at_ms"], "OriginAssertion.collected_at_ms", 0)
    _id(o["key_id"], "OriginAssertion.key_id", "fvkey_")
    return o


def validate_signed_origin(v: object) -> dict:
    o = _check(v, "SignedOrigin", {"body", "signature"}, {"body", "signature"})
    validate_origin_body(o["body"])
    _sig(o["signature"], "SignedOrigin.signature")
    return o


def validate_reference(v: object) -> dict:
    o = _check(
        v,
        "Reference",
        {"v", "id", "project_id", "train_hash", "holdout_hash", "origin", "created_at_ms"},
        {"v", "id", "project_id", "train_hash", "holdout_hash", "origin", "created_at_ms"},
        {"v": REFERENCE_V},
    )
    _id(o["id"], "Reference.id", "fvref_")
    _id(o["project_id"], "Reference.project_id", "fvprj_")
    _digest(o["train_hash"], "Reference.train_hash")
    _digest(o["holdout_hash"], "Reference.holdout_hash")
    validate_signed_origin(o["origin"])
    _int(o["created_at_ms"], "Reference.created_at_ms", 0)
    return o


POLICY_BOUNDS = {
    "min_candidates": (32, 1024),
    "max_filter_bps": (0, 2500),
    "min_vendi_reference_bps": (1, 10000),
    "min_vendi_parent_bps": (1, 10000),
    "max_self_bleu_increase_bps": (0, 2000),
    "min_category_coverage_bps": (1, 10000),
    "max_synthetic_bps": (0, 8000),
    "max_rounds": (1, 3),
    "max_total_candidates": (32, 3072),
}
POLICY_DEFAULTS = {
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


def validate_policy(v: object) -> dict:
    o = _check(
        v,
        "Policy",
        {
            "v",
            "suite",
            "reference_id",
            "reference_hash",
            "categories",
            "min_candidates",
            "max_filter_bps",
            "min_vendi_reference_bps",
            "min_vendi_parent_bps",
            "max_self_bleu_increase_bps",
            "min_category_coverage_bps",
            "max_synthetic_bps",
            "max_rounds",
            "max_total_candidates",
        },
        {
            "v",
            "suite",
            "reference_id",
            "reference_hash",
            "categories",
            "min_candidates",
            "max_filter_bps",
            "min_vendi_reference_bps",
            "min_vendi_parent_bps",
            "max_self_bleu_increase_bps",
            "min_category_coverage_bps",
            "max_synthetic_bps",
            "max_rounds",
            "max_total_candidates",
        },
        {"v": POLICY_V, "suite": SUITES[0]},
    )
    _id(o["reference_id"], "Policy.reference_id", "fvref_")
    _digest(o["reference_hash"], "Policy.reference_hash")
    _categories(o["categories"], "Policy.categories")
    for field, (lo, hi) in POLICY_BOUNDS.items():
        _int(o[field], f"Policy.{field}", lo, hi)
    if o["max_total_candidates"] < o["min_candidates"]:
        raise _fail("SCHEMA", "Policy.max_total_candidates must be at least min_candidates.")
    return o


def validate_generation_body(v: object) -> dict:
    o = _check(
        v,
        "GenerationBody",
        {
            "v",
            "project_id",
            "stream_id",
            "expected_revision",
            "candidate_hash",
            "generator",
            "generator_version",
            "generator_config_hash",
            "model_artifact_hash",
            "parent_model_hash",
            "prompt_hash",
            "seed",
            "created_at_ms",
            "key_id",
        },
        {
            "v",
            "project_id",
            "stream_id",
            "expected_revision",
            "candidate_hash",
            "generator",
            "generator_version",
            "generator_config_hash",
            "model_artifact_hash",
            "parent_model_hash",
            "prompt_hash",
            "seed",
            "created_at_ms",
            "key_id",
        },
        {"v": GENERATION_V},
    )
    _id(o["project_id"], "GenerationBody.project_id", "fvprj_")
    _id(o["stream_id"], "GenerationBody.stream_id", "fvstr_")
    _int(o["expected_revision"], "GenerationBody.expected_revision", 0)
    _digest(o["candidate_hash"], "GenerationBody.candidate_hash")
    if o["generator"] != "ForgeDistill":
        raise _fail("SCHEMA", "GenerationBody.generator must be ForgeDistill.")
    _str(o["generator_version"], "GenerationBody.generator_version", 1, 64, VERSION_RE)
    _digest(o["generator_config_hash"], "GenerationBody.generator_config_hash")
    _digest(o["model_artifact_hash"], "GenerationBody.model_artifact_hash")
    if o["parent_model_hash"] is not None:
        _digest(o["parent_model_hash"], "GenerationBody.parent_model_hash")
    _digest(o["prompt_hash"], "GenerationBody.prompt_hash")
    _str(o["seed"], "GenerationBody.seed", 1, 128, PRINTABLE_RE)
    _int(o["created_at_ms"], "GenerationBody.created_at_ms", 0)
    _id(o["key_id"], "GenerationBody.key_id", "fvkey_")
    return o


def validate_generation(v: object) -> dict:
    o = _check(v, "Generation", {"body", "signature"}, {"body", "signature"})
    validate_generation_body(o["body"])
    _sig(o["signature"], "Generation.signature")
    return o


def validate_job_request(v: object) -> dict:
    o = _check(
        v,
        "JobRequest",
        {"stream_id", "expected_revision", "candidate_hash", "generation", "mode", "previous_job_id"},
        {"stream_id", "expected_revision", "candidate_hash", "generation", "mode", "previous_job_id"},
    )
    _id(o["stream_id"], "JobRequest.stream_id", "fvstr_")
    _int(o["expected_revision"], "JobRequest.expected_revision", 0)
    _digest(o["candidate_hash"], "JobRequest.candidate_hash")
    validate_generation(o["generation"])
    _enum(o["mode"], "JobRequest.mode", MODES)
    if o["previous_job_id"] is not None:
        _id(o["previous_job_id"], "JobRequest.previous_job_id", "fvjob_")
    return o


def validate_record_link(v: object) -> dict:
    o = _check(v, "RecordLink", {"record_id", "content_hash", "origin", "source_hash"}, {"record_id", "content_hash", "origin", "source_hash"})
    _id(o["record_id"], "RecordLink.record_id", "fvrec_")
    _digest(o["content_hash"], "RecordLink.content_hash")
    _enum(o["origin"], "RecordLink.origin", ORIGINS)
    _digest(o["source_hash"], "RecordLink.source_hash")
    return o


def validate_manifest(v: object) -> dict:
    o = _check(
        v,
        "Manifest",
        {"v", "project_id", "stream_id", "revision", "parent_release_hash", "reference_hash", "policy_hash", "corpus_hash", "records", "generation_hash"},
        {"v", "project_id", "stream_id", "revision", "parent_release_hash", "reference_hash", "policy_hash", "corpus_hash", "records", "generation_hash"},
        {"v": MANIFEST_V},
    )
    _id(o["project_id"], "Manifest.project_id", "fvprj_")
    _id(o["stream_id"], "Manifest.stream_id", "fvstr_")
    _int(o["revision"], "Manifest.revision", 0)
    if o["parent_release_hash"] is not None:
        _digest(o["parent_release_hash"], "Manifest.parent_release_hash")
    _digest(o["reference_hash"], "Manifest.reference_hash")
    _digest(o["policy_hash"], "Manifest.policy_hash")
    _digest(o["corpus_hash"], "Manifest.corpus_hash")
    records = _list(o["records"], "Manifest.records", 1, 4096)
    prev = None
    for i, link in enumerate(records):
        r = validate_record_link(link)
        if prev is not None and r["record_id"] <= prev:
            raise _fail("SCHEMA", "Manifest.records must be sorted by record ID.")
        prev = r["record_id"]
    if o["generation_hash"] is not None:
        _digest(o["generation_hash"], "Manifest.generation_hash")
    return o


def validate_stream(v: object) -> dict:
    o = _check(
        v,
        "Stream",
        {"v", "id", "project_id", "state", "revision", "policy_hash", "reference_hash", "head_release_hash"},
        {"v", "id", "project_id", "state", "revision", "policy_hash", "reference_hash", "head_release_hash"},
        {"v": STREAM_V},
    )
    _id(o["id"], "Stream.id", "fvstr_")
    _id(o["project_id"], "Stream.project_id", "fvprj_")
    _enum(o["state"], "Stream.state", STREAM_STATES)
    _int(o["revision"], "Stream.revision", 0)
    _digest(o["policy_hash"], "Stream.policy_hash")
    _digest(o["reference_hash"], "Stream.reference_hash")
    _digest(o["head_release_hash"], "Stream.head_release_hash")
    return o


def validate_exclusion(v: object) -> dict:
    o = _check(v, "Exclusion", {"record_id", "code"}, {"record_id", "code"})
    _id(o["record_id"], "Exclusion.record_id", "fvrec_")
    _enum(o["code"], "Exclusion.code", FILTER_CODES)
    return o


def validate_metric_set(v: object) -> dict:
    o = _check(v, "MetricSet", {"sample_count", "vendi", "self_bleu_bps"}, {"sample_count", "vendi", "self_bleu_bps"})
    _int(o["sample_count"], "MetricSet.sample_count", 0)
    _rational(o["vendi"], "MetricSet.vendi")
    _int(o["self_bleu_bps"], "MetricSet.self_bleu_bps", 0, 10000)
    return o


def validate_gate_metrics(v: object) -> dict:
    o = _check(
        v,
        "GateMetrics",
        {
            "reference",
            "parent",
            "proposed",
            "vendi_reference_bps",
            "vendi_parent_bps",
            "self_bleu_increase_bps",
            "category_coverage_bps",
            "synthetic_bps",
            "filter_bps",
            "collapse_proxy_bps",
        },
        {
            "reference",
            "parent",
            "proposed",
            "vendi_reference_bps",
            "vendi_parent_bps",
            "self_bleu_increase_bps",
            "category_coverage_bps",
            "synthetic_bps",
            "filter_bps",
            "collapse_proxy_bps",
        },
    )
    validate_metric_set(o["reference"])
    validate_metric_set(o["parent"])
    validate_metric_set(o["proposed"])
    _int(o["vendi_reference_bps"], "GateMetrics.vendi_reference_bps", 0)
    _int(o["vendi_parent_bps"], "GateMetrics.vendi_parent_bps", 0)
    _int(o["self_bleu_increase_bps"], "GateMetrics.self_bleu_increase_bps", -10000, 10000)
    _int(o["category_coverage_bps"], "GateMetrics.category_coverage_bps", 0, 10000)
    _int(o["synthetic_bps"], "GateMetrics.synthetic_bps", 0, 10000)
    _int(o["filter_bps"], "GateMetrics.filter_bps", 0, 10000)
    _int(o["collapse_proxy_bps"], "GateMetrics.collapse_proxy_bps", 0, 10000)
    return o


def validate_decision(v: object) -> dict:
    o = _check(
        v,
        "DecisionCore",
        {
            "v",
            "suite",
            "policy_hash",
            "reference_hash",
            "parent_release_hash",
            "candidate_hash",
            "generation_hash",
            "mode",
            "submitted_count",
            "accepted_candidate_ids",
            "excluded",
            "proposed_corpus_hash",
            "metrics",
            "verdict",
            "reasons",
        },
        {
            "v",
            "suite",
            "policy_hash",
            "reference_hash",
            "parent_release_hash",
            "candidate_hash",
            "generation_hash",
            "mode",
            "submitted_count",
            "accepted_candidate_ids",
            "excluded",
            "proposed_corpus_hash",
            "metrics",
            "verdict",
            "reasons",
        },
        {"v": DECISION_V, "suite": SUITES[0]},
    )
    for field in ("policy_hash", "reference_hash", "parent_release_hash", "candidate_hash", "generation_hash"):
        _digest(o[field], f"DecisionCore.{field}")
    _enum(o["mode"], "DecisionCore.mode", MODES)
    _int(o["submitted_count"], "DecisionCore.submitted_count", 0)
    ids = _list(o["accepted_candidate_ids"], "DecisionCore.accepted_candidate_ids", 0, 4096)
    for i, rid in enumerate(ids):
        _id(rid, f"DecisionCore.accepted_candidate_ids[{i}]", "fvrec_")
    excluded = _list(o["excluded"], "DecisionCore.excluded", 0, 4096)
    for ex in excluded:
        validate_exclusion(ex)
    if o["proposed_corpus_hash"] is not None:
        _digest(o["proposed_corpus_hash"], "DecisionCore.proposed_corpus_hash")
    if o["metrics"] is not None:
        validate_gate_metrics(o["metrics"])
    _enum(o["verdict"], "DecisionCore.verdict", ("accept", "reject"))
    reasons = _list(o["reasons"], "DecisionCore.reasons", 0, len(GATE_REASONS))
    for i, reason in enumerate(reasons):
        _enum(reason, f"DecisionCore.reasons[{i}]", GATE_REASONS)
    return o


def validate_release(v: object) -> dict:
    o = _check(
        v,
        "Release",
        {"v", "kind", "project_id", "stream_id", "revision", "manifest_hash", "decision_hash", "suite", "policy_hash", "reference_hash"},
        {"v", "kind", "project_id", "stream_id", "revision", "manifest_hash", "decision_hash", "suite", "policy_hash", "reference_hash"},
        {"v": RELEASE_V, "suite": SUITES[0]},
    )
    _enum(o["kind"], "Release.kind", ("genesis", "accepted"))
    _id(o["project_id"], "Release.project_id", "fvprj_")
    _id(o["stream_id"], "Release.stream_id", "fvstr_")
    _int(o["revision"], "Release.revision", 0)
    _digest(o["manifest_hash"], "Release.manifest_hash")
    if o["decision_hash"] is not None:
        _digest(o["decision_hash"], "Release.decision_hash")
    _digest(o["policy_hash"], "Release.policy_hash")
    _digest(o["reference_hash"], "Release.reference_hash")
    return o


def validate_key_record(v: object, name: str = "KeyRecord") -> dict:
    o = _check(
        v,
        name,
        {"id", "public_key", "purpose", "valid_from_ms", "valid_until_ms", "revoked_at_ms"},
        {"id", "public_key", "purpose", "valid_from_ms", "valid_until_ms", "revoked_at_ms"},
    )
    _id(o["id"], f"{name}.id", "fvkey_")
    _key(o["public_key"], f"{name}.public_key")
    _enum(o["purpose"], f"{name}.purpose", KEY_PURPOSES)
    _int(o["valid_from_ms"], f"{name}.valid_from_ms", 0)
    _int(o["valid_until_ms"], f"{name}.valid_until_ms", 0)
    if o["valid_until_ms"] <= o["valid_from_ms"]:
        raise _fail("SCHEMA", f"{name}.valid_until_ms must exceed valid_from_ms.")
    if o["revoked_at_ms"] is not None:
        _int(o["revoked_at_ms"], f"{name}.revoked_at_ms", 0)
    return o


def validate_trust(v: object) -> dict:
    o = _check(
        v,
        "TrustSnapshot",
        {"v", "project_id", "receipt_root", "sources", "generators", "previous_hash", "old_signature", "new_signature"},
        {"v", "project_id", "receipt_root", "sources", "generators", "previous_hash", "old_signature", "new_signature"},
        {"v": TRUST_V},
    )
    _id(o["project_id"], "TrustSnapshot.project_id", "fvprj_")
    root = validate_key_record(o["receipt_root"], "TrustSnapshot.receipt_root")
    if root["purpose"] != "receipt":
        raise _fail("SCHEMA", "TrustSnapshot.receipt_root purpose must be receipt.")
    sources = _list(o["sources"], "TrustSnapshot.sources", 0, 1024)
    prev = None
    seen_keys = {root["public_key"]}
    for i, entry in enumerate(sources):
        e = _check(entry, f"TrustSnapshot.sources[{i}]", {"source_id", "key"}, {"source_id", "key"})
        sid = _id(e["source_id"], f"TrustSnapshot.sources[{i}].source_id", "fvsrc_")
        if prev is not None and sid <= prev:
            raise _fail("SCHEMA", "TrustSnapshot.sources must be sorted by source_id.")
        prev = sid
        k = validate_key_record(e["key"], f"TrustSnapshot.sources[{i}].key")
        if k["purpose"] != "origin":
            raise _fail("SCHEMA", "TrustSnapshot source keys must have purpose origin.")
        if k["public_key"] in seen_keys:
            raise _fail("SCHEMA", "TrustSnapshot public keys must be distinct.")
        seen_keys.add(k["public_key"])
    generators = _list(o["generators"], "TrustSnapshot.generators", 0, 1024)
    prev = None
    for i, entry in enumerate(generators):
        k = validate_key_record(entry, f"TrustSnapshot.generators[{i}]")
        if k["purpose"] != "generator":
            raise _fail("SCHEMA", "TrustSnapshot generator keys must have purpose generator.")
        if prev is not None and k["id"] <= prev:
            raise _fail("SCHEMA", "TrustSnapshot.generators must be sorted by key ID.")
        prev = k["id"]
        if k["public_key"] in seen_keys:
            raise _fail("SCHEMA", "TrustSnapshot public keys must be distinct.")
        seen_keys.add(k["public_key"])
    if o["previous_hash"] is not None:
        _digest(o["previous_hash"], "TrustSnapshot.previous_hash")
    if o["old_signature"] is not None:
        _sig(o["old_signature"], "TrustSnapshot.old_signature")
    _sig(o["new_signature"], "TrustSnapshot.new_signature")
    if (o["previous_hash"] is None) != (o["old_signature"] is None):
        raise _fail("SCHEMA", "TrustSnapshot previous_hash and old_signature must both be null or both set.")
    return o


def validate_event_data(v: object) -> dict:
    o = _check(
        v,
        "EventData",
        {"job_id", "stream_id", "from_state", "to_state", "reasons", "revision"},
        {"job_id", "stream_id", "from_state", "to_state", "reasons", "revision"},
    )
    if o["job_id"] is not None:
        _id(o["job_id"], "EventData.job_id", "fvjob_")
    if o["stream_id"] is not None:
        _id(o["stream_id"], "EventData.stream_id", "fvstr_")
    for field in ("from_state", "to_state"):
        if o[field] is not None:
            _enum(o[field], f"EventData.{field}", JOB_STATES + STREAM_STATES)
    reasons = _list(o["reasons"], "EventData.reasons", 0, 64)
    for i, r in enumerate(reasons):
        _str(r, f"EventData.reasons[{i}]", 1, 64)
    if o["revision"] is not None:
        _int(o["revision"], "EventData.revision", 0)
    return o


def validate_audit_body(v: object) -> dict:
    o = _check(
        v,
        "AuditBody",
        {"v", "entry_id", "project_id", "seq", "previous_hash", "at_ms", "event", "subject_hash", "data", "key_id"},
        {"v", "entry_id", "project_id", "seq", "previous_hash", "at_ms", "event", "subject_hash", "data", "key_id"},
        {"v": AUDIT_V},
    )
    _id(o["entry_id"], "AuditBody.entry_id", "fvent_")
    _id(o["project_id"], "AuditBody.project_id", "fvprj_")
    _int(o["seq"], "AuditBody.seq", 1)
    if o["previous_hash"] is not None:
        _digest(o["previous_hash"], "AuditBody.previous_hash")
    _int(o["at_ms"], "AuditBody.at_ms", 0)
    _enum(o["event"], "AuditBody.event", EVENT_NAMES)
    _digest(o["subject_hash"], "AuditBody.subject_hash")
    validate_event_data(o["data"])
    _id(o["key_id"], "AuditBody.key_id", "fvkey_")
    return o


def validate_receipt(v: object) -> dict:
    o = _check(v, "Receipt", {"body", "entry_hash", "signature"}, {"body", "entry_hash", "signature"})
    validate_audit_body(o["body"])
    _digest(o["entry_hash"], "Receipt.entry_hash")
    _sig(o["signature"], "Receipt.signature")
    return o


def validate_release_envelope(v: object) -> dict:
    o = _check(v, "ReleaseEnvelope", {"release", "receipt"}, {"release", "receipt"})
    validate_release(o["release"])
    validate_receipt(o["receipt"])
    return o


def validate_consumption_request(v: object) -> dict:
    o = _check(
        v,
        "ConsumptionRequest",
        {"stream_id", "expected_revision", "release_hash", "manifest_hash", "consumer_label"},
        {"stream_id", "expected_revision", "release_hash", "manifest_hash", "consumer_label"},
    )
    _id(o["stream_id"], "ConsumptionRequest.stream_id", "fvstr_")
    _int(o["expected_revision"], "ConsumptionRequest.expected_revision", 0)
    _digest(o["release_hash"], "ConsumptionRequest.release_hash")
    _digest(o["manifest_hash"], "ConsumptionRequest.manifest_hash")
    _str(o["consumer_label"], "ConsumptionRequest.consumer_label", 1, 128, PRINTABLE_RE)
    return o


def validate_consumption(v: object) -> dict:
    o = _check(v, "Consumption", {"v", "id", "request", "at_ms", "receipt_hash"}, {"v", "id", "request", "at_ms", "receipt_hash"}, {"v": CONSUMPTION_V})
    _id(o["id"], "Consumption.id", "fvcon_")
    validate_consumption_request(o["request"])
    _int(o["at_ms"], "Consumption.at_ms", 0)
    _digest(o["receipt_hash"], "Consumption.receipt_hash")
    return o


def validate_error_body(v: object) -> dict:
    o = _check(v, "ErrorBody", {"code", "message", "retryable", "request_id"}, {"code", "message", "retryable", "request_id"})
    _str(o["code"], "ErrorBody.code", 1, 64)
    _str(o["message"], "ErrorBody.message", 0, 256, PRINTABLE_RE)
    if not isinstance(o["retryable"], bool):
        raise _fail("SCHEMA", "ErrorBody.retryable must be a boolean.")
    _id(o["request_id"], "ErrorBody.request_id", "fvreq_")
    return o


def validate_tip(v: object) -> dict:
    o = _check(v, "TipDescriptor", {"seq", "entry_hash"}, {"seq", "entry_hash"})
    _int(o["seq"], "TipDescriptor.seq", 1)
    _digest(o["entry_hash"], "TipDescriptor.entry_hash")
    return o


def validate_export_bundle(v: object) -> dict:
    o = _check(
        v,
        "ExportBundle",
        {"v", "release", "manifest", "decision", "reference", "policy", "generations", "receipts", "ancestors", "checkpoint", "keys", "trust_snapshots"},
        {"v", "release", "manifest", "decision", "reference", "policy", "generations", "receipts", "ancestors", "checkpoint", "keys", "trust_snapshots"},
        {"v": EXPORT_V},
    )
    validate_release(o["release"])
    validate_manifest(o["manifest"])
    if o["decision"] is not None:
        validate_decision(o["decision"])
    validate_reference(o["reference"])
    validate_policy(o["policy"])
    for i, g in enumerate(_list(o["generations"], "ExportBundle.generations", 0, 4096)):
        validate_generation(g)
    for i, r in enumerate(_list(o["receipts"], "ExportBundle.receipts", 1, 100000)):
        validate_receipt(r)
    for i, a in enumerate(_list(o["ancestors"], "ExportBundle.ancestors", 0, 4096)):
        ao = _check(a, f"ExportBundle.ancestors[{i}]", {"release", "manifest", "decision"}, {"release", "manifest", "decision"})
        validate_release(ao["release"])
        validate_manifest(ao["manifest"])
        if ao["decision"] is not None:
            validate_decision(ao["decision"])
    validate_receipt(o["checkpoint"])
    for i, k in enumerate(_list(o["keys"], "ExportBundle.keys", 1, 4096)):
        validate_key_record(k, f"ExportBundle.keys[{i}]")
    for i, t in enumerate(_list(o["trust_snapshots"], "ExportBundle.trust_snapshots", 1, 64)):
        validate_trust(t)
    return o


def validate_reference_register_request(v: object) -> dict:
    o = _check(v, "ReferenceRegisterRequest", {"origin"}, {"origin"})
    validate_signed_origin(o["origin"])
    return o


def validate_stream_create_request(v: object) -> dict:
    o = _check(v, "StreamCreateRequest", {"policy_hash", "reference_id"}, {"policy_hash", "reference_id"})
    _digest(o["policy_hash"], "StreamCreateRequest.policy_hash")
    _id(o["reference_id"], "StreamCreateRequest.reference_id", "fvref_")
    return o


def validate_stream_state_request(v: object) -> dict:
    o = _check(v, "StreamStateRequest", {"expected_revision", "state", "reason"}, {"expected_revision", "state", "reason"})
    _int(o["expected_revision"], "StreamStateRequest.expected_revision", 0)
    _enum(o["state"], "StreamStateRequest.state", STREAM_STATES)
    _str(o["reason"], "StreamStateRequest.reason", 1, 256, PRINTABLE_RE)
    return o


def validate_job_cancel_request(v: object) -> dict:
    return _check(v, "JobCancelRequest", set(), set())


def validate_token_record(v: object) -> dict:
    o = _check(
        v,
        "TokenRecord",
        {"token_digest", "principal_id", "role", "expires_at_ms", "revoked_at_ms"},
        {"token_digest", "principal_id", "role", "expires_at_ms", "revoked_at_ms"},
    )
    _digest(o["token_digest"], "TokenRecord.token_digest")
    _id(o["principal_id"], "TokenRecord.principal_id", "fvact_")
    _enum(o["role"], "TokenRecord.role", ROLES)
    _int(o["expires_at_ms"], "TokenRecord.expires_at_ms", 0)
    if o["revoked_at_ms"] is not None:
        _int(o["revoked_at_ms"], "TokenRecord.revoked_at_ms", 0)
    return o


def validate_generate_request(v: object) -> dict:
    o = _check(
        v,
        "GenerateRequest",
        {"v", "stream_id", "round", "seed", "count", "categories", "feedback"},
        {"v", "stream_id", "round", "seed", "count", "categories", "feedback"},
        {"v": GENERATE_V},
    )
    _id(o["stream_id"], "GenerateRequest.stream_id", "fvstr_")
    _int(o["round"], "GenerateRequest.round", 1, 3)
    _str(o["seed"], "GenerateRequest.seed", 1, 128, PRINTABLE_RE)
    _int(o["count"], "GenerateRequest.count", 1, 1024)
    _categories(o["categories"], "GenerateRequest.categories", 1, 32)
    feedback = _list(o["feedback"], "GenerateRequest.feedback", 0, len(GATE_REASONS))
    for i, r in enumerate(feedback):
        _enum(r, f"GenerateRequest.feedback[{i}]", GATE_REASONS)
    return o


def validate_generated(v: object) -> dict:
    o = _check(
        v,
        "GeneratedOutput",
        {"v", "artifact", "generator_version", "model_artifact_hash", "parent_model_hash", "prompt_hash", "generator_config_hash", "seed"},
        {"v", "artifact", "generator_version", "model_artifact_hash", "parent_model_hash", "prompt_hash", "generator_config_hash", "seed"},
        {"v": GENERATED_V},
    )
    validate_artifact(o["artifact"], strict_tickets=True)
    _str(o["generator_version"], "GeneratedOutput.generator_version", 1, 64, VERSION_RE)
    _digest(o["model_artifact_hash"], "GeneratedOutput.model_artifact_hash")
    if o["parent_model_hash"] is not None:
        _digest(o["parent_model_hash"], "GeneratedOutput.parent_model_hash")
    _digest(o["prompt_hash"], "GeneratedOutput.prompt_hash")
    _digest(o["generator_config_hash"], "GeneratedOutput.generator_config_hash")
    _str(o["seed"], "GeneratedOutput.seed", 1, 128, PRINTABLE_RE)
    return o


def validate_export_ack(v: object) -> dict:
    o = _check(v, "ExportAck", {"v", "bundle_hash", "status"}, {"v", "bundle_hash", "status"}, {"v": EXPORT_ACK_V})
    _digest(o["bundle_hash"], "ExportAck.bundle_hash")
    _enum(o["status"], "ExportAck.status", ("stored", "duplicate"))
    return o


def validate_capabilities(v: object) -> dict:
    o = _check(
        v,
        "Capabilities",
        {"protocol", "suites", "max_body_bytes", "max_candidate_records", "max_corpus_records", "sample_size"},
        {"protocol", "suites", "max_body_bytes", "max_candidate_records", "max_corpus_records", "sample_size"},
    )
    if o["protocol"] != "fv.http/1":
        raise _fail("SCHEMA", "Capabilities.protocol must be fv.http/1.")
    suites = _list(o["suites"], "Capabilities.suites", 1, 16)
    for s in suites:
        _enum(s, "Capabilities.suites[]", SUITES)
    _int(o["max_body_bytes"], "Capabilities.max_body_bytes", 1)
    _int(o["max_candidate_records"], "Capabilities.max_candidate_records", 1)
    _int(o["max_corpus_records"], "Capabilities.max_corpus_records", 1)
    _int(o["sample_size"], "Capabilities.sample_size", 1)
    return o


def validate_config(v: object) -> dict:
    """Validate the .devin/forgeverity.json local configuration."""
    o = _check(
        v,
        "Config",
        {"v", "project_id", "state_dir", "api", "trust_file", "receipt_key_id", "generator", "limits", "retention", "telemetry"},
        {"v", "project_id", "state_dir", "api", "trust_file", "receipt_key_id", "generator", "limits", "retention", "telemetry"},
        {"v": CONFIG_V},
    )
    _id(o["project_id"], "Config.project_id", "fvprj_")
    _str(o["state_dir"], "Config.state_dir", 1, 1024)
    api = _check(o["api"], "Config.api", {"base_url", "token_env", "timeout_ms"}, {"base_url", "token_env", "timeout_ms"})
    _str(api["base_url"], "Config.api.base_url", 1, 2048)
    if not (api["base_url"].startswith("http://") or api["base_url"].startswith("https://")):
        raise _fail("SCHEMA", "Config.api.base_url must be http(s).")
    _str(api["token_env"], "Config.api.token_env", 1, 128)
    _int(api["timeout_ms"], "Config.api.timeout_ms", 1000, 300000)
    _str(o["trust_file"], "Config.trust_file", 1, 1024)
    _id(o["receipt_key_id"], "Config.receipt_key_id", "fvkey_")
    gen = _check(
        o["generator"],
        "Config.generator",
        {"executable", "args", "timeout_ms", "key_id"},
        {"executable", "args", "timeout_ms", "key_id"},
    )
    exe = _str(gen["executable"], "Config.generator.executable", 1, 4096)
    if not exe.startswith("/"):
        raise _fail("SCHEMA", "Config.generator.executable must be an absolute path.")
    args = _list(gen["args"], "Config.generator.args", 0, 16)
    for i, a in enumerate(args):
        s = _str(a, f"Config.generator.args[{i}]", 0, 256)
        if not PRINTABLE_RE.match(s):
            raise _fail("SCHEMA", "Config.generator.args must be printable ASCII.")
    _int(gen["timeout_ms"], "Config.generator.timeout_ms", 1000, 300000)
    _id(gen["key_id"], "Config.generator.key_id", "fvkey_")
    limits = _check(
        o["limits"],
        "Config.limits",
        {"body_bytes", "queued_jobs", "workers", "worker_memory_mib", "job_cpu_seconds", "job_wall_seconds"},
        {"body_bytes", "queued_jobs", "workers", "worker_memory_mib", "job_cpu_seconds", "job_wall_seconds"},
    )
    _int(limits["body_bytes"], "Config.limits.body_bytes", 1048576, 33554432)
    _int(limits["queued_jobs"], "Config.limits.queued_jobs", 1, 32)
    _int(limits["workers"], "Config.limits.workers", 1, 4)
    _int(limits["worker_memory_mib"], "Config.limits.worker_memory_mib", 512, 4096)
    _int(limits["job_cpu_seconds"], "Config.limits.job_cpu_seconds", 1, 120)
    _int(limits["job_wall_seconds"], "Config.limits.job_wall_seconds", 1, 300)
    ret = _check(
        o["retention"],
        "Config.retention",
        {"rejected_candidate_days", "unreferenced_blob_hours"},
        {"rejected_candidate_days", "unreferenced_blob_hours"},
    )
    _int(ret["rejected_candidate_days"], "Config.retention.rejected_candidate_days", 1, 30)
    _int(ret["unreferenced_blob_hours"], "Config.retention.unreferenced_blob_hours", 24, 168)
    tel = _check(
        o["telemetry"],
        "Config.telemetry",
        {"enabled", "metrics_bind", "log_level"},
        {"enabled", "metrics_bind", "log_level"},
    )
    if not isinstance(tel["enabled"], bool):
        raise _fail("SCHEMA", "Config.telemetry.enabled must be a boolean.")
    _str(tel["metrics_bind"], "Config.telemetry.metrics_bind", 1, 128)
    _enum(tel["log_level"], "Config.telemetry.log_level", ("debug", "info", "warn", "error"))
    return o
