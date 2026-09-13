/**
 * Runtime validators for the ForgeVerity §5 schema algebra.
 *
 * Mirrors the Python `schema.py` contract: unknown fields, wrong version
 * literals, and type mismatches are all SCHEMA failures. These validators
 * check the envelope types the verifier and dashboard consume; they do not
 * broaden the normative type algebra.
 */

import {
  EVENT_NAMES,
  FILTER_CODES,
  GATE_REASONS,
  type AuditBody,
  type DecisionCore,
  type ExportBundle,
  type Generation,
  type KeyRecord,
  type Manifest,
  type Policy,
  type Receipt,
  type Reference,
  type Release,
  type SignedOrigin,
  type TrustSnapshot,
} from "./types.js";

export const INT_MIN = -(2 ** 53 - 1);
export const INT_MAX = 2 ** 53 - 1;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const B64U_RE = /^[A-Za-z0-9_-]*$/;
const ID_RE = /^fv[a-z]{3,5}_[A-Za-z0-9_-]{21}$/;
const RATIONAL_RE = /^(0|[1-9][0-9]*)$/;

export class SchemaError extends Error {
  readonly code = "SCHEMA" as const;
  constructor(message: string) {
    super(message);
    this.name = "SchemaError";
  }
}

function fail(msg: string): never {
  throw new SchemaError(msg);
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function exactKeys(v: Record<string, unknown>, keys: readonly string[], what: string): void {
  const want = new Set(keys);
  for (const k of Object.keys(v)) {
    if (!want.has(k)) fail(`${what}: unknown field ${k}`);
  }
  for (const k of keys) {
    if (!(k in v)) fail(`${what}: missing field ${k}`);
  }
}

export function isInt(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= INT_MIN && v <= INT_MAX;
}

function checkInt(v: unknown, what: string): asserts v is number {
  if (!isInt(v)) fail(`${what}: not a safe integer`);
}

function checkNonneg(v: unknown, what: string): void {
  checkInt(v, what);
  if ((v as number) < 0) fail(`${what}: negative`);
}

export function isBps(v: unknown): v is number {
  return isInt(v) && v >= 0 && v <= 10000;
}

function checkBps(v: unknown, what: string): void {
  if (!isBps(v)) fail(`${what}: not a basis-point integer`);
}

export function isDigest(v: unknown): v is string {
  return typeof v === "string" && DIGEST_RE.test(v);
}

function checkDigest(v: unknown, what: string): void {
  if (!isDigest(v)) fail(`${what}: not a sha256 digest`);
}

export function isId(v: unknown): v is string {
  return typeof v === "string" && ID_RE.test(v);
}

function checkId(v: unknown, prefix: string, what: string): void {
  if (!isId(v) || !v.startsWith(prefix)) fail(`${what}: not a ${prefix} id`);
}

/** Canonical base64url: unpadded, no unused trailing bits set. */
export function isCanonicalB64u(v: unknown, bytes: number): v is string {
  if (typeof v !== "string" || !B64U_RE.test(v) || v.includes("=")) return false;
  // bytes -> base64url chars: ceil(bytes*8/6)
  const chars = Math.ceil((bytes * 8) / 6);
  if (v.length !== chars) return false;
  // The last char must not carry bits beyond the byte length.
  const rem = (bytes * 8) % 6;
  if (rem === 0) return true;
  const idx = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(
    v[v.length - 1],
  );
  if (idx < 0) return false;
  return idx % (1 << (6 - rem)) === 0;
}

function checkB64Key(v: unknown, what: string): void {
  if (!isCanonicalB64u(v, 32)) fail(`${what}: not a canonical 32-byte base64url key`);
}

function checkB64Sig(v: unknown, what: string): void {
  if (!isCanonicalB64u(v, 64)) fail(`${what}: not a canonical 64-byte base64url signature`);
}

function checkString(v: unknown, what: string): asserts v is string {
  if (typeof v !== "string") fail(`${what}: not a string`);
}

function checkLiteral(v: unknown, literal: string, what: string): void {
  if (v !== literal) fail(`${what}: must equal ${JSON.stringify(literal)}`);
}

function checkRational(v: unknown, what: string): void {
  if (!isObject(v)) fail(`${what}: not an object`);
  exactKeys(v, ["numerator", "denominator"], what);
  const n = v.numerator;
  const d = v.denominator;
  if (typeof n !== "string" || typeof d !== "string") fail(`${what}: rational fields must be strings`);
  if (!RATIONAL_RE.test(n) || !RATIONAL_RE.test(d)) fail(`${what}: bad rational digits`);
  if (d === "0") fail(`${what}: zero denominator`);
}

function checkEnum<T extends string>(v: unknown, values: readonly T[], what: string): asserts v is T {
  if (typeof v !== "string" || !values.includes(v as T)) fail(`${what}: bad enum value`);
}

export function validateKeyRecord(v: unknown): asserts v is KeyRecord {
  if (!isObject(v)) fail("KeyRecord: not an object");
  exactKeys(v, ["id", "public_key", "purpose", "valid_from_ms", "valid_until_ms", "revoked_at_ms"], "KeyRecord");
  checkId(v.id, "fvkey_", "KeyRecord.id");
  checkB64Key(v.public_key, "KeyRecord.public_key");
  checkEnum(v.purpose, ["receipt", "origin", "generator"] as const, "KeyRecord.purpose");
  checkNonneg(v.valid_from_ms, "KeyRecord.valid_from_ms");
  checkNonneg(v.valid_until_ms, "KeyRecord.valid_until_ms");
  if ((v.valid_until_ms as number) <= (v.valid_from_ms as number)) {
    fail("KeyRecord: valid_until_ms must exceed valid_from_ms");
  }
  if (v.revoked_at_ms !== null) checkNonneg(v.revoked_at_ms, "KeyRecord.revoked_at_ms");
}

export function validateTrustSnapshot(v: unknown): asserts v is TrustSnapshot {
  if (!isObject(v)) fail("TrustSnapshot: not an object");
  exactKeys(
    v,
    ["v", "project_id", "receipt_root", "sources", "generators", "previous_hash", "old_signature", "new_signature"],
    "TrustSnapshot",
  );
  checkLiteral(v.v, "fv.trust/1", "TrustSnapshot.v");
  checkId(v.project_id, "fvprj_", "TrustSnapshot.project_id");
  validateKeyRecord(v.receipt_root);
  if ((v.receipt_root as KeyRecord).purpose !== "receipt") fail("TrustSnapshot: receipt_root purpose");
  if (!Array.isArray(v.sources)) fail("TrustSnapshot.sources: not an array");
  for (const s of v.sources) {
    if (!isObject(s)) fail("TrustSnapshot.sources[]: not an object");
    exactKeys(s, ["source_id", "key"], "TrustSnapshot.sources[]");
    checkId(s.source_id, "fvsrc_", "TrustSnapshot.sources[].source_id");
    validateKeyRecord(s.key);
    if ((s.key as KeyRecord).purpose !== "origin") fail("TrustSnapshot.sources[]: key purpose");
  }
  if (!Array.isArray(v.generators)) fail("TrustSnapshot.generators: not an array");
  for (const g of v.generators) {
    validateKeyRecord(g);
    if ((g as KeyRecord).purpose !== "generator") fail("TrustSnapshot.generators[]: key purpose");
  }
  if (v.previous_hash !== null) checkDigest(v.previous_hash, "TrustSnapshot.previous_hash");
  if (v.old_signature !== null) checkB64Sig(v.old_signature, "TrustSnapshot.old_signature");
  checkB64Sig(v.new_signature, "TrustSnapshot.new_signature");
}

export function validateAuditBody(v: unknown): asserts v is AuditBody {
  if (!isObject(v)) fail("AuditBody: not an object");
  exactKeys(
    v,
    ["v", "entry_id", "project_id", "seq", "previous_hash", "at_ms", "event", "subject_hash", "data", "key_id"],
    "AuditBody",
  );
  checkLiteral(v.v, "fv.audit/1", "AuditBody.v");
  checkId(v.entry_id, "fvent_", "AuditBody.entry_id");
  checkId(v.project_id, "fvprj_", "AuditBody.project_id");
  checkNonneg(v.seq, "AuditBody.seq");
  if (v.previous_hash !== null) checkDigest(v.previous_hash, "AuditBody.previous_hash");
  checkNonneg(v.at_ms, "AuditBody.at_ms");
  checkEnum(v.event, EVENT_NAMES, "AuditBody.event");
  checkDigest(v.subject_hash, "AuditBody.subject_hash");
  checkId(v.key_id, "fvkey_", "AuditBody.key_id");
  const d = v.data;
  if (!isObject(d)) fail("AuditBody.data: not an object");
  exactKeys(d, ["job_id", "stream_id", "from_state", "to_state", "reasons", "revision"], "AuditBody.data");
  if (d.job_id !== null) checkId(d.job_id, "fvjob_", "AuditBody.data.job_id");
  if (d.stream_id !== null) checkId(d.stream_id, "fvstr_", "AuditBody.data.stream_id");
  if (!Array.isArray(d.reasons) || d.reasons.some((r) => typeof r !== "string")) {
    fail("AuditBody.data.reasons: not a string array");
  }
  if (d.revision !== null) checkNonneg(d.revision, "AuditBody.data.revision");
}

export function validateReceipt(v: unknown): asserts v is Receipt {
  if (!isObject(v)) fail("Receipt: not an object");
  exactKeys(v, ["body", "entry_hash", "signature"], "Receipt");
  validateAuditBody(v.body);
  checkDigest(v.entry_hash, "Receipt.entry_hash");
  checkB64Sig(v.signature, "Receipt.signature");
}

export function validateSignedOrigin(v: unknown): asserts v is SignedOrigin {
  if (!isObject(v)) fail("SignedOrigin: not an object");
  exactKeys(v, ["body", "signature"], "SignedOrigin");
  const b = v.body;
  if (!isObject(b)) fail("SignedOrigin.body: not an object");
  exactKeys(
    b,
    ["v", "project_id", "source_id", "train_hash", "holdout_hash", "origin", "collected_at_ms", "key_id"],
    "SignedOrigin.body",
  );
  checkLiteral(b.v, "fv.origin/1", "SignedOrigin.body.v");
  checkId(b.project_id, "fvprj_", "SignedOrigin.body.project_id");
  checkId(b.source_id, "fvsrc_", "SignedOrigin.body.source_id");
  checkDigest(b.train_hash, "SignedOrigin.body.train_hash");
  checkDigest(b.holdout_hash, "SignedOrigin.body.holdout_hash");
  checkLiteral(b.origin, "human_attested", "SignedOrigin.body.origin");
  checkNonneg(b.collected_at_ms, "SignedOrigin.body.collected_at_ms");
  checkId(b.key_id, "fvkey_", "SignedOrigin.body.key_id");
  checkB64Sig(v.signature, "SignedOrigin.signature");
}

export function validateReference(v: unknown): asserts v is Reference {
  if (!isObject(v)) fail("Reference: not an object");
  exactKeys(v, ["v", "id", "project_id", "train_hash", "holdout_hash", "origin", "created_at_ms"], "Reference");
  checkLiteral(v.v, "fv.reference/1", "Reference.v");
  checkId(v.id, "fvref_", "Reference.id");
  checkId(v.project_id, "fvprj_", "Reference.project_id");
  checkDigest(v.train_hash, "Reference.train_hash");
  checkDigest(v.holdout_hash, "Reference.holdout_hash");
  validateSignedOrigin(v.origin);
  checkNonneg(v.created_at_ms, "Reference.created_at_ms");
}

export function validatePolicy(v: unknown): asserts v is Policy {
  if (!isObject(v)) fail("Policy: not an object");
  exactKeys(
    v,
    [
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
    ],
    "Policy",
  );
  checkLiteral(v.v, "fv.policy/1", "Policy.v");
  checkLiteral(v.suite, "tickets-lexical-1", "Policy.suite");
  checkId(v.reference_id, "fvref_", "Policy.reference_id");
  checkDigest(v.reference_hash, "Policy.reference_hash");
  if (!Array.isArray(v.categories) || v.categories.some((c) => typeof c !== "string")) {
    fail("Policy.categories: not a string array");
  }
  checkInt(v.min_candidates, "Policy.min_candidates");
  checkBps(v.max_filter_bps, "Policy.max_filter_bps");
  checkBps(v.min_vendi_reference_bps, "Policy.min_vendi_reference_bps");
  checkBps(v.min_vendi_parent_bps, "Policy.min_vendi_parent_bps");
  checkBps(v.max_self_bleu_increase_bps, "Policy.max_self_bleu_increase_bps");
  checkBps(v.min_category_coverage_bps, "Policy.min_category_coverage_bps");
  checkBps(v.max_synthetic_bps, "Policy.max_synthetic_bps");
  checkInt(v.max_rounds, "Policy.max_rounds");
  checkInt(v.max_total_candidates, "Policy.max_total_candidates");
}

export function validateGeneration(v: unknown): asserts v is Generation {
  if (!isObject(v)) fail("Generation: not an object");
  exactKeys(v, ["body", "signature"], "Generation");
  const b = v.body;
  if (!isObject(b)) fail("Generation.body: not an object");
  exactKeys(
    b,
    [
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
    ],
    "Generation.body",
  );
  checkLiteral(b.v, "fv.generation/1", "Generation.body.v");
  checkId(b.project_id, "fvprj_", "Generation.body.project_id");
  checkId(b.stream_id, "fvstr_", "Generation.body.stream_id");
  checkNonneg(b.expected_revision, "Generation.body.expected_revision");
  checkDigest(b.candidate_hash, "Generation.body.candidate_hash");
  checkLiteral(b.generator, "ForgeDistill", "Generation.body.generator");
  checkString(b.generator_version, "Generation.body.generator_version");
  checkDigest(b.generator_config_hash, "Generation.body.generator_config_hash");
  checkDigest(b.model_artifact_hash, "Generation.body.model_artifact_hash");
  if (b.parent_model_hash !== null) checkDigest(b.parent_model_hash, "Generation.body.parent_model_hash");
  checkDigest(b.prompt_hash, "Generation.body.prompt_hash");
  checkString(b.seed, "Generation.body.seed");
  checkNonneg(b.created_at_ms, "Generation.body.created_at_ms");
  checkId(b.key_id, "fvkey_", "Generation.body.key_id");
  checkB64Sig(v.signature, "Generation.signature");
}

export function validateManifest(v: unknown): asserts v is Manifest {
  if (!isObject(v)) fail("Manifest: not an object");
  exactKeys(
    v,
    [
      "v",
      "project_id",
      "stream_id",
      "revision",
      "parent_release_hash",
      "reference_hash",
      "policy_hash",
      "corpus_hash",
      "records",
      "generation_hash",
    ],
    "Manifest",
  );
  checkLiteral(v.v, "fv.manifest/1", "Manifest.v");
  checkId(v.project_id, "fvprj_", "Manifest.project_id");
  checkId(v.stream_id, "fvstr_", "Manifest.stream_id");
  checkNonneg(v.revision, "Manifest.revision");
  if (v.parent_release_hash !== null) checkDigest(v.parent_release_hash, "Manifest.parent_release_hash");
  checkDigest(v.reference_hash, "Manifest.reference_hash");
  checkDigest(v.policy_hash, "Manifest.policy_hash");
  checkDigest(v.corpus_hash, "Manifest.corpus_hash");
  if (!Array.isArray(v.records)) fail("Manifest.records: not an array");
  for (const r of v.records) {
    if (!isObject(r)) fail("Manifest.records[]: not an object");
    exactKeys(r, ["record_id", "content_hash", "origin", "source_hash"], "Manifest.records[]");
    checkId(r.record_id, "fvrec_", "Manifest.records[].record_id");
    checkDigest(r.content_hash, "Manifest.records[].content_hash");
    checkEnum(r.origin, ["human_attested", "synthetic"] as const, "Manifest.records[].origin");
    checkDigest(r.source_hash, "Manifest.records[].source_hash");
  }
  if (v.generation_hash !== null) checkDigest(v.generation_hash, "Manifest.generation_hash");
}

function checkMetricSet(v: unknown, what: string): void {
  if (!isObject(v)) fail(`${what}: not an object`);
  exactKeys(v, ["sample_count", "vendi", "self_bleu_bps"], what);
  checkNonneg(v.sample_count, `${what}.sample_count`);
  checkRational(v.vendi, `${what}.vendi`);
  checkBps(v.self_bleu_bps, `${what}.self_bleu_bps`);
}

export function validateDecision(v: unknown): asserts v is DecisionCore {
  if (!isObject(v)) fail("DecisionCore: not an object");
  exactKeys(
    v,
    [
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
    ],
    "DecisionCore",
  );
  checkLiteral(v.v, "fv.decision/1", "DecisionCore.v");
  checkLiteral(v.suite, "tickets-lexical-1", "DecisionCore.suite");
  checkDigest(v.policy_hash, "DecisionCore.policy_hash");
  checkDigest(v.reference_hash, "DecisionCore.reference_hash");
  checkDigest(v.parent_release_hash, "DecisionCore.parent_release_hash");
  checkDigest(v.candidate_hash, "DecisionCore.candidate_hash");
  checkDigest(v.generation_hash, "DecisionCore.generation_hash");
  checkEnum(v.mode, ["mix", "replace"] as const, "DecisionCore.mode");
  checkNonneg(v.submitted_count, "DecisionCore.submitted_count");
  if (!Array.isArray(v.accepted_candidate_ids)) fail("DecisionCore.accepted_candidate_ids: not an array");
  for (const id of v.accepted_candidate_ids) checkId(id, "fvrec_", "DecisionCore.accepted_candidate_ids[]");
  if (!Array.isArray(v.excluded)) fail("DecisionCore.excluded: not an array");
  for (const e of v.excluded) {
    if (!isObject(e)) fail("DecisionCore.excluded[]: not an object");
    exactKeys(e, ["record_id", "code"], "DecisionCore.excluded[]");
    checkId(e.record_id, "fvrec_", "DecisionCore.excluded[].record_id");
    checkEnum(e.code, FILTER_CODES, "DecisionCore.excluded[].code");
  }
  if (v.proposed_corpus_hash !== null) checkDigest(v.proposed_corpus_hash, "DecisionCore.proposed_corpus_hash");
  if (v.metrics !== null) {
    const m = v.metrics;
    if (!isObject(m)) fail("DecisionCore.metrics: not an object");
    exactKeys(
      m,
      [
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
      ],
      "DecisionCore.metrics",
    );
    checkMetricSet(m.reference, "metrics.reference");
    checkMetricSet(m.parent, "metrics.parent");
    checkMetricSet(m.proposed, "metrics.proposed");
    checkNonneg(m.vendi_reference_bps, "metrics.vendi_reference_bps");
    checkNonneg(m.vendi_parent_bps, "metrics.vendi_parent_bps");
    checkInt(m.self_bleu_increase_bps, "metrics.self_bleu_increase_bps");
    if ((m.self_bleu_increase_bps as number) < -10000 || (m.self_bleu_increase_bps as number) > 10000) {
      fail("metrics.self_bleu_increase_bps: out of range");
    }
    checkBps(m.category_coverage_bps, "metrics.category_coverage_bps");
    checkBps(m.synthetic_bps, "metrics.synthetic_bps");
    checkBps(m.filter_bps, "metrics.filter_bps");
    checkBps(m.collapse_proxy_bps, "metrics.collapse_proxy_bps");
  }
  checkEnum(v.verdict, ["accept", "reject"] as const, "DecisionCore.verdict");
  if (!Array.isArray(v.reasons)) fail("DecisionCore.reasons: not an array");
  for (const r of v.reasons) checkEnum(r, GATE_REASONS, "DecisionCore.reasons[]");
}

export function validateRelease(v: unknown): asserts v is Release {
  if (!isObject(v)) fail("Release: not an object");
  exactKeys(
    v,
    [
      "v",
      "kind",
      "project_id",
      "stream_id",
      "revision",
      "manifest_hash",
      "decision_hash",
      "suite",
      "policy_hash",
      "reference_hash",
    ],
    "Release",
  );
  checkLiteral(v.v, "fv.release/1", "Release.v");
  checkEnum(v.kind, ["genesis", "accepted"] as const, "Release.kind");
  checkId(v.project_id, "fvprj_", "Release.project_id");
  checkId(v.stream_id, "fvstr_", "Release.stream_id");
  checkNonneg(v.revision, "Release.revision");
  checkDigest(v.manifest_hash, "Release.manifest_hash");
  if (v.decision_hash !== null) checkDigest(v.decision_hash, "Release.decision_hash");
  checkLiteral(v.suite, "tickets-lexical-1", "Release.suite");
  checkDigest(v.policy_hash, "Release.policy_hash");
  checkDigest(v.reference_hash, "Release.reference_hash");
}

export function validateExportBundle(v: unknown): asserts v is ExportBundle {
  if (!isObject(v)) fail("ExportBundle: not an object");
  exactKeys(
    v,
    [
      "v",
      "release",
      "manifest",
      "decision",
      "reference",
      "policy",
      "generations",
      "receipts",
      "ancestors",
      "checkpoint",
      "keys",
      "trust_snapshots",
    ],
    "ExportBundle",
  );
  checkLiteral(v.v, "fv.sunlight-export/1", "ExportBundle.v");
  validateRelease(v.release);
  validateManifest(v.manifest);
  if (v.decision !== null) validateDecision(v.decision);
  validateReference(v.reference);
  validatePolicy(v.policy);
  if (!Array.isArray(v.generations)) fail("ExportBundle.generations: not an array");
  for (const g of v.generations) validateGeneration(g);
  if (!Array.isArray(v.receipts) || v.receipts.length === 0) fail("ExportBundle.receipts: empty");
  for (const r of v.receipts) validateReceipt(r);
  if (!Array.isArray(v.ancestors)) fail("ExportBundle.ancestors: not an array");
  for (const a of v.ancestors) {
    if (!isObject(a)) fail("ExportBundle.ancestors[]: not an object");
    exactKeys(a, ["release", "manifest", "decision"], "ExportBundle.ancestors[]");
    validateRelease(a.release);
    validateManifest(a.manifest);
    if (a.decision !== null) validateDecision(a.decision);
  }
  validateReceipt(v.checkpoint);
  if (!Array.isArray(v.keys)) fail("ExportBundle.keys: not an array");
  for (const k of v.keys) validateKeyRecord(k);
  if (!Array.isArray(v.trust_snapshots) || v.trust_snapshots.length === 0) {
    fail("ExportBundle.trust_snapshots: empty");
  }
  for (const s of v.trust_snapshots) validateTrustSnapshot(s);
}
