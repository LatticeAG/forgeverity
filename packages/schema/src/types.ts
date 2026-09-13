/**
 * ForgeVerity §5 exact protocol schemas — normative TypeScript type algebra.
 *
 * Every property is required unless marked `?`; every object forbids
 * additional properties; union objects must match exactly one alternative.
 * `Int` is an integer in [-(2^53-1), 2^53-1]; `Bps` an integer 0..10000;
 * `Digest` matches /^sha256:[0-9a-f]{64}$/; `Rational` is nonnegative,
 * denominator positive, coprime decimal integers without leading zeros.
 */

export type Int = number;
export type Bps = number;
export type Digest = string;
export type Id<P extends string> = string;
export type B64Key = string;
export type B64Sig = string;
export type Rational = { numerator: string; denominator: string };

export type ProjectId = Id<"fvprj_">;
export type SourceId = Id<"fvsrc_">;
export type ReferenceId = Id<"fvref_">;
export type StreamId = Id<"fvstr_">;
export type RecordId = Id<"fvrec_">;
export type JobId = Id<"fvjob_">;
export type KeyId = Id<"fvkey_">;

export type JobState =
  | "QUEUED"
  | "FILTERING"
  | "SCORING"
  | "COMMITTING"
  | "ACCEPTED"
  | "REJECTED"
  | "FAILED"
  | "STALE"
  | "CANCELLED";

export type StreamState = "ACTIVE" | "PAUSED";
export type Mode = "mix" | "replace";

export type Ticket = {
  id: RecordId;
  title: string;
  body: string;
  category: string;
};

export type TicketArtifact = {
  v: "fv.artifact/1";
  kind: "tickets";
  records: Ticket[];
};

export type JsonValue =
  | string
  | Int
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type IngestRecord = {
  id: RecordId;
  title?: JsonValue;
  body?: JsonValue;
  category?: JsonValue;
};

export type IngestArtifact = {
  v: "fv.artifact/1";
  kind: "tickets";
  records: IngestRecord[];
};

export type OriginAssertion = {
  v: "fv.origin/1";
  project_id: ProjectId;
  source_id: SourceId;
  train_hash: Digest;
  holdout_hash: Digest;
  origin: "human_attested";
  collected_at_ms: Int;
  key_id: KeyId;
};

export type SignedOrigin = { body: OriginAssertion; signature: B64Sig };

export type Reference = {
  v: "fv.reference/1";
  id: ReferenceId;
  project_id: ProjectId;
  train_hash: Digest;
  holdout_hash: Digest;
  origin: SignedOrigin;
  created_at_ms: Int;
};

export type Policy = {
  v: "fv.policy/1";
  suite: "tickets-lexical-1";
  reference_id: ReferenceId;
  reference_hash: Digest;
  categories: string[];
  min_candidates: Int;
  max_filter_bps: Bps;
  min_vendi_reference_bps: Bps;
  min_vendi_parent_bps: Bps;
  max_self_bleu_increase_bps: Bps;
  min_category_coverage_bps: Bps;
  max_synthetic_bps: Bps;
  max_rounds: Int;
  max_total_candidates: Int;
};

export type GenerationBody = {
  v: "fv.generation/1";
  project_id: ProjectId;
  stream_id: StreamId;
  expected_revision: Int;
  candidate_hash: Digest;
  generator: "ForgeDistill";
  generator_version: string;
  generator_config_hash: Digest;
  model_artifact_hash: Digest;
  parent_model_hash: Digest | null;
  prompt_hash: Digest;
  seed: string;
  created_at_ms: Int;
  key_id: KeyId;
};

export type Generation = { body: GenerationBody; signature: B64Sig };

export type JobRequest = {
  stream_id: StreamId;
  expected_revision: Int;
  candidate_hash: Digest;
  generation: Generation;
  mode: Mode;
  previous_job_id: JobId | null;
};

export type RecordLink = {
  record_id: RecordId;
  content_hash: Digest;
  origin: "human_attested" | "synthetic";
  source_hash: Digest;
};

export type Manifest = {
  v: "fv.manifest/1";
  project_id: ProjectId;
  stream_id: StreamId;
  revision: Int;
  parent_release_hash: Digest | null;
  reference_hash: Digest;
  policy_hash: Digest;
  corpus_hash: Digest;
  records: RecordLink[];
  generation_hash: Digest | null;
};

export type Stream = {
  v: "fv.stream/1";
  id: StreamId;
  project_id: ProjectId;
  state: StreamState;
  revision: Int;
  policy_hash: Digest;
  reference_hash: Digest;
  head_release_hash: Digest;
};

export type FilterCode =
  | "SHAPE"
  | "TEXT"
  | "CATEGORY"
  | "DUP_CANDIDATE"
  | "DUP_PARENT"
  | "NEAR_CANDIDATE"
  | "NEAR_PARENT";

export type Exclusion = { record_id: RecordId; code: FilterCode };

export type MetricSet = {
  sample_count: Int;
  vendi: Rational;
  self_bleu_bps: Bps;
};

export type GateMetrics = {
  reference: MetricSet;
  parent: MetricSet;
  proposed: MetricSet;
  vendi_reference_bps: Int;
  vendi_parent_bps: Int;
  self_bleu_increase_bps: Int;
  category_coverage_bps: Bps;
  synthetic_bps: Bps;
  filter_bps: Bps;
  collapse_proxy_bps: Bps;
};

export type GateReason =
  | "HOLDOUT_LEAK"
  | "TOO_FEW_VALID"
  | "FILTER_BUDGET"
  | "CORPUS_LIMIT"
  | "REPLACE_FORBIDDEN"
  | "SYNTHETIC_LIMIT"
  | "REFERENCE_DIVERSITY"
  | "PARENT_DIVERSITY"
  | "REPETITION"
  | "CATEGORY_LOSS";

export type DecisionCore = {
  v: "fv.decision/1";
  suite: "tickets-lexical-1";
  policy_hash: Digest;
  reference_hash: Digest;
  parent_release_hash: Digest;
  candidate_hash: Digest;
  generation_hash: Digest;
  mode: Mode;
  submitted_count: Int;
  accepted_candidate_ids: RecordId[];
  excluded: Exclusion[];
  proposed_corpus_hash: Digest | null;
  metrics: GateMetrics | null;
  verdict: "accept" | "reject";
  reasons: GateReason[];
};

export type Release = {
  v: "fv.release/1";
  kind: "genesis" | "accepted";
  project_id: ProjectId;
  stream_id: StreamId;
  revision: Int;
  manifest_hash: Digest;
  decision_hash: Digest | null;
  suite: "tickets-lexical-1";
  policy_hash: Digest;
  reference_hash: Digest;
};

export type Job = {
  v: "fv.job/1";
  id: JobId;
  request: JobRequest;
  state: JobState;
  trust_hash: Digest;
  round: Int;
  total_candidates: Int;
  attempt: Int;
  fence: Int;
  created_at_ms: Int;
  updated_at_ms: Int;
  decision_hash: Digest | null;
  release_hash: Digest | null;
  receipt_hash: Digest | null;
  error: ErrorBody | null;
};

export type EventName =
  | "REFERENCE_REGISTERED"
  | "POLICY_REGISTERED"
  | "STREAM_CREATED"
  | "STREAM_PAUSED"
  | "STREAM_RESUMED"
  | "JOB_QUEUED"
  | "FILTER_STARTED"
  | "SCORE_STARTED"
  | "COMMIT_STARTED"
  | "JOB_ACCEPTED"
  | "JOB_REJECTED"
  | "JOB_FAILED"
  | "JOB_STALE"
  | "JOB_CANCELLED"
  | "LEASE_RECOVERED"
  | "CONSUMED"
  | "KEY_ROTATED"
  | "CHECKPOINTED"
  | "MIGRATED"
  | "TOKEN_ISSUED"
  | "TOKEN_REVOKED";

export type EventData = {
  job_id: JobId | null;
  stream_id: StreamId | null;
  from_state: JobState | StreamState | null;
  to_state: JobState | StreamState | null;
  reasons: string[];
  revision: Int | null;
};

export type AuditBody = {
  v: "fv.audit/1";
  entry_id: Id<"fvent_">;
  project_id: ProjectId;
  seq: Int;
  previous_hash: Digest | null;
  at_ms: Int;
  event: EventName;
  subject_hash: Digest;
  data: EventData;
  key_id: KeyId;
};

export type Receipt = { body: AuditBody; entry_hash: Digest; signature: B64Sig };
export type ReleaseEnvelope = { release: Release; receipt: Receipt };

export type KeyRecord = {
  id: KeyId;
  public_key: B64Key;
  purpose: "receipt" | "origin" | "generator";
  valid_from_ms: Int;
  valid_until_ms: Int;
  revoked_at_ms: Int | null;
};

export type ConsumptionRequest = {
  stream_id: StreamId;
  expected_revision: Int;
  release_hash: Digest;
  manifest_hash: Digest;
  consumer_label: string;
};

export type Consumption = {
  v: "fv.consumption/1";
  id: Id<"fvcon_">;
  request: ConsumptionRequest;
  at_ms: Int;
  receipt_hash: Digest;
};

export type ErrorBody = {
  code: string;
  message: string;
  retryable: boolean;
  request_id: Id<"fvreq_">;
};

export type ErrorResponse = { error: ErrorBody };

export type TrustSnapshot = {
  v: "fv.trust/1";
  project_id: ProjectId;
  receipt_root: KeyRecord;
  sources: { source_id: SourceId; key: KeyRecord }[];
  generators: KeyRecord[];
  previous_hash: Digest | null;
  old_signature: B64Sig | null;
  new_signature: B64Sig;
};

export type ExportBundle = {
  v: "fv.sunlight-export/1";
  release: Release;
  manifest: Manifest;
  decision: DecisionCore | null;
  reference: Reference;
  policy: Policy;
  generations: Generation[];
  receipts: Receipt[];
  ancestors: { release: Release; manifest: Manifest; decision: DecisionCore | null }[];
  checkpoint: Receipt;
  keys: KeyRecord[];
  trust_snapshots: TrustSnapshot[];
};

export type TipDescriptor = { seq: Int; entry_hash: Digest };

export type ReferenceRegisterRequest = { origin: SignedOrigin };
export type StreamCreateRequest = { policy_hash: Digest; reference_id: ReferenceId };
export type StreamStateRequest = {
  expected_revision: Int;
  state: StreamState;
  reason: string;
};
export type JobCancelRequest = Record<string, never>;
export type PolicyPutResult = { hash: Digest };
export type BlobPutResult = { hash: Digest; kind: "tickets"; bytes: Int };
export type ListPage<T> = { items: T[]; next_cursor: string | null };
export type AuditPage = { items: Receipt[]; next_cursor: string | null; tip: TipDescriptor };
export type ConsumptionEnvelope = { consumption: Consumption; receipt: Receipt };
export type KeysResponse = { keys: KeyRecord[]; root_key_id: KeyId };
export type ArtifactMap = { [digest: string]: JsonValue };
export type Capabilities = {
  protocol: "fv.http/1";
  suites: "tickets-lexical-1"[];
  max_body_bytes: Int;
  max_candidate_records: Int;
  max_corpus_records: Int;
  sample_size: Int;
};
export type TokenRecord = {
  token_digest: Digest;
  principal_id: Id<"fvact_">;
  role: "admin" | "producer" | "consumer" | "viewer" | "auditor";
  expires_at_ms: Int;
  revoked_at_ms: Int | null;
};

export const EVENT_NAMES: readonly EventName[] = [
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
];

export const GATE_REASONS: readonly GateReason[] = [
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
];

export const FILTER_CODES: readonly FilterCode[] = [
  "SHAPE",
  "TEXT",
  "CATEGORY",
  "DUP_CANDIDATE",
  "DUP_PARENT",
  "NEAR_CANDIDATE",
  "NEAR_PARENT",
];
