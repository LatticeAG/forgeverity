/**
 * Pure view-model functions for the ForgeVerity dashboard (spec section 13).
 *
 * Every rule the UI must honor lives here, away from the DOM, so it is
 * unit-testable: failed/missing scores are gaps not zeros; terminal verdicts
 * have distinct text labels (color is never the sole encoding); reference or
 * policy resets start a new labeled series; holdout text is never rendered;
 * no accept-override control exists anywhere in this module.
 */

import type {
  DecisionCore,
  Job,
  Manifest,
  Policy,
  Reference,
  Release,
  Stream,
} from "@forgeverity/schema";

export const SCOPE_WARNING =
  "ForgeVerity verifies provenance and lexical diversity only. " +
  "Acceptance is a gate signal, not a claim of model quality or collapse immunity.";

export type TerminalVerdict = "accepted" | "rejected" | "stale" | "cancelled" | "failed";

export const VERDICT_LABELS: Record<TerminalVerdict, string> = {
  accepted: "accepted",
  rejected: "rejected",
  stale: "stale",
  cancelled: "cancelled",
  failed: "failed",
};

export function terminalVerdict(state: Job["state"]): TerminalVerdict | null {
  switch (state) {
    case "ACCEPTED":
      return "accepted";
    case "REJECTED":
      return "rejected";
    case "STALE":
      return "stale";
    case "CANCELLED":
      return "cancelled";
    case "FAILED":
      return "failed";
    default:
      return null;
  }
}

export interface StreamRow {
  id: string;
  state: string;
  revision: number;
  reference_pin: string;
  policy_pin: string;
  head: string;
  latest_verdict: string;
}

export function streamRow(stream: Stream, latestJob: Job | null): StreamRow {
  const verdict = latestJob === null ? "none" : (terminalVerdict(latestJob.state) ?? latestJob.state.toLowerCase());
  return {
    id: stream.id,
    state: stream.state,
    revision: stream.revision,
    reference_pin: stream.reference_hash,
    policy_pin: stream.policy_hash,
    head: stream.head_release_hash,
    latest_verdict: verdict,
  };
}

/** One point in a metric timeline. `value: null` is a gap, never a zero. */
export interface TimelinePoint {
  revision: number;
  value: number | null;
  verdict: TerminalVerdict;
}

export interface TimelineSeries {
  /** e.g. "vendi_reference_bps · series 2 (policy reset @ rev 4)" */
  label: string;
  metric: string;
  segment: number;
  points: TimelinePoint[];
}

export type MetricKey =
  | "collapse_proxy_bps"
  | "vendi_reference_bps"
  | "vendi_parent_bps"
  | "self_bleu_increase_bps"
  | "category_coverage_bps"
  | "synthetic_bps";

export const TIMELINE_METRICS: readonly MetricKey[] = [
  "collapse_proxy_bps",
  "vendi_reference_bps",
  "vendi_parent_bps",
  "self_bleu_increase_bps",
  "category_coverage_bps",
  "synthetic_bps",
];

export interface DecisionPoint {
  release: Release;
  decision: DecisionCore | null;
  job: Job;
}

/**
 * Build one labeled series per metric. A change in the release's pinned
 * reference or policy hash starts a new series segment — comparisons across
 * a reset must never read as a continuous improvement line. Jobs whose
 * decision carries no metrics (rejected/failed/missing) emit a null gap so
 * the renderer can break the line instead of plotting zero.
 */
export function timelineSeries(points: DecisionPoint[]): TimelineSeries[] {
  const sorted = [...points].sort((a, b) => a.release.revision - b.release.revision);
  const out: TimelineSeries[] = [];
  for (const metric of TIMELINE_METRICS) {
    let segment = 0;
    let prevRef: string | null = null;
    let prevPol: string | null = null;
    let series: TimelineSeries | null = null;
    for (const p of sorted) {
      const verdict = terminalVerdict(p.job.state) ?? "failed";
      if (prevRef !== null && (p.release.reference_hash !== prevRef || p.release.policy_hash !== prevPol)) {
        segment += 1;
        series = null;
      }
      prevRef = p.release.reference_hash;
      prevPol = p.release.policy_hash;
      if (series === null) {
        const suffix = segment === 0 ? "" : ` · series ${segment + 1} (reference/policy reset @ rev ${p.release.revision})`;
        series = { label: `${metric}${suffix}`, metric, segment, points: [] };
        out.push(series);
      }
      const metrics = p.decision?.metrics ?? null;
      series.points.push({
        revision: p.release.revision,
        value: metrics === null ? null : (metrics[metric] as number),
        verdict,
      });
    }
  }
  return out;
}

export interface JobDetail {
  job_id: string;
  state: string;
  verdict: string;
  submitted_count: number | null;
  retained_count: number | null;
  exclusions: { record_id: string; code: string }[];
  sample_sizes: { reference: number | null; parent: number | null; proposed: number | null };
  reasons: string[];
  pins: { policy_hash: string; reference_hash: string; trust_hash: string };
  receipt_status: string;
}

export function jobDetail(job: Job, decision: DecisionCore | null): JobDetail {
  const verdict = terminalVerdict(job.state) ?? "pending";
  return {
    job_id: job.id,
    state: job.state,
    verdict,
    submitted_count: decision?.submitted_count ?? null,
    retained_count: decision?.accepted_candidate_ids.length ?? null,
    exclusions: decision?.excluded ?? [],
    sample_sizes: {
      reference: decision?.metrics?.reference.sample_count ?? null,
      parent: decision?.metrics?.parent.sample_count ?? null,
      proposed: decision?.metrics?.proposed.sample_count ?? null,
    },
    reasons: decision?.reasons ?? [],
    pins: {
      policy_hash: decision?.policy_hash ?? "",
      reference_hash: decision?.reference_hash ?? "",
      trust_hash: job.trust_hash,
    },
    receipt_status: job.receipt_hash === null ? "none" : "receipt recorded",
  };
}

export interface ReleaseGraphNode {
  digest: string;
  kind: string;
  label: string;
}

export interface ReleaseGraphEdge {
  from: string;
  to: string;
  kind: "parent" | "manifest" | "decision" | "policy" | "reference" | "generation";
}

/** The complete hash graph for a release detail view. */
export function releaseGraph(
  release: Release,
  manifest: Manifest,
  decision: DecisionCore | null,
): { nodes: ReleaseGraphNode[]; edges: ReleaseGraphEdge[] } {
  const nodes: ReleaseGraphNode[] = [
    { digest: "self", kind: "release", label: `release rev ${release.revision}` },
    { digest: release.manifest_hash, kind: "manifest", label: "manifest" },
    { digest: release.policy_hash, kind: "policy", label: "policy" },
    { digest: release.reference_hash, kind: "reference", label: "reference" },
  ];
  const edges: ReleaseGraphEdge[] = [
    { from: "self", to: release.manifest_hash, kind: "manifest" },
    { from: "self", to: release.policy_hash, kind: "policy" },
    { from: "self", to: release.reference_hash, kind: "reference" },
  ];
  if (manifest.parent_release_hash !== null) {
    nodes.push({ digest: manifest.parent_release_hash, kind: "release", label: "parent release" });
    edges.push({ from: "self", to: manifest.parent_release_hash, kind: "parent" });
  }
  if (release.decision_hash !== null) {
    nodes.push({ digest: release.decision_hash, kind: "decision", label: "decision" });
    edges.push({ from: "self", to: release.decision_hash, kind: "decision" });
  }
  if (manifest.generation_hash !== null) {
    nodes.push({ digest: manifest.generation_hash, kind: "generation", label: "generation" });
    edges.push({ from: release.manifest_hash, to: manifest.generation_hash, kind: "generation" });
  }
  if (decision !== null) {
    nodes.push({ digest: decision.candidate_hash, kind: "artifact", label: "candidate artifact" });
    edges.push({ from: release.decision_hash as string, to: decision.candidate_hash, kind: "decision" });
  }
  return { nodes, edges };
}

/**
 * The "verify locally" command shown on release detail. It never embeds a
 * token — verification needs only the export bundle, a trust file, and the
 * artifact directory.
 */
export function verifyCommand(releaseHash: string): string {
  return `forgeverity export sunlight --release ${releaseHash} --out export.json && forgeverity verify export.json --trust forgeverity-trust.json --artifacts artifacts/`;
}

export interface ReferencePolicyView {
  reference_id: string;
  reference_hash: string;
  train_hash: string;
  holdout_hash: string;
  origin_source: string;
  policy_hash: string;
  suite: string;
  categories: string[];
  gates: { name: string; value: number }[];
}

export function referencePolicyView(
  reference: Reference,
  referenceHash: string,
  policy: Policy,
  policyHash: string,
): ReferencePolicyView {
  return {
    reference_id: reference.id,
    reference_hash: referenceHash,
    train_hash: reference.train_hash,
    holdout_hash: reference.holdout_hash,
    origin_source: reference.origin.body.source_id,
    policy_hash: policyHash,
    suite: policy.suite,
    categories: policy.categories,
    gates: [
      { name: "min_candidates", value: policy.min_candidates },
      { name: "max_filter_bps", value: policy.max_filter_bps },
      { name: "min_vendi_reference_bps", value: policy.min_vendi_reference_bps },
      { name: "min_vendi_parent_bps", value: policy.min_vendi_parent_bps },
      { name: "max_self_bleu_increase_bps", value: policy.max_self_bleu_increase_bps },
      { name: "min_category_coverage_bps", value: policy.min_category_coverage_bps },
      { name: "max_synthetic_bps", value: policy.max_synthetic_bps },
      { name: "max_rounds", value: policy.max_rounds },
      { name: "max_total_candidates", value: policy.max_total_candidates },
    ],
  };
}
