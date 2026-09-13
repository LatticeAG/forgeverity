import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { DecisionCore, Job, Manifest, Policy, Reference, Release } from "@forgeverity/schema";
import {
  SCOPE_WARNING,
  TIMELINE_METRICS,
  VERDICT_LABELS,
  jobDetail,
  releaseGraph,
  terminalVerdict,
  timelineSeries,
  verifyCommand,
  type DecisionPoint,
} from "../src/views.js";

const D = (n: number) => `sha256:${n.toString(16).padStart(64, "0")}`;

function release(rev: number, over: Partial<Release> = {}): Release {
  return {
    v: "fv.release/1",
    kind: "accepted",
    project_id: "fvprj_000000000000000000099",
    stream_id: "fvstr_000000000000000000099",
    revision: rev,
    manifest_hash: D(100 + rev),
    decision_hash: D(200 + rev),
    suite: "tickets-lexical-1",
    policy_hash: D(1),
    reference_hash: D(2),
    ...over,
  };
}

function job(state: Job["state"], over: Partial<Job> = {}): Job {
  return {
    v: "fv.job/1",
    id: "fvjob_000000000000000000001",
    request: {
      stream_id: "fvstr_000000000000000000099",
      expected_revision: 0,
      candidate_hash: D(9),
      generation: { body: {}, signature: "" } as never,
      mode: "mix",
      previous_job_id: null,
    },
    state,
    trust_hash: D(3),
    round: 1,
    total_candidates: 32,
    attempt: 1,
    fence: 1,
    created_at_ms: 0,
    updated_at_ms: 1,
    decision_hash: null,
    release_hash: null,
    receipt_hash: null,
    error: null,
    ...over,
  };
}

function metrics(v: number): DecisionCore["metrics"] {
  const set = { sample_count: 32, vendi: { numerator: "3", denominator: "2" }, self_bleu_bps: v };
  return {
    reference: set,
    parent: set,
    proposed: set,
    vendi_reference_bps: v,
    vendi_parent_bps: v,
    self_bleu_increase_bps: v,
    category_coverage_bps: v,
    synthetic_bps: v,
    filter_bps: v,
    collapse_proxy_bps: v,
  };
}

function decision(over: Partial<DecisionCore> = {}): DecisionCore {
  return {
    v: "fv.decision/1",
    suite: "tickets-lexical-1",
    policy_hash: D(1),
    reference_hash: D(2),
    parent_release_hash: D(4),
    candidate_hash: D(9),
    generation_hash: D(8),
    mode: "mix",
    submitted_count: 32,
    accepted_candidate_ids: ["fvrec_000000000000000002001"],
    excluded: [{ record_id: "fvrec_000000000000000002002", code: "DUP_PARENT" as const }],
    proposed_corpus_hash: D(7),
    metrics: metrics(500),
    verdict: "accept",
    reasons: [],
    ...over,
  };
}

describe("terminalVerdict", () => {
  it("maps each terminal state to a distinct text label", () => {
    const labels = new Set(
      (["ACCEPTED", "REJECTED", "STALE", "CANCELLED", "FAILED"] as const).map((s) => terminalVerdict(s)),
    );
    assert.equal(labels.size, 5);
    for (const l of labels) assert.ok(l !== null && l in VERDICT_LABELS);
  });
  it("returns null for non-terminal states", () => {
    assert.equal(terminalVerdict("QUEUED"), null);
    assert.equal(terminalVerdict("SCORING"), null);
  });
});

describe("timelineSeries", () => {
  it("emits one series per metric with labeled gaps, never zeros", () => {
    const points: DecisionPoint[] = [
      { release: release(1), decision: decision(), job: job("ACCEPTED") },
      { release: release(2), decision: null, job: job("FAILED") },
      { release: release(3), decision: decision(), job: job("ACCEPTED") },
    ];
    const series = timelineSeries(points);
    assert.equal(series.length, TIMELINE_METRICS.length);
    const vendi = series.find((s) => s.metric === "vendi_reference_bps")!;
    assert.deepEqual(
      vendi.points.map((p) => p.value),
      [500, null, 500],
    );
    assert.equal(vendi.points[1].verdict, "failed");
  });

  it("starts a new labeled series on policy/reference reset", () => {
    const points: DecisionPoint[] = [
      { release: release(1), decision: decision(), job: job("ACCEPTED") },
      { release: release(2, { policy_hash: D(42) }), decision: decision(), job: job("ACCEPTED") },
      { release: release(3, { policy_hash: D(42) }), decision: decision(), job: job("ACCEPTED") },
    ];
    const series = timelineSeries(points).filter((s) => s.metric === "collapse_proxy_bps");
    assert.equal(series.length, 2);
    assert.match(series[1].label, /reset @ rev 2/);
    assert.equal(series[1].points[0].revision, 2);
  });
});

describe("jobDetail", () => {
  it("shows ordered reasons, exclusions, and sample sizes", () => {
    const j = job("REJECTED", { receipt_hash: D(55) });
    const d = decision({ verdict: "reject", reasons: ["REPETITION", "FILTER_BUDGET"], metrics: null });
    const v = jobDetail(j, d);
    assert.equal(v.verdict, "rejected");
    assert.deepEqual(v.reasons, ["REPETITION", "FILTER_BUDGET"]);
    assert.equal(v.sample_sizes.reference, null); // gap, not zero
    assert.equal(v.receipt_status, "receipt recorded");
    assert.equal(v.exclusions[0].code, "DUP_PARENT");
  });
});

describe("releaseGraph", () => {
  it("links manifest, policy, reference, decision, and parent", () => {
    const rel = release(3);
    const manifest: Manifest = {
      v: "fv.manifest/1",
      project_id: rel.project_id,
      stream_id: rel.stream_id,
      revision: 3,
      parent_release_hash: D(77),
      reference_hash: rel.reference_hash,
      policy_hash: rel.policy_hash,
      corpus_hash: D(6),
      records: [],
      generation_hash: D(8),
    };
    const g = releaseGraph(rel, manifest, decision());
    const edgeKinds = new Set(g.edges.map((e) => e.kind));
    for (const k of ["manifest", "policy", "reference", "parent", "decision", "generation"]) {
      assert.ok(edgeKinds.has(k as never), `missing edge ${k}`);
    }
  });
});

describe("verifyCommand", () => {
  it("never embeds a token", () => {
    const cmd = verifyCommand(D(99));
    assert.match(cmd, /forgeverity verify/);
    assert.ok(!/token|bearer|authorization/i.test(cmd));
  });
});

describe("scope warning", () => {
  it("disclaims quality claims", () => {
    assert.match(SCOPE_WARNING, /not a claim/i);
  });
});
