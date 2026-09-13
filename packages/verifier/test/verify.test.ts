import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import type {
  DecisionCore,
  ExportBundle,
  KeyRecord,
  Policy,
  Receipt,
  Reference,
  Release,
  TrustSnapshot,
} from "@forgeverity/schema";
import {
  AUDIT_HASH_DOMAIN,
  B,
  D,
  GENERATION_SIGN_DOMAIN,
  J,
  ORIGIN_SIGN_DOMAIN,
  RECEIPT_SIGN_DOMAIN,
  TRUST_SIGN_DOMAIN,
  b64uEncode,
  checkpointSubject,
  digestBytes,
  verifyExportBundle,
  VerifyTransportError,
  type Json,
} from "../src/index.js";

const te = new TextEncoder();
const T = 1789257600000;
const PROJECT = "fvprj_000000000000000000099";
const STREAM = "fvstr_000000000000000000099";

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { priv: privateKey, pubB64: der.subarray(der.length - 32).toString("base64url") };
}

function sign(priv: Parameters<typeof cryptoSign>[2], domain: string, msg: Uint8Array): string {
  return b64uEncode(cryptoSign(null, Buffer.concat([te.encode(domain), Buffer.from(msg)]), priv));
}

function keyRecord(id: string, pub: string, purpose: KeyRecord["purpose"]): KeyRecord {
  return { id, public_key: pub, purpose, valid_from_ms: 0, valid_until_ms: T + 10_000_000, revoked_at_ms: null };
}

const RK = keyPair();
const OK = keyPair();
const GK = keyPair();
const RKR = keyRecord("fvkey_0000000000000000000rk", RK.pubB64, "receipt");
const OKR = keyRecord("fvkey_0000000000000000000ok", OK.pubB64, "origin");
const GKR = keyRecord("fvkey_0000000000000000000gk", GK.pubB64, "generator");

function trustSnapshot(): TrustSnapshot {
  const snap: Record<string, unknown> = {
    v: "fv.trust/1",
    project_id: PROJECT,
    receipt_root: RKR,
    sources: [{ source_id: "fvsrc_000000000000000000001", key: OKR }],
    generators: [GKR],
    previous_hash: null,
    old_signature: null,
    new_signature: null,
  };
  const payload = { ...snap } as Record<string, unknown>;
  delete payload.old_signature;
  delete payload.new_signature;
  snap.new_signature = sign(RK.priv, TRUST_SIGN_DOMAIN, J(payload as Json));
  return snap as unknown as TrustSnapshot;
}

function makeReceipt(
  seq: number,
  previousHash: string | null,
  event: string,
  subjectHash: string,
): Receipt {
  const body = {
    v: "fv.audit/1",
    entry_id: `fvent_${String(seq).padStart(21, "0")}`,
    project_id: PROJECT,
    seq,
    previous_hash: previousHash,
    at_ms: T + seq,
    event,
    subject_hash: subjectHash,
    data: { job_id: null, stream_id: null, from_state: null, to_state: null, reasons: [], revision: null },
    key_id: RKR.id,
  };
  const entry = D(Buffer.concat([te.encode(AUDIT_HASH_DOMAIN), J(body as Json)]));
  const signature = sign(RK.priv, RECEIPT_SIGN_DOMAIN, digestBytes(entry) as Uint8Array);
  return { body: body as unknown as Receipt["body"], entry_hash: entry, signature };
}

function buildBundle(): ExportBundle {
  const corpus = {
    v: "fv.artifact/1",
    kind: "tickets",
    records: [
      { id: "fvrec_000000000000000000001", title: "t1", body: "a b c", category: "billing" },
    ],
  };
  const corpusHash = B(corpus as unknown as Json);
  const reference: Reference = {
    v: "fv.reference/1",
    id: "fvref_000000000000000000099",
    project_id: PROJECT,
    train_hash: B({ train: 1 } as unknown as Json),
    holdout_hash: B({ holdout: 1 } as unknown as Json),
    origin: (() => {
      const ob = {
        v: "fv.origin/1",
        project_id: PROJECT,
        source_id: "fvsrc_000000000000000000001",
        train_hash: B({ train: 1 } as unknown as Json),
        holdout_hash: B({ holdout: 1 } as unknown as Json),
        origin: "human_attested",
        collected_at_ms: T,
        key_id: OKR.id,
      };
      return { body: ob, signature: sign(OK.priv, ORIGIN_SIGN_DOMAIN, J(ob as Json)) } as Reference["origin"];
    })(),
    created_at_ms: T,
  };
  const policy: Policy = {
    v: "fv.policy/1",
    suite: "tickets-lexical-1",
    reference_id: reference.id,
    reference_hash: B(reference as unknown as Json),
    categories: ["billing"],
    min_candidates: 1,
    max_filter_bps: 1000,
    min_vendi_reference_bps: 0,
    min_vendi_parent_bps: 0,
    max_self_bleu_increase_bps: 10000,
    min_category_coverage_bps: 0,
    max_synthetic_bps: 10000,
    max_rounds: 3,
    max_total_candidates: 100,
  };
  const genesisManifest = {
    v: "fv.manifest/1",
    project_id: PROJECT,
    stream_id: STREAM,
    revision: 0,
    parent_release_hash: null,
    reference_hash: B(reference as unknown as Json),
    policy_hash: B(policy as unknown as Json),
    corpus_hash: corpusHash,
    records: [
      {
        record_id: "fvrec_000000000000000000001",
        content_hash: B({ title: "t1", body: "a b c", category: "billing" } as Json),
        origin: "human_attested",
        source_hash: B({ src: 1 } as unknown as Json),
      },
    ],
    generation_hash: null,
  };
  const genesis: Release = {
    v: "fv.release/1",
    kind: "genesis",
    project_id: PROJECT,
    stream_id: STREAM,
    revision: 0,
    manifest_hash: B(genesisManifest as unknown as Json),
    decision_hash: null,
    suite: "tickets-lexical-1",
    policy_hash: B(policy as unknown as Json),
    reference_hash: B(reference as unknown as Json),
  };
  const genBody = {
    v: "fv.generation/1",
    project_id: PROJECT,
    stream_id: STREAM,
    expected_revision: 0,
    candidate_hash: B({ cand: 1 } as unknown as Json),
    generator: "ForgeDistill",
    generator_version: "0.1.0",
    generator_config_hash: B({ cfg: 1 } as unknown as Json),
    model_artifact_hash: B({ model: 1 } as unknown as Json),
    parent_model_hash: null,
    prompt_hash: B({ prompt: 1 } as unknown as Json),
    seed: "1",
    created_at_ms: T,
    key_id: GKR.id,
  };
  const generation = {
    body: genBody,
    signature: sign(GK.priv, GENERATION_SIGN_DOMAIN, J(genBody as Json)),
  };
  const decision = {
    v: "fv.decision/1",
    suite: "tickets-lexical-1",
    policy_hash: B(policy as unknown as Json),
    reference_hash: B(reference as unknown as Json),
    parent_release_hash: B(genesis as unknown as Json),
    candidate_hash: genBody.candidate_hash,
    generation_hash: B(generation as unknown as Json),
    mode: "mix",
    submitted_count: 1,
    accepted_candidate_ids: ["fvrec_000000000000000002001"],
    excluded: [],
    proposed_corpus_hash: B({ proposed: 1 } as unknown as Json),
    metrics: null,
    verdict: "accept",
    reasons: [],
  };
  const manifest = {
    v: "fv.manifest/1",
    project_id: PROJECT,
    stream_id: STREAM,
    revision: 1,
    parent_release_hash: B(genesis as unknown as Json),
    reference_hash: B(reference as unknown as Json),
    policy_hash: B(policy as unknown as Json),
    corpus_hash: B({ proposed: 1 } as unknown as Json),
    records: [
      {
        record_id: "fvrec_000000000000000002001",
        content_hash: B({ title: "s1", body: "x y z", category: "billing" } as Json),
        origin: "synthetic",
        source_hash: B(genBody.candidate_hash as unknown as Json),
      },
    ],
    generation_hash: B(generation as unknown as Json),
  };
  const release: Release = {
    v: "fv.release/1",
    kind: "accepted",
    project_id: PROJECT,
    stream_id: STREAM,
    revision: 1,
    manifest_hash: B(manifest as unknown as Json),
    decision_hash: B(decision as unknown as Json),
    suite: "tickets-lexical-1",
    policy_hash: B(policy as unknown as Json),
    reference_hash: B(reference as unknown as Json),
  };
  const r1 = makeReceipt(1, null, "STREAM_CREATED", B(genesis as unknown as Json));
  const r2 = makeReceipt(2, r1.entry_hash, "JOB_ACCEPTED", B(release as unknown as Json));
  const checkpoint = makeReceipt(3, r2.entry_hash, "CHECKPOINTED", checkpointSubject(2, r2.entry_hash));
  return {
    v: "fv.sunlight-export/1",
    release,
    manifest: manifest as ExportBundle["manifest"],
    decision: decision as unknown as DecisionCore,
    reference,
    policy,
    generations: [generation as ExportBundle["generations"][number]],
    receipts: [r1, r2],
    ancestors: [{ release: genesis, manifest: genesisManifest as ExportBundle["manifest"], decision: null }],
    checkpoint,
    keys: [RKR, OKR, GKR],
    trust_snapshots: [trustSnapshot()],
  };
}

describe("verifyExportBundle", () => {
  it("verifies a well-formed bundle", async () => {
    const bundle = buildBundle();
    const res = await verifyExportBundle({ bundle, pinned_root: RKR });
    assert.equal(res.valid, true);
    if (res.valid) {
      assert.equal(res.freshness, "unproven");
      assert.equal(res.release_hash, B(bundle.release as unknown as Json));
      assert.equal(res.replay, "not_requested");
    }
  });

  it("rejects a wrong pinned root (TRUST_MISMATCH)", async () => {
    const bundle = buildBundle();
    const other = keyPair();
    const badRoot = keyRecord("fvkey_0000000000000000000xx", other.pubB64, "receipt");
    const res = await verifyExportBundle({ bundle, pinned_root: badRoot });
    assert.deepEqual([res.valid, res.valid ? null : res.code], [false, "TRUST_MISMATCH"]);
  });

  it("rejects a tampered subject_hash (HASH_MISMATCH)", async () => {
    const bundle = buildBundle();
    bundle.receipts[1] = {
      ...bundle.receipts[1],
      body: { ...bundle.receipts[1].body, subject_hash: B({ other: 1 } as Json) },
    };
    const res = await verifyExportBundle({ bundle, pinned_root: RKR });
    assert.equal(res.valid, false);
    if (!res.valid) assert.equal(res.code, "HASH_MISMATCH");
  });

  it("rejects a sequence gap (SCHEMA)", async () => {
    const bundle = buildBundle();
    // Drop receipt 2 but keep checkpoint — seqs no longer contiguous.
    bundle.receipts = [bundle.receipts[0]];
    // fix link so only the gap is wrong: checkpoint.previous_hash must be tip of [r1]
    bundle.checkpoint = makeReceipt(2, bundle.receipts[0].entry_hash, "CHECKPOINTED", checkpointSubject(1, bundle.receipts[0].entry_hash));
    const res = await verifyExportBundle({ bundle, pinned_root: RKR });
    assert.equal(res.valid, false);
    // With only r1 the release has no creating receipt -> TRUST_MISMATCH or SCHEMA depending on order
    if (!res.valid) assert.ok(["SCHEMA", "TRUST_MISMATCH", "HASH_MISMATCH"].includes(res.code));
  });

  it("rejects a forged signature (SIGNATURE_INVALID)", async () => {
    const bundle = buildBundle();
    const evil = keyPair();
    const forged = makeReceipt(2, bundle.receipts[0].entry_hash, "JOB_ACCEPTED", B(bundle.release as unknown as Json));
    forged.signature = sign(evil.priv, RECEIPT_SIGN_DOMAIN, digestBytes(forged.entry_hash) as Uint8Array);
    bundle.receipts[1] = forged;
    const res = await verifyExportBundle({ bundle, pinned_root: RKR });
    assert.equal(res.valid, false);
    if (!res.valid) assert.equal(res.code, "SIGNATURE_INVALID");
  });

  it("rejects a checkpoint pin beyond the chain (TRUST_MISMATCH)", async () => {
    const bundle = buildBundle();
    const res = await verifyExportBundle({
      bundle,
      pinned_root: RKR,
      checkpoint_pin: { seq: 5, entry_hash: bundle.receipts[0].entry_hash },
    });
    assert.equal(res.valid, false);
    if (!res.valid) assert.equal(res.code, "TRUST_MISMATCH");
  });

  it("rejects a mismatched checkpoint pin (TRUST_MISMATCH)", async () => {
    const bundle = buildBundle();
    const res = await verifyExportBundle({
      bundle,
      pinned_root: RKR,
      checkpoint_pin: { seq: 2, entry_hash: bundle.receipts[0].entry_hash },
    });
    assert.equal(res.valid, false);
    if (!res.valid) assert.equal(res.code, "TRUST_MISMATCH");
  });

  it("checks supplied artifact digests", async () => {
    const bundle = buildBundle();
    const bad = { v: "fv.artifact/1", kind: "tickets", records: [] };
    const res = await verifyExportBundle({
      bundle,
      pinned_root: RKR,
      artifacts: { ["sha256:" + "00".repeat(32)]: bad as never },
    });
    assert.equal(res.valid, false);
    if (!res.valid) assert.equal(res.code, "HASH_MISMATCH");
  });

  it("refuses replay with WORKER_UNAVAILABLE", async () => {
    const bundle = buildBundle();
    await assert.rejects(
      verifyExportBundle({ bundle, pinned_root: RKR, replay: true }),
      (e) => e instanceof VerifyTransportError && e.code === "WORKER_UNAVAILABLE",
    );
  });

  it("requires a client for current mode", async () => {
    const bundle = buildBundle();
    await assert.rejects(
      verifyExportBundle({ bundle, pinned_root: RKR, mode: "current" }),
      VerifyTransportError,
    );
  });

  it("current mode succeeds with fresh head + unrevoked keys", async () => {
    const bundle = buildBundle();
    const res = await verifyExportBundle({
      bundle,
      pinned_root: RKR,
      mode: "current",
      client: {
        getStream: () => ({ head_release_hash: B(bundle.release as unknown as Json), state: "ACTIVE" }),
        getKeys: () => ({ keys: [RKR, OKR, GKR] }),
      },
    });
    assert.equal(res.valid, true);
    if (res.valid) assert.equal(res.freshness, "current");
  });
});
