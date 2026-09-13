/**
 * ForgeVerity offline export-bundle verifier (spec sections 8, 9.4, 12).
 *
 * Port of the Python `verify.py` historical path: trust chain, receipt
 * chain, checkpoint tip binding, signed metadata DAG, generation/origin
 * signatures, and artifact/corpus cross-checks. The caller pins the project
 * receipt root out of band — bundled keys are never trusted by themselves.
 *
 * Decision replay ("REPLAY_MISMATCH") is intentionally not implemented here:
 * recomputation lives in the authoritative Python pipeline. Freshness is
 * always "unproven" for offline verification.
 */

import {
  SchemaError,
  validateExportBundle,
  validateKeyRecord,
  type DecisionCore,
  type ExportBundle,
  type Generation,
  type JsonValue,
  type KeyRecord,
  type Receipt,
  type TrustSnapshot,
} from "@forgeverity/schema";
import {
  checkpointSubject,
  entryHash,
  keyValidAt,
  trustGeneratorKey,
  trustSourceKey,
  verifyGeneration,
  verifyOrigin,
  verifyReceiptSig,
  verifyTrustChain,
} from "./audit.js";
import { B, type Json } from "./jcs.js";

export type VerifyCode =
  | "SCHEMA"
  | "HASH_MISMATCH"
  | "SIGNATURE_INVALID"
  | "TRUST_MISMATCH"
  | "UNSUPPORTED_VERSION"
  | "REPLAY_MISMATCH";

export interface VerifyOk {
  valid: true;
  freshness: "unproven" | "current";
  release_hash: string;
  replay: "not_requested";
}

export interface VerifyFail {
  valid: false;
  code: VerifyCode;
  message: string;
}

export type VerifyResult = VerifyOk | VerifyFail;

export interface VerifyInput {
  bundle: ExportBundle;
  /** Out-of-band pinned receipt-root KeyRecord. Required. */
  pinned_root: KeyRecord;
  /** "historical" (default) or "current"; current requires `client`. */
  mode?: "historical" | "current";
  /** Optional TipDescriptor pinned out of band; detects rollback. */
  checkpoint_pin?: { seq: number; entry_hash: string } | null;
  /** Optional digest -> decoded artifact map for corpus/record checks. */
  artifacts?: Record<string, JsonValue>;
  /** Replay requests are refused by the TS verifier (WORKER_UNAVAILABLE). */
  replay?: boolean;
  /** Authenticated client for mode:"current" fresh state/key reads. */
  client?: {
    getStream(streamId: string): Promise<{ head_release_hash: string; state: string }> | { head_release_hash: string; state: string };
    getKeys(): Promise<{ keys: KeyRecord[] }> | { keys: KeyRecord[] };
  } | null;
}

/** Operational/transport failure — not a verification verdict. */
export class VerifyTransportError extends Error {
  readonly code = "WORKER_UNAVAILABLE" as const;
  constructor(message: string) {
    super(message);
    this.name = "VerifyTransportError";
  }
}

class VerifyError extends Error {
  constructor(
    readonly code: VerifyCode,
    message: string,
  ) {
    super(message);
    this.name = "VerifyError";
  }
}

function fail(code: VerifyCode, msg: string): never {
  throw new VerifyError(code, msg);
}

function schemaToVerify(exc: SchemaError): VerifyError {
  return new VerifyError("SCHEMA", exc.message);
}

function keysById(snapshots: TrustSnapshot[]): Map<string, KeyRecord> {
  const out = new Map<string, KeyRecord>();
  for (const snap of snapshots) {
    out.set(snap.receipt_root.id, snap.receipt_root);
    for (const s of snap.sources) out.set(s.key.id, s.key);
    for (const g of snap.generators) out.set(g.id, g);
  }
  return out;
}

function receiptRootAt(snapshots: TrustSnapshot[], activationSeqs: number[], seq: number): KeyRecord {
  let chosen = snapshots[0];
  for (let i = 0; i < snapshots.length; i++) {
    if (activationSeqs[i] <= seq) chosen = snapshots[i];
  }
  return chosen.receipt_root;
}

export async function verifyExportBundle(inputs: VerifyInput): Promise<VerifyResult> {
  try {
    return await inner(inputs);
  } catch (exc) {
    if (exc instanceof VerifyError) return { valid: false, code: exc.code, message: exc.message };
    throw exc;
  }
}

async function inner(inputs: VerifyInput): Promise<VerifyResult> {
  const mode = inputs.mode ?? "historical";
  if (mode !== "historical" && mode !== "current") {
    fail("SCHEMA", "mode must be historical or current.");
  }
  // Spec: the TS client refuses replay entirely (WORKER_UNAVAILABLE).
  if (inputs.replay) {
    throw new VerifyTransportError("Decision replay requires the Python verifier.");
  }
  if (typeof inputs !== "object" || inputs === null) fail("SCHEMA", "verify input must be an object");
  const { bundle, pinned_root: pinnedRoot } = inputs;
  const artifacts = inputs.artifacts ?? {};
  const checkpointPin = inputs.checkpoint_pin ?? null;

  try {
    validateKeyRecord(pinnedRoot);
    validateExportBundle(bundle);
  } catch (exc) {
    if (exc instanceof SchemaError) throw schemaToVerify(exc);
    throw exc;
  }

  const snapshots = bundle.trust_snapshots;
  if (!verifyTrustChain(snapshots, pinnedRoot)) {
    fail("TRUST_MISMATCH", "Trust snapshot chain does not verify under the pinned root.");
  }
  keysById(snapshots); // populated for API parity / future online checks

  // Activation sequence per snapshot: snapshot[0] -> 0; later snapshots
  // activate at their KEY_ROTATED audit seq (subject = B(snapshot)).
  const activationSeqs = [0];
  const receipts = bundle.receipts;
  for (const snap of snapshots.slice(1)) {
    let act: number | null = null;
    for (const r of receipts) {
      if (r.body.event === "KEY_ROTATED" && r.body.subject_hash === B(snap as unknown as Json)) {
        act = r.body.seq;
      }
    }
    if (act === null) fail("TRUST_MISMATCH", "A trust snapshot lacks its KEY_ROTATED event.");
    activationSeqs.push(act);
  }

  // Receipt chain: contiguous seq from 1, exact previous_hash links.
  let prevHash: string | null = null;
  for (let i = 0; i < receipts.length; i++) {
    const receipt = receipts[i];
    const body = receipt.body;
    if (body.seq !== i + 1) fail("SCHEMA", "Audit sequence gap.");
    if (body.previous_hash !== prevHash) fail("HASH_MISMATCH", "Audit previous_hash link broken.");
    if (entryHash(body as unknown as Json) !== receipt.entry_hash) {
      fail("HASH_MISMATCH", "Audit entry hash mismatch.");
    }
    const root = receiptRootAt(snapshots, activationSeqs, body.seq);
    if (body.key_id !== root.id) fail("TRUST_MISMATCH", "Receipt signed by a non-root key.");
    if (!keyValidAt(root, body.at_ms)) fail("TRUST_MISMATCH", "Receipt key not valid at event time.");
    if (!verifyReceiptSig(root.public_key, receipt.signature, receipt.entry_hash)) {
      fail("SIGNATURE_INVALID", "Receipt signature invalid.");
    }
    prevHash = receipt.entry_hash;
  }
  const tipSeq = receipts.length;
  const tipHash = prevHash;

  // Checkpoint receipt: extends the supplied tip; subject is B(TipDescriptor).
  const ckpt = bundle.checkpoint;
  const cbody = ckpt.body;
  if (cbody.event !== "CHECKPOINTED") fail("SCHEMA", "checkpoint is not a CHECKPOINTED receipt.");
  if (cbody.previous_hash !== tipHash) {
    fail("TRUST_MISMATCH", "Checkpoint does not extend the supplied chain tip.");
  }
  if (cbody.subject_hash !== checkpointSubject(tipSeq, tipHash as string)) {
    fail("HASH_MISMATCH", "Checkpoint tip descriptor mismatch.");
  }
  if (entryHash(cbody as unknown as Json) !== ckpt.entry_hash) {
    fail("HASH_MISMATCH", "Checkpoint entry hash mismatch.");
  }
  const croot = receiptRootAt(snapshots, activationSeqs, cbody.seq);
  if (cbody.key_id !== croot.id || !keyValidAt(croot, cbody.at_ms)) {
    fail("TRUST_MISMATCH", "Checkpoint key invalid at event time.");
  }
  if (!verifyReceiptSig(croot.public_key, ckpt.signature, ckpt.entry_hash)) {
    fail("SIGNATURE_INVALID", "Checkpoint signature invalid.");
  }

  // Out-of-band pinned checkpoint detects rollback before its sequence.
  if (checkpointPin !== null) {
    if (checkpointPin.seq > tipSeq) {
      fail("TRUST_MISMATCH", "Pinned checkpoint is not covered by the chain.");
    }
    if (receipts[checkpointPin.seq - 1].entry_hash !== checkpointPin.entry_hash) {
      fail("TRUST_MISMATCH", "Pinned checkpoint hash does not match the chain.");
    }
  }

  // Signed metadata DAG.
  const { release, manifest, decision, reference, policy } = bundle;

  if (release.manifest_hash !== B(manifest as unknown as Json)) {
    fail("HASH_MISMATCH", "Release manifest hash mismatch.");
  }
  if (release.policy_hash !== B(policy as unknown as Json) || manifest.policy_hash !== B(policy as unknown as Json)) {
    fail("HASH_MISMATCH", "Policy hash mismatch.");
  }
  if (
    release.reference_hash !== B(reference as unknown as Json) ||
    manifest.reference_hash !== B(reference as unknown as Json)
  ) {
    fail("HASH_MISMATCH", "Reference hash mismatch.");
  }
  if ((release.decision_hash === null) !== (decision === null)) {
    fail("HASH_MISMATCH", "Release/decision link mismatch.");
  }
  if (decision !== null && release.decision_hash !== B(decision as unknown as Json)) {
    fail("HASH_MISMATCH", "Decision hash mismatch.");
  }
  if (release.kind === "genesis" && release.decision_hash !== null) {
    fail("SCHEMA", "Genesis release cannot carry a decision.");
  }
  if (release.kind === "accepted" && (decision === null || decision.verdict !== "accept")) {
    fail("SCHEMA", "Accepted release requires an accept DecisionCore.");
  }

  // The creating receipt (JOB_ACCEPTED or STREAM_CREATED) must be in the chain.
  const releaseDigest = B(release as unknown as Json);
  const creating = receipts.find(
    (r) =>
      r.body.subject_hash === releaseDigest &&
      (r.body.event === "JOB_ACCEPTED" || r.body.event === "STREAM_CREATED"),
  );
  if (creating === undefined) fail("TRUST_MISMATCH", "No chain event records this release.");

  // Ancestors oldest-first, hash-consistent, chain-linked through
  // manifest.parent_release_hash, ending at the parent release.
  let prevReleaseHash: string | null = null;
  for (const anc of bundle.ancestors) {
    const ancHash = B(anc.release as unknown as Json);
    if (prevReleaseHash !== null && anc.manifest.parent_release_hash !== prevReleaseHash) {
      fail("HASH_MISMATCH", "Ancestor ordering is broken.");
    }
    if (anc.release.manifest_hash !== B(anc.manifest as unknown as Json)) {
      fail("HASH_MISMATCH", "Ancestor manifest hash mismatch.");
    }
    if ((anc.release.decision_hash === null) !== (anc.decision === null)) {
      fail("HASH_MISMATCH", "Ancestor decision link mismatch.");
    }
    if (anc.decision !== null && anc.release.decision_hash !== B(anc.decision as unknown as Json)) {
      fail("HASH_MISMATCH", "Ancestor decision hash mismatch.");
    }
    prevReleaseHash = ancHash;
  }
  if (
    bundle.ancestors.length > 0 &&
    manifest.parent_release_hash !== B(bundle.ancestors[bundle.ancestors.length - 1].release as unknown as Json)
  ) {
    fail("HASH_MISMATCH", "Manifest parent link mismatch.");
  }

  // Generations: digest-sorted, verified under pinned generator keys valid
  // at the claimed signing time.
  const gens = bundle.generations;
  const sorted = [...gens].sort((a, b) => (B(a as unknown as Json) < B(b as unknown as Json) ? -1 : 1));
  for (let i = 0; i < gens.length; i++) {
    if (gens[i] !== sorted[i]) fail("SCHEMA", "Generations are not digest-sorted.");
  }
  for (const g of gens) {
    const gb = g.body;
    let key: KeyRecord | null = null;
    for (const snap of snapshots) {
      const k = trustGeneratorKey(snap, gb.key_id);
      if (k !== null) key = k;
    }
    if (key === null) fail("TRUST_MISMATCH", "Generator key is not pinned.");
    if (!keyValidAt(key, gb.created_at_ms)) {
      fail("TRUST_MISMATCH", "Generator key invalid at signing time.");
    }
    if (!verifyGeneration(g as { body: Json; signature: string }, key.public_key)) {
      fail("SIGNATURE_INVALID", "Generation signature invalid.");
    }
  }

  // Origin assertion under the pinned source key.
  let okey: KeyRecord | null = null;
  for (const snap of snapshots) {
    const k = trustSourceKey(snap, reference.origin.body.source_id, reference.origin.body.key_id);
    if (k !== null) okey = k;
  }
  if (okey === null) fail("TRUST_MISMATCH", "Origin source key is not pinned.");
  if (!verifyOrigin(reference.origin as { body: Json; signature: string }, okey.public_key)) {
    fail("SIGNATURE_INVALID", "Origin signature invalid.");
  }

  // Artifact hashes: every supplied artifact must match its digest.
  for (const [digest, value] of Object.entries(artifacts)) {
    if (B(value as Json) !== digest) fail("HASH_MISMATCH", `Artifact ${digest} does not match its bytes.`);
  }

  // Corpus cross-check when supplied.
  const corpus = artifacts[manifest.corpus_hash] as { records?: { id: string; title: Json; body: Json; category: Json }[] } | undefined;
  if (corpus !== undefined && corpus !== null) {
    const records = corpus.records ?? [];
    if (records.length !== manifest.records.length) {
      fail("HASH_MISMATCH", "Corpus does not match the manifest.");
    }
    for (let i = 0; i < records.length; i++) {
      const link = manifest.records[i];
      const rec = records[i];
      if (link.record_id !== rec.id) {
        fail("HASH_MISMATCH", "Corpus record order does not match the manifest.");
      }
      if (
        link.content_hash !==
        B({ title: rec.title, body: rec.body, category: rec.category } as unknown as Json)
      ) {
        fail("HASH_MISMATCH", "Corpus record content does not match the manifest.");
      }
    }
  }

  let freshness: "unproven" | "current" = "unproven";
  if (mode === "current") {
    if (inputs.client == null) {
      throw new VerifyTransportError("Current verification requires an authenticated client.");
    }
    const keyMap = keysById(snapshots);
    let stream: { head_release_hash: string; state: string };
    let keys: { keys: KeyRecord[] };
    try {
      stream = await inputs.client.getStream(release.stream_id);
      keys = await inputs.client.getKeys();
    } catch (exc) {
      if (exc instanceof VerifyTransportError) throw exc;
      throw new VerifyTransportError("Online state read failed.");
    }
    if (stream.head_release_hash !== releaseDigest || stream.state !== "ACTIVE") {
      fail("TRUST_MISMATCH", "Release is not the active stream head.");
    }
    const live = new Map(keys.keys.map((k) => [k.id, k]));
    for (const [kid] of keyMap) {
      const cur = live.get(kid);
      if (cur !== undefined && cur.revoked_at_ms !== null) {
        fail("TRUST_MISMATCH", `Key ${kid} is currently revoked.`);
      }
    }
    freshness = "current";
  }

  return {
    valid: true,
    freshness,
    release_hash: releaseDigest,
    replay: "not_requested",
  };
}
