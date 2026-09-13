/**
 * ForgeVerity §8 audit primitives: domains, receipt hashes, Ed25519
 * verification, and trust-snapshot chain checks — ported from Python
 * `audit.py`. This module verifies; it never signs.
 */

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { Json } from "./jcs.js";
import { B, D, J } from "./jcs.js";
import { b64uDecode, digestBytes } from "./codec.js";
import type { KeyRecord, Receipt, TrustSnapshot } from "@forgeverity/schema";

export const AUDIT_HASH_DOMAIN = "forgeverity.audit.v1\n";
export const RECEIPT_SIGN_DOMAIN = "forgeverity.receipt.v1\n";
export const ORIGIN_SIGN_DOMAIN = "forgeverity.origin.v1\n";
export const GENERATION_SIGN_DOMAIN = "forgeverity.generation.v1\n";
export const TRUST_SIGN_DOMAIN = "forgeverity.trust.v1\n";

const te = new TextEncoder();

/** Ed25519 SPKI DER prefix for a raw 32-byte public key. */
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function verifyBytes(publicKeyB64u: string, signatureB64u: string, message: Uint8Array): boolean {
  const rawPub = b64uDecode(publicKeyB64u, 32);
  const rawSig = b64uDecode(signatureB64u, 64);
  if (rawPub === null || rawSig === null) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([SPKI_PREFIX, Buffer.from(rawPub)]),
      format: "der",
      type: "spki",
    });
    return cryptoVerify(null, Buffer.from(message), key, Buffer.from(rawSig));
  } catch {
    return false;
  }
}

export function entryHash(body: Json): string {
  return D(concat(te.encode(AUDIT_HASH_DOMAIN), J(body)));
}

export function verifyReceiptSig(publicKey: string, signature: string, hashDigest: string): boolean {
  const raw = digestBytes(hashDigest);
  if (raw === null) return false;
  return verifyBytes(publicKey, signature, concat(te.encode(RECEIPT_SIGN_DOMAIN), raw));
}

export function verifyOrigin(signed: { body: Json; signature: string }, publicKey: string): boolean {
  return verifyBytes(publicKey, signed.signature, concat(te.encode(ORIGIN_SIGN_DOMAIN), J(signed.body)));
}

export function verifyGeneration(signed: { body: Json; signature: string }, publicKey: string): boolean {
  return verifyBytes(publicKey, signed.signature, concat(te.encode(GENERATION_SIGN_DOMAIN), J(signed.body)));
}

export function trustPayload(snapshot: TrustSnapshot): Uint8Array {
  const { old_signature: _o, new_signature: _n, ...body } = snapshot as Record<string, Json>;
  return concat(te.encode(TRUST_SIGN_DOMAIN), J(body as Json));
}

export function verifyTrustSig(publicKey: string, signature: string, snapshot: TrustSnapshot): boolean {
  return verifyBytes(publicKey, signature, trustPayload(snapshot));
}

export function lifecycleSubject(jobId: string, fromState: string | null, toState: string, fence: number): string {
  return B({ job_id: jobId, from_state: fromState, to_state: toState, fence } as Json);
}

export function checkpointSubject(tipSeq: number, tipHash: string): string {
  return B({ seq: tipSeq, entry_hash: tipHash } as Json);
}

/** Half-open validity: valid_from <= at < valid_until. */
export function keyValidAt(key: KeyRecord, atMs: number): boolean {
  return key.valid_from_ms <= atMs && atMs < key.valid_until_ms;
}

export function trustGeneratorKey(snapshot: TrustSnapshot, keyId: string): KeyRecord | null {
  for (const k of snapshot.generators) {
    if (k.id === keyId) return k;
  }
  return null;
}

export function trustSourceKey(snapshot: TrustSnapshot, sourceId: string, keyId: string): KeyRecord | null {
  for (const entry of snapshot.sources) {
    if (entry.source_id === sourceId && entry.key.id === keyId) return entry.key;
  }
  return null;
}

/**
 * Walk the snapshot chain from the pinned root. The first snapshot must have
 * null previous_hash/old_signature and a new_signature valid under the
 * pinned root; each later snapshot needs old_signature under the preceding
 * root plus new_signature under its own.
 */
export function verifyTrustChain(snapshots: TrustSnapshot[], pinnedRoot: KeyRecord): boolean {
  if (snapshots.length === 0) return false;
  const first = snapshots[0];
  if (first.previous_hash !== null || first.old_signature !== null) return false;
  if (first.receipt_root.id !== pinnedRoot.id) return false;
  if (first.receipt_root.public_key !== pinnedRoot.public_key) return false;
  if (!verifyTrustSig(pinnedRoot.public_key, first.new_signature, first)) return false;
  let prev = first;
  for (const snap of snapshots.slice(1)) {
    if (snap.previous_hash !== B(prev as unknown as Json) || snap.old_signature === null) return false;
    if (!verifyTrustSig(prev.receipt_root.public_key, snap.old_signature, snap)) return false;
    if (!verifyTrustSig(snap.receipt_root.public_key, snap.new_signature, snap)) return false;
    prev = snap;
  }
  return true;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
