import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  SchemaError,
  isCanonicalB64u,
  isDigest,
  isId,
  validateKeyRecord,
  validateReceipt,
} from "../src/validators.js";

const D = `sha256:${"ab".repeat(32)}`;
const KEY32 = "A".repeat(43);
const SIG64 = "A".repeat(86);

function keyRecord(over: Record<string, unknown> = {}) {
  return {
    id: "fvkey_AAAAAAAAAAAAAAAAAAAAA",
    public_key: KEY32,
    purpose: "receipt",
    valid_from_ms: 0,
    valid_until_ms: 1000,
    revoked_at_ms: null,
    ...over,
  };
}

describe("lexical primitives", () => {
  it("digest accepts canonical sha256 form", () => {
    assert.ok(isDigest(D));
  });
  it("digest rejects bad forms", () => {
    for (const bad of ["", "sha256:", "SHA256:" + "ab".repeat(32), "sha256:" + "AB".repeat(32), "sha256:" + "ab".repeat(31)]) {
      assert.ok(!isDigest(bad), bad);
    }
  });
  it("ids require fv prefix + 21 nanoid chars", () => {
    assert.ok(isId("fvkey_AAAAAAAAAAAAAAAAAAAAA"));
    assert.ok(!isId("fvkey_short"));
    assert.ok(!isId("xxxxx_AAAAAAAAAAAAAAAAAAAAA"));
    assert.ok(!isId("fvkey_AAAAAAAAAAAAAAAAAAAA="));
  });
  it("canonical b64u rejects padding and unused bits", () => {
    assert.ok(isCanonicalB64u(KEY32, 32));
    assert.ok(!isCanonicalB64u(KEY32 + "=", 32));
    assert.ok(!isCanonicalB64u("A".repeat(42), 32));
    // 32 bytes -> 43 chars, last char carries 2 bits (32*8 % 6 = 4 -> 6-4=2 unused)
    assert.ok(!isCanonicalB64u("A".repeat(42) + "B", 32));
    assert.ok(isCanonicalB64u("A".repeat(42) + "Q", 32));
  });
});

describe("KeyRecord", () => {
  it("accepts a well-formed record", () => {
    validateKeyRecord(keyRecord());
  });
  it("rejects unknown fields", () => {
    assert.throws(() => validateKeyRecord(keyRecord({ extra: 1 })), SchemaError);
  });
  it("rejects reversed validity window", () => {
    assert.throws(() => validateKeyRecord(keyRecord({ valid_from_ms: 5, valid_until_ms: 5 })), SchemaError);
  });
  it("rejects bad purpose", () => {
    assert.throws(() => validateKeyRecord(keyRecord({ purpose: "admin" })), SchemaError);
  });
});

describe("Receipt", () => {
  const body = {
    v: "fv.audit/1",
    entry_id: "fvent_AAAAAAAAAAAAAAAAAAAAA",
    project_id: "fvprj_AAAAAAAAAAAAAAAAAAAAA",
    seq: 1,
    previous_hash: null,
    at_ms: 0,
    event: "CHECKPOINTED",
    subject_hash: D,
    data: {
      job_id: null,
      stream_id: null,
      from_state: null,
      to_state: null,
      reasons: [],
      revision: null,
    },
    key_id: "fvkey_AAAAAAAAAAAAAAAAAAAAA",
  };
  it("accepts a well-formed receipt", () => {
    validateReceipt({ body, entry_hash: D, signature: SIG64 });
  });
  it("rejects a missing event-data key", () => {
    const bad = { ...body, data: { ...body.data, extra: null } };
    assert.throws(() => validateReceipt({ body: bad, entry_hash: D, signature: SIG64 }), SchemaError);
  });
  it("rejects an unknown event name", () => {
    const bad = { ...body, event: "NOPE" };
    assert.throws(() => validateReceipt({ body: bad, entry_hash: D, signature: SIG64 }), SchemaError);
  });
});
