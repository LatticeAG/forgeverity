/** Canonical base64url and hex codecs. */

const B64U_RE = /^[A-Za-z0-9_-]*$/;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function b64uEncode(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

/** Canonical unpadded base64url decode; returns null on any violation. */
export function b64uDecode(text: string, expectedLen?: number): Uint8Array | null {
  if (typeof text !== "string" || !B64U_RE.test(text) || text.includes("=")) return null;
  let raw: Buffer;
  try {
    raw = Buffer.from(text, "base64url");
  } catch {
    return null;
  }
  if (expectedLen !== undefined && raw.length !== expectedLen) return null;
  if (raw.toString("base64url") !== text) return null;
  return new Uint8Array(raw);
}

/** Decode "sha256:<64 lowercase hex>" into 32 raw bytes; null on bad form. */
export function digestBytes(digest: string): Uint8Array | null {
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) return null;
  return new Uint8Array(Buffer.from(digest.slice(7), "hex"));
}

export { ALPHABET as B64U_ALPHABET };
