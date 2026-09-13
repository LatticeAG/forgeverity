/**
 * RFC 8785 (JCS) canonicalization and the ForgeVerity digest helpers.
 *
 * J(x) is the RFC8785 UTF-8 byte encoding. B(x) = "sha256:" + hex(SHA256(J(x))).
 * D(bytes) = "sha256:" + hex(SHA256(bytes)). Only safe integers are
 * canonicalizable — the wire format has no non-integral numbers.
 */

import { createHash } from "node:crypto";

export const INT_MIN = -(2 ** 53 - 1);
export const INT_MAX = 2 ** 53 - 1;

export type Json =
  | string
  | number
  | boolean
  | null
  | Json[]
  | { [key: string]: Json };

export class CanonicalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalError";
  }
}

const ESCAPES: Record<number, string> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

function escapeString(text: string): string {
  let out = '"';
  for (const ch of text) {
    const code = ch.codePointAt(0) as number;
    if (code < 0x20 || code === 0x22 || code === 0x5c) {
      out += ESCAPES[code] ?? `\\u${code.toString(16).padStart(4, "0")}`;
    } else if (code >= 0xd800 && code <= 0xdfff) {
      // Unpaired surrogates are invalid input, not canonicalizable.
      throw new CanonicalError("unpaired surrogate in string");
    } else {
      out += ch;
    }
  }
  return out + '"';
}

export function canonicalize(value: Json): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < INT_MIN || value > INT_MAX) {
      throw new CanonicalError(`non-integral or unsafe number: ${value}`);
    }
    return String(value);
  }
  if (typeof value === "string") return escapeString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    // JS string ordering already compares UTF-16 code units — RFC 8785's rule.
    const keys = Object.keys(value).sort();
    const parts = keys.map((k) => `${escapeString(k)}:${canonicalize((value as Record<string, Json>)[k])}`);
    return "{" + parts.join(",") + "}";
  }
  throw new CanonicalError(`cannot canonicalize ${typeof value}`);
}

export function J(value: Json): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

function hex(buf: ArrayBuffer | Uint8Array): string {
  return Buffer.from(buf as Uint8Array).toString("hex");
}

export function D(data: Uint8Array): string {
  return "sha256:" + hex(createHash("sha256").update(data).digest());
}

export function B(value: Json): string {
  return D(J(value));
}
