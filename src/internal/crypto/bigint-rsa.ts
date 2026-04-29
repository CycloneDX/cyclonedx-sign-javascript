/*!
This file is part of CycloneDX Signing Library for Javascript.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
Copyright (c) OWASP Foundation. All Rights Reserved.
*/

/**
 * Pure-JS raw RSA primitive used by the Web backend.
 *
 * WebCrypto's `crypto.subtle` does not expose a raw RSA primitive
 * (`m^d mod n`). It only offers PKCS#1 v1.5 / PSS / OAEP with built-in
 * padding and hashing. JSS pre-hashed signing requires the algorithm
 * to consume an externally-computed digest, which means the library
 * has to perform the EMSA-PSS or PKCS#1 v1.5 padding step itself and
 * then apply the raw RSA private operation to the result.
 *
 * Implementation:
 *
 *   - JS `BigInt` is used for modular exponentiation.
 *   - The Chinese Remainder Theorem (CRT) optimization is applied
 *     when private parameters `p`, `q`, `dp`, `dq`, `qi` are known,
 *     yielding ~3x to 4x speedup over the direct `m^d mod n` form.
 *   - All arithmetic uses bytes that round-trip through hex strings;
 *     no bit-level micro-optimizations because the perf floor is
 *     "fast enough for one signature per request" (a few milliseconds
 *     on a modern engine for RSA-3072).
 *
 * Security notes:
 *
 *   - This is NOT a constant-time implementation. JS BigInt has no
 *     constant-time guarantee at the engine level. For workloads
 *     where side-channel resistance matters (multi-tenant servers
 *     processing untrusted inputs at high frequency) the user should
 *     prefer the Node backend, where node:crypto routes through
 *     OpenSSL.
 *   - For the typical browser / serverless use case (single signer
 *     producing a signature per page-load or per request), the timing
 *     attack model does not apply: there is no oracle.
 */

/** Convert a Uint8Array (big-endian) into a BigInt. */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const byte of bytes) {
    n = (n << 8n) | BigInt(byte);
  }
  return n;
}

/** Convert a BigInt to a big-endian Uint8Array of the specified byte length. */
export function bigIntToBytes(n: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = n;
  for (let i = length - 1; i >= 0; i -= 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop within bounds.
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw new Error(`bigIntToBytes: value does not fit in ${length} bytes`);
  }
  return out;
}

/** Modular exponentiation: base^exp mod m. Square-and-multiply. */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m === 1n) return 0n;
  let result = 1n;
  let b = base % m;
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % m;
    }
    e >>= 1n;
    b = (b * b) % m;
  }
  return result;
}

/** Decode a JWK base64url-encoded BigInt component. */
export function decodeJwkBigInt(b64url: string): bigint {
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - (b64url.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytesToBigInt(bytes);
}

/** RSA private parameters extracted from a JWK. */
export interface RsaPrivateParams {
  n: bigint;
  e: bigint;
  d: bigint;
  /** Optional CRT components — present in well-formed JWKs. */
  p?: bigint;
  q?: bigint;
  dp?: bigint;
  dq?: bigint;
  qi?: bigint;
}

export interface RsaPublicParams {
  n: bigint;
  e: bigint;
}

/** Modulus size in bytes given the modulus integer. */
export function modulusBytes(n: bigint): number {
  let bits = 0;
  let v = n;
  while (v > 0n) { bits += 1; v >>= 1n; }
  return Math.ceil(bits / 8);
}

/** Modulus size in bits given the modulus integer. */
export function modulusBits(n: bigint): number {
  let bits = 0;
  let v = n;
  while (v > 0n) { bits += 1; v >>= 1n; }
  return bits;
}

/**
 * Raw RSA private operation: `s = m^d mod n`.
 *
 * Uses CRT when `p`, `q`, `dp`, `dq`, `qi` are present (essentially
 * always, for keys imported from a standard JWK or PKCS#8 file).
 */
export function rsaPrivate(em: Uint8Array, params: RsaPrivateParams): Uint8Array {
  const m = bytesToBigInt(em);
  const k = modulusBytes(params.n);

  let s: bigint;
  if (params.p !== undefined && params.q !== undefined &&
      params.dp !== undefined && params.dq !== undefined && params.qi !== undefined) {
    // CRT: m1 = m^dp mod p; m2 = m^dq mod q; h = qi * (m1 - m2) mod p; s = m2 + h * q
    const m1 = modPow(m % params.p, params.dp, params.p);
    const m2 = modPow(m % params.q, params.dq, params.q);
    let diff = m1 - m2;
    if (diff < 0n) diff += params.p;
    const h = (params.qi * diff) % params.p;
    s = (m2 + h * params.q) % params.n;
  } else {
    s = modPow(m, params.d, params.n);
  }
  return bigIntToBytes(s, k);
}

/** Raw RSA public operation: `m = s^e mod n`. */
export function rsaPublic(signature: Uint8Array, params: RsaPublicParams): Uint8Array {
  const s = bytesToBigInt(signature);
  const k = modulusBytes(params.n);
  const m = modPow(s, params.e, params.n);
  return bigIntToBytes(m, k);
}
