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
 * Shared cryptographic byte primitives used by both the Node and the
 * Web backends.
 *
 * These functions operate on raw bytes and never touch the host
 * crypto API directly; instead they take a `digest()` and a
 * `randomBytes()` callback supplied by the calling backend. That
 * keeps the EMSA-PSS encoding and PKCS#1 DigestInfo building logic in
 * a single audit surface — the only difference between Node and Web
 * is which primitive computes the SHA-* digest.
 */

import type { Sha } from './types.js';

const HASH_LENGTHS: Record<Sha, number> = {
  'sha-256': 32,
  'sha-384': 48,
  'sha-512': 64,
};

export function hashLength(name: Sha): number {
  // eslint-disable-next-line security/detect-object-injection -- `name` narrowed to a Sha literal.
  return HASH_LENGTHS[name];
}

/**
 * PKCS#1 v1.5 DigestInfo SEQUENCE prefixes for the supported hashes,
 * per RFC 3447 Appendix B.1. Concatenate `prefix || hash` to obtain
 * the DER-encoded DigestInfo to wrap with PKCS#1 v1.5 padding.
 */
const DIGEST_INFO_PREFIX: Record<Sha, Uint8Array> = {
  'sha-256': new Uint8Array([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
  ]),
  'sha-384': new Uint8Array([
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
  ]),
  'sha-512': new Uint8Array([
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
  ]),
};

export function buildDigestInfo(hash: Sha, digest: Uint8Array): Uint8Array {
  // eslint-disable-next-line security/detect-object-injection -- `hash` narrowed to a Sha literal.
  const prefix = DIGEST_INFO_PREFIX[hash];
  const out = new Uint8Array(prefix.length + digest.length);
  out.set(prefix, 0);
  out.set(digest, prefix.length);
  return out;
}

/** Constant-time equality on two byte arrays. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop with matched-length arrays.
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  /* c8 ignore next 3 -- defensive guard; xor is module-private and every
     caller (mgf1) passes arrays whose lengths come from the same hash
     length math. Unreachable through any public path. */
  if (a.length !== b.length) {
    throw new Error('xor: inputs must have equal length');
  }
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop with matched-length arrays.
    out[i] = a[i]! ^ b[i]!;
  }
  return out;
}

/** Async digest provider supplied by the backend. */
export type DigestFn = (hash: Sha, data: Uint8Array) => Promise<Uint8Array>;

async function mgf1(
  digestFn: DigestFn,
  hash: Sha,
  seed: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const hLen = hashLength(hash);
  const blocks: Uint8Array[] = [];
  let taken = 0;
  for (let counter = 0; taken < length; counter += 1) {
    const c = new Uint8Array(4);
    new DataView(c.buffer).setUint32(0, counter, false);
    const block = new Uint8Array(seed.length + 4);
    block.set(seed, 0);
    block.set(c, seed.length);
    blocks.push(await digestFn(hash, block));
    taken += hLen;
  }
  const total = new Uint8Array(blocks.reduce((acc, b) => acc + b.length, 0));
  let off = 0;
  for (const b of blocks) {
    total.set(b, off);
    off += b.length;
  }
  return total.subarray(0, length);
}

/**
 * EMSA-PSS-ENCODE per RFC 8017 § 9.1.1. Salt length defaults to the
 * hash length (matches JWA RFC 7518 § 3.5).
 */
export async function pssEncode(
  digestFn: DigestFn,
  randomBytes: (n: number) => Uint8Array,
  hash: Sha,
  mHash: Uint8Array,
  saltLength: number,
  modulusBits: number,
): Promise<Uint8Array> {
  const hLen = hashLength(hash);
  if (mHash.length !== hLen) {
    throw new Error(`pssEncode: hash length mismatch (got ${mHash.length}, expected ${hLen})`);
  }
  const sLen = saltLength;
  const emBits = modulusBits - 1;
  const emLen = Math.ceil(emBits / 8);

  if (emLen < hLen + sLen + 2) {
    throw new Error('RSA modulus too small for PSS encoding');
  }

  const salt = randomBytes(sLen);
  const mPrime = new Uint8Array(8 + hLen + sLen);
  mPrime.set(mHash, 8);
  mPrime.set(salt, 8 + hLen);
  const h = await digestFn(hash, mPrime);

  const psLen = emLen - sLen - hLen - 2;
  const db = new Uint8Array(psLen + 1 + sLen);
  db[psLen] = 0x01;
  db.set(salt, psLen + 1);

  const dbMask = await mgf1(digestFn, hash, h, emLen - hLen - 1);
  const maskedDb = xor(db, dbMask);

  // Set the leftmost 8*emLen - emBits bits of maskedDb to zero.
  const leftBits = 8 * emLen - emBits;
  if (leftBits > 0) {
    maskedDb[0] = (maskedDb[0]! & (0xff >> leftBits));
  }

  const em = new Uint8Array(emLen);
  em.set(maskedDb, 0);
  em.set(h, maskedDb.length);
  em[em.length - 1] = 0xbc;
  return em;
}

/**
 * EMSA-PSS-VERIFY per RFC 8017 § 9.1.2. Returns true iff the encoded
 * message is valid for the supplied hash.
 */
export async function pssVerify(
  digestFn: DigestFn,
  hash: Sha,
  em: Uint8Array,
  mHash: Uint8Array,
  saltLength: number,
  modulusBits: number,
): Promise<boolean> {
  const hLen = hashLength(hash);
  if (mHash.length !== hLen) return false;
  const sLen = saltLength;
  const emBits = modulusBits - 1;
  const emLen = Math.ceil(emBits / 8);

  // privateEncrypt(RSA_NO_PADDING) in Node may emit a leading 0x00
  // byte when emBits is a multiple of 8 minus 1; strip it if present.
  if (em.length === emLen + 1 && em[0] === 0x00) em = em.subarray(1);
  if (em.length !== emLen) return false;
  if (em[em.length - 1] !== 0xbc) return false;
  if (emLen < hLen + sLen + 2) return false;

  const maskedDb = em.subarray(0, emLen - hLen - 1);
  const h = em.subarray(emLen - hLen - 1, emLen - 1);

  const leftBits = 8 * emLen - emBits;
  if (leftBits > 0) {
    if ((maskedDb[0]! & ~(0xff >> leftBits)) !== 0) return false;
  }

  const dbMask = await mgf1(digestFn, hash, h, emLen - hLen - 1);
  const db = xor(maskedDb, dbMask);
  if (leftBits > 0) {
    db[0] = (db[0]! & (0xff >> leftBits));
  }

  const psLen = emLen - sLen - hLen - 2;
  for (let i = 0; i < psLen; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop bounded by psLen.
    if (db[i] !== 0x00) return false;
  }
  if (db[psLen] !== 0x01) return false;

  const salt = db.subarray(psLen + 1);
  const mPrime = new Uint8Array(8 + hLen + sLen);
  mPrime.set(mHash, 8);
  mPrime.set(salt, 8 + hLen);
  const hPrime = await digestFn(hash, mPrime);
  return constantTimeEqual(h, hPrime);
}

/**
 * Wrap a digest with PKCS#1 v1.5 padding for an RSA modulus of the
 * given byte length. Output length equals the modulus byte length.
 */
export function pkcs1V15Pad(digestInfo: Uint8Array, modulusBytes: number): Uint8Array {
  // EM = 0x00 || 0x01 || PS || 0x00 || T   (RFC 8017 § 9.2)
  // PS = at least 8 bytes of 0xff
  const psLen = modulusBytes - digestInfo.length - 3;
  if (psLen < 8) {
    throw new Error('RSA modulus too small for PKCS#1 v1.5 signature padding');
  }
  const em = new Uint8Array(modulusBytes);
  em[0] = 0x00;
  em[1] = 0x01;
  em.fill(0xff, 2, 2 + psLen);
  em[2 + psLen] = 0x00;
  em.set(digestInfo, 3 + psLen);
  return em;
}

/**
 * Inverse of `pkcs1V15Pad`: extract the DigestInfo from a padded
 * RSA-decrypted block. Returns null on malformed input.
 */
export function pkcs1V15Unpad(em: Uint8Array, modulusBytes: number): Uint8Array | null {
  // privateEncrypt(RSA_NO_PADDING) and pure-JS modPow can both emit
  // a leading 0x00 stripped or a leading 0x00 retained; tolerate both.
  if (em.length === modulusBytes - 1) {
    const padded = new Uint8Array(modulusBytes);
    padded.set(em, 1);
    em = padded;
  }
  if (em.length !== modulusBytes) return null;
  if (em[0] !== 0x00 || em[1] !== 0x01) return null;
  let i = 2;
  while (i < em.length && em[i] === 0xff) i += 1;
  if (i < 10) return null;          // PS must be at least 8 bytes
  if (em[i] !== 0x00) return null;
  return em.subarray(i + 1);
}
