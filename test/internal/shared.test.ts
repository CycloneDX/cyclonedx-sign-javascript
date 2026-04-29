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
 * Tests for src/internal/crypto/shared.ts.
 *
 * These primitives are the byte-level audit surface that both the
 * Node and Web backends share. Bugs here break wire compatibility
 * across both runtimes simultaneously, so exercise them in
 * isolation: round-trip every encoder/decoder, fuzz a tamper
 * detection, and pin the DigestInfo prefixes against the RFC values.
 */

import { describe, it, expect } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';

import {
  buildDigestInfo,
  constantTimeEqual,
  hashLength,
  pkcs1V15Pad,
  pkcs1V15Unpad,
  pssEncode,
  pssVerify,
  type DigestFn,
} from '../../src/internal/crypto/shared.js';
import type { Sha } from '../../src/internal/crypto/types.js';

const NODE_HASH: Record<Sha, string> = {
  'sha-256': 'sha256',
  'sha-384': 'sha384',
  'sha-512': 'sha512',
};

const nodeDigest: DigestFn = async (hash, data) =>
  new Uint8Array(createHash(NODE_HASH[hash]).update(data).digest());

const nodeRandom = (n: number) => new Uint8Array(randomBytes(n));

describe('shared.hashLength', () => {
  it('returns the canonical byte counts', () => {
    expect(hashLength('sha-256')).toBe(32);
    expect(hashLength('sha-384')).toBe(48);
    expect(hashLength('sha-512')).toBe(64);
  });
});

describe('shared.buildDigestInfo', () => {
  // RFC 3447 Appendix B.1 DigestInfo prefixes. Pinning these here so
  // a refactor that drifts a byte trips a test, not a verifying peer.
  const SHA256_PREFIX = '3031300d060960864801650304020105000420';
  const SHA384_PREFIX = '3041300d060960864801650304020205000430';
  const SHA512_PREFIX = '3051300d060960864801650304020305000440';

  it('prepends the SHA-256 prefix and appends the digest', () => {
    const digest = new Uint8Array(32).fill(0xab);
    const di = buildDigestInfo('sha-256', digest);
    const hex = Buffer.from(di).toString('hex');
    expect(hex.startsWith(SHA256_PREFIX)).toBe(true);
    expect(hex.endsWith('ab'.repeat(32))).toBe(true);
    expect(di.length).toBe(SHA256_PREFIX.length / 2 + 32);
  });

  it('uses the SHA-384 prefix for sha-384', () => {
    const di = buildDigestInfo('sha-384', new Uint8Array(48));
    expect(Buffer.from(di).toString('hex').startsWith(SHA384_PREFIX)).toBe(true);
  });

  it('uses the SHA-512 prefix for sha-512', () => {
    const di = buildDigestInfo('sha-512', new Uint8Array(64));
    expect(Buffer.from(di).toString('hex').startsWith(SHA512_PREFIX)).toBe(true);
  });
});

describe('shared.constantTimeEqual', () => {
  it('returns true on equal arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 5]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it('returns false on a single-byte difference at the end', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 6]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it('returns false on a single-byte difference at the start', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([0, 2, 3]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it('returns false on length mismatch', () => {
    expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([]), new Uint8Array([0]))).toBe(false);
  });

  it('handles zero-length arrays', () => {
    expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

describe('shared.pkcs1V15Pad / pkcs1V15Unpad', () => {
  it('round-trips a typical DigestInfo block', () => {
    const di = buildDigestInfo('sha-256', new Uint8Array(32).fill(0x55));
    const padded = pkcs1V15Pad(di, 256);          // 2048-bit modulus
    expect(padded.length).toBe(256);
    expect(padded[0]).toBe(0x00);
    expect(padded[1]).toBe(0x01);
    const unpadded = pkcs1V15Unpad(padded, 256);
    expect(unpadded).not.toBeNull();
    expect(constantTimeEqual(unpadded!, di)).toBe(true);
  });

  it('produces 0xff PS bytes between header and DigestInfo', () => {
    const di = buildDigestInfo('sha-256', new Uint8Array(32));
    const padded = pkcs1V15Pad(di, 256);
    // Walk PS region.
    let i = 2;
    while (i < padded.length && padded[i] === 0xff) i += 1;
    // Must end with 0x00 separator.
    expect(padded[i]).toBe(0x00);
    // PS must be at least 8 bytes.
    expect(i - 2).toBeGreaterThanOrEqual(8);
  });

  it('rejects a modulus too small for the digest plus padding overhead', () => {
    const di = buildDigestInfo('sha-512', new Uint8Array(64));
    // 64 + DigestInfo prefix (~19) + 11 overhead = ~94 bytes. A 64-byte
    // modulus is far too small.
    expect(() => pkcs1V15Pad(di, 64)).toThrow(/too small/);
  });

  it('returns null for malformed leading bytes', () => {
    const bad = new Uint8Array(256);
    bad[0] = 0x42;          // wrong leader
    bad[1] = 0x01;
    expect(pkcs1V15Unpad(bad, 256)).toBeNull();
  });

  it('returns null when the PS region is shorter than 8 bytes', () => {
    const bad = new Uint8Array(256);
    bad[0] = 0x00;
    bad[1] = 0x01;
    // Only 4 bytes of 0xff before the separator.
    bad[2] = 0xff; bad[3] = 0xff; bad[4] = 0xff; bad[5] = 0xff;
    bad[6] = 0x00;
    expect(pkcs1V15Unpad(bad, 256)).toBeNull();
  });

  it('tolerates a leading-zero-stripped block (length n-1)', () => {
    const di = buildDigestInfo('sha-256', new Uint8Array(32).fill(0x77));
    const padded = pkcs1V15Pad(di, 256);
    expect(padded[0]).toBe(0x00);
    const stripped = padded.subarray(1);
    expect(stripped.length).toBe(255);
    const recovered = pkcs1V15Unpad(stripped, 256);
    expect(recovered).not.toBeNull();
    expect(constantTimeEqual(recovered!, di)).toBe(true);
  });
});

describe('shared.pssEncode / pssVerify', () => {
  it('round-trips for SHA-256 with a 2048-bit modulus', async () => {
    const mHash = await nodeDigest('sha-256', new TextEncoder().encode('hello'));
    const em = await pssEncode(nodeDigest, nodeRandom, 'sha-256', mHash, 32, 2048);
    expect(em.length).toBe(Math.ceil((2048 - 1) / 8));
    expect(em[em.length - 1]).toBe(0xbc);
    const ok = await pssVerify(nodeDigest, 'sha-256', em, mHash, 32, 2048);
    expect(ok).toBe(true);
  });

  it('round-trips for SHA-384 with a 3072-bit modulus', async () => {
    const mHash = await nodeDigest('sha-384', new TextEncoder().encode('hello'));
    const em = await pssEncode(nodeDigest, nodeRandom, 'sha-384', mHash, 48, 3072);
    const ok = await pssVerify(nodeDigest, 'sha-384', em, mHash, 48, 3072);
    expect(ok).toBe(true);
  });

  it('round-trips for SHA-512 with a 4096-bit modulus', async () => {
    const mHash = await nodeDigest('sha-512', new TextEncoder().encode('hello'));
    const em = await pssEncode(nodeDigest, nodeRandom, 'sha-512', mHash, 64, 4096);
    const ok = await pssVerify(nodeDigest, 'sha-512', em, mHash, 64, 4096);
    expect(ok).toBe(true);
  });

  it('produces randomized output for the same input across calls', async () => {
    const mHash = await nodeDigest('sha-256', new Uint8Array(0));
    const em1 = await pssEncode(nodeDigest, nodeRandom, 'sha-256', mHash, 32, 2048);
    const em2 = await pssEncode(nodeDigest, nodeRandom, 'sha-256', mHash, 32, 2048);
    expect(constantTimeEqual(em1, em2)).toBe(false);
  });

  it('rejects an EM whose trailing byte is not 0xbc', async () => {
    const mHash = await nodeDigest('sha-256', new Uint8Array(0));
    const em = await pssEncode(nodeDigest, nodeRandom, 'sha-256', mHash, 32, 2048);
    em[em.length - 1] = 0xab;
    const ok = await pssVerify(nodeDigest, 'sha-256', em, mHash, 32, 2048);
    expect(ok).toBe(false);
  });

  it('rejects an EM that fails the masked-DB high-bit zero check', async () => {
    const mHash = await nodeDigest('sha-256', new Uint8Array(0));
    const em = await pssEncode(nodeDigest, nodeRandom, 'sha-256', mHash, 32, 2048);
    // Set the leftmost masked-DB bit, which the spec mandates is zero
    // for a 2047-bit emBits encoding.
    em[0] |= 0x80;
    const ok = await pssVerify(nodeDigest, 'sha-256', em, mHash, 32, 2048);
    expect(ok).toBe(false);
  });

  it('rejects an EM with the digest tampered', async () => {
    const original = await nodeDigest('sha-256', new TextEncoder().encode('original'));
    const tampered = await nodeDigest('sha-256', new TextEncoder().encode('TAMPERED'));
    const em = await pssEncode(nodeDigest, nodeRandom, 'sha-256', original, 32, 2048);
    expect(await pssVerify(nodeDigest, 'sha-256', em, tampered, 32, 2048)).toBe(false);
    expect(await pssVerify(nodeDigest, 'sha-256', em, original, 32, 2048)).toBe(true);
  });

  it('rejects an EM whose hash length does not match the algorithm', async () => {
    const mHash = await nodeDigest('sha-256', new Uint8Array(0));
    const em = await pssEncode(nodeDigest, nodeRandom, 'sha-256', mHash, 32, 2048);
    const wrongLen = new Uint8Array(20);
    expect(await pssVerify(nodeDigest, 'sha-256', em, wrongLen, 32, 2048)).toBe(false);
  });

  it('throws when the modulus is too small for hash + salt + 2 overhead', async () => {
    const mHash = await nodeDigest('sha-512', new Uint8Array(0));
    // SHA-512 needs hash=64 + salt=64 + 2 = 130 bytes; 512 bits = 64 bytes.
    await expect(
      pssEncode(nodeDigest, nodeRandom, 'sha-512', mHash, 64, 512),
    ).rejects.toThrow(/too small/);
  });
});
