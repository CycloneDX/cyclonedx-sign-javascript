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
 * Tests for the security-hardening defenses added in the secure-code-review
 * pass:
 *
 *   - DER length bounds checks in the Web backend's parser. A crafted
 *     PEM/DER blob with an oversized long-form length, a forbidden
 *     indefinite length, or a truncated trailer must be rejected
 *     promptly rather than driving the walker into an attacker-paced
 *     loop. Defends against CWE-400 / CWE-1284.
 *   - RSA modulus size cap on both backends. An envelope whose
 *     embedded public key declares a multi-megabit modulus must be
 *     rejected at import; otherwise the verifier burns CPU and
 *     memory on EMSA-PSS / MGF1 / modPow before the signature check
 *     even runs. Defends against CWE-400.
 */

import { describe, it, expect } from 'vitest';
import { backend as nodeBackend } from '../../src/internal/crypto/node.js';
import { backend as webBackend } from '../../src/internal/crypto/web.js';

// ---------------------------------------------------------------------------
// DER length bounds (Web backend X.509 / PEM walker)
// ---------------------------------------------------------------------------

describe('Web backend: DER length bounds', () => {
  /** Build a fake PEM blob from a raw DER buffer. */
  function asPemPublic(der: Uint8Array): string {
    let bin = '';
    for (const byte of der) bin += String.fromCharCode(byte);
    const b64 = Buffer.from(bin, 'binary').toString('base64');
    return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
  }

  it('rejects a SEQUENCE with indefinite-length form (0x80)', async () => {
    // SEQUENCE (0x30), length 0x80 = indefinite (forbidden in DER).
    const der = new Uint8Array([0x30, 0x80, 0x00, 0x00]);
    await expect(webBackend.parseCertSpkiPublicKey(der))
      .rejects.toThrow(/unsupported long-form length/);
  });

  it('rejects a long-form length over 4 octets (DoS guard)', async () => {
    // SEQUENCE, length form 0x88 = 8 octets follow. Even with valid
    // bytes after, this is rejected because parsing such a length
    // would express values up to 2^64.
    const der = new Uint8Array([
      0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);
    await expect(webBackend.parseCertSpkiPublicKey(der))
      .rejects.toThrow(/unsupported long-form length/);
  });

  it('rejects a declared length that exceeds the actual buffer', async () => {
    // SEQUENCE with length 1000, but the buffer is only 5 bytes total.
    const der = new Uint8Array([0x30, 0x82, 0x03, 0xe8, 0x00]);
    await expect(webBackend.parseCertSpkiPublicKey(der))
      .rejects.toThrow(/exceeds buffer/);
  });

  it('rejects a truncated long-form length (length byte missing)', async () => {
    // SEQUENCE with length form 0x82 = 2 octets follow, but only 1 octet present.
    const der = new Uint8Array([0x30, 0x82, 0x10]);
    await expect(webBackend.parseCertSpkiPublicKey(der))
      .rejects.toThrow(/truncated long-form length/);
  });

  it('rejects a SEQUENCE whose short-form length runs past the buffer', async () => {
    // Outer SEQUENCE length 100, but only 10 bytes total in the buffer.
    const der = new Uint8Array([0x30, 0x64, ...new Array(8).fill(0)]);
    await expect(webBackend.parseCertSpkiPublicKey(der))
      .rejects.toThrow(/exceeds buffer/);
  });
});

// ---------------------------------------------------------------------------
// RSA modulus size cap (both backends)
// ---------------------------------------------------------------------------

describe('RSA modulus size cap', () => {
  /**
   * Construct a JWK whose `n` decodes to a BigInt of approximately
   * `bits` bits. Only the public components matter for the import
   * path; the value does not need to be a valid RSA modulus.
   */
  function rsaJwkOfSize(bits: number): { kty: 'RSA'; n: string; e: string } {
    // BigInt with the top bit set, then enough bytes to reach `bits`.
    const bytes = Math.ceil(bits / 8);
    const buf = new Uint8Array(bytes);
    buf[0] = 0x80 | (1 << ((bits - 1) % 8) >>> 0);
    for (let i = 1; i < bytes; i += 1) buf[i] = 0xab;
    let bin = '';
    for (const b of buf) bin += String.fromCharCode(b);
    const n = Buffer.from(bin, 'binary').toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return { kty: 'RSA', n, e: 'AQAB' };
  }

  it('Web: rejects an RSA JWK with a 32 768-bit modulus (over the cap)', async () => {
    const jwk = rsaJwkOfSize(32_768);
    await expect(webBackend.importPublicKey(jwk as never))
      .rejects.toThrow(/outside the accepted range/);
  });

  it('Web: rejects an RSA JWK with a 1 024-bit modulus (under the floor)', async () => {
    const jwk = rsaJwkOfSize(1024);
    await expect(webBackend.importPublicKey(jwk as never))
      .rejects.toThrow(/outside the accepted range/);
  });

  it('Web: accepts the canonical 2 048-bit modulus', async () => {
    const jwk = rsaJwkOfSize(2048);
    const handle = await webBackend.importPublicKey(jwk as never);
    expect(handle.rsaModulusBits).toBe(2048);
  });

  it('Web: accepts a 16 384-bit modulus (boundary)', async () => {
    const jwk = rsaJwkOfSize(16_384);
    const handle = await webBackend.importPublicKey(jwk as never);
    expect(handle.rsaModulusBits).toBe(16_384);
  });

  it('Node: rejects a 1 024-bit RSA KeyObject as under the floor', async () => {
    // Node's createPrivateKey accepts shorter moduli; the backend
    // describeKey is what guards the policy. Generate a real 1024-bit
    // key and confirm the import fails. This test is slow because of
    // RSA-1024 keygen; skip if the runtime cannot afford it.
    const { generateKeyPairSync } = await import('node:crypto');
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
    await expect(nodeBackend.importPublicKey(publicKey))
      .rejects.toThrow(/outside the accepted range/);
  });
});
