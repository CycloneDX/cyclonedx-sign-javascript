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
 * Algorithm registry and primitive sign/verify tests.
 *
 * The tests sign and verify canonical byte arrays directly so that
 * any issue with algorithm dispatch or key-type gating surfaces here
 * instead of being obscured by the higher-level JSF orchestrator.
 * After the dual-runtime refactor, signBytes / verifyBytes are async
 * and take backend-neutral key handles, so the tests await every
 * primitive call and route HMAC keys through `backend.importHmacKey`.
 */

import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';

import {
  getAlgorithmSpec,
  isRegisteredAlgorithm,
  signBytes,
  verifyBytes,
} from '../src/jsf/algorithms.js';
import { toPrivateKey, toPublicKey } from '../src/jwk.js';
import { backend } from '../src/internal/crypto/node.js';
import { JsfInputError } from '../src/errors.js';
import { ecPair, edPair, rsaPair } from './helpers.js';

const DATA = new TextEncoder().encode('canonical payload');

const importHmac = (bytes: Uint8Array) =>
  backend.importHmacKey(bytes, 'sha-256');

describe('algorithm registry', () => {
  it('knows every specified JSF algorithm', () => {
    const names = [
      'RS256', 'RS384', 'RS512',
      'PS256', 'PS384', 'PS512',
      'ES256', 'ES384', 'ES512',
      'Ed25519', 'Ed448',
      'HS256', 'HS384', 'HS512',
    ];
    for (const n of names) {
      expect(isRegisteredAlgorithm(n)).toBe(true);
      const spec = getAlgorithmSpec(n);
      expect(spec).toBeDefined();
    }
  });

  it('rejects unknown algorithms', () => {
    expect(isRegisteredAlgorithm('none')).toBe(false);
    expect(() => getAlgorithmSpec('none')).toThrow(JsfInputError);
  });

  it('matches ECDSA coordinate sizes to curves', () => {
    expect(getAlgorithmSpec('ES256')).toMatchObject({ expectedCurve: 'P-256', coordinateBytes: 32 });
    expect(getAlgorithmSpec('ES384')).toMatchObject({ expectedCurve: 'P-384', coordinateBytes: 48 });
    expect(getAlgorithmSpec('ES512')).toMatchObject({ expectedCurve: 'P-521', coordinateBytes: 66 });
  });

  it('uses hash-length salts for RSA-PSS', () => {
    expect(getAlgorithmSpec('PS256')).toMatchObject({ saltLength: 32 });
    expect(getAlgorithmSpec('PS384')).toMatchObject({ saltLength: 48 });
    expect(getAlgorithmSpec('PS512')).toMatchObject({ saltLength: 64 });
  });
});

describe('signBytes + verifyBytes round-trips', () => {
  it('RS256 signs and verifies', async () => {
    const { privateKey, publicKey } = rsaPair();
    const spec = getAlgorithmSpec('RS256');
    const priv = await toPrivateKey(privateKey);
    const pub = await toPublicKey(publicKey);
    const sig = await signBytes(spec, DATA, priv);
    expect(await verifyBytes(spec, DATA, sig, pub)).toBe(true);
  });

  it('PS256 signs and verifies with distinct ciphertexts per call', async () => {
    const { privateKey, publicKey } = rsaPair();
    const spec = getAlgorithmSpec('PS256');
    const priv = await toPrivateKey(privateKey);
    const pub = await toPublicKey(publicKey);
    const sig1 = await signBytes(spec, DATA, priv);
    const sig2 = await signBytes(spec, DATA, priv);
    expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(false);
    expect(await verifyBytes(spec, DATA, sig1, pub)).toBe(true);
    expect(await verifyBytes(spec, DATA, sig2, pub)).toBe(true);
  });

  it('ES256 signs and verifies with a fixed-length raw R||S signature', async () => {
    const { privateKey, publicKey } = ecPair('prime256v1');
    const spec = getAlgorithmSpec('ES256');
    const priv = await toPrivateKey(privateKey);
    const pub = await toPublicKey(publicKey);
    const sig = await signBytes(spec, DATA, priv);
    expect(sig.length).toBe(64);
    expect(await verifyBytes(spec, DATA, sig, pub)).toBe(true);
  });

  it('ES384 produces a 96-byte raw signature', async () => {
    const { privateKey, publicKey } = ecPair('secp384r1');
    const spec = getAlgorithmSpec('ES384');
    const priv = await toPrivateKey(privateKey);
    const pub = await toPublicKey(publicKey);
    const sig = await signBytes(spec, DATA, priv);
    expect(sig.length).toBe(96);
    expect(await verifyBytes(spec, DATA, sig, pub)).toBe(true);
  });

  it('ES512 produces a 132-byte raw signature', async () => {
    const { privateKey, publicKey } = ecPair('secp521r1');
    const spec = getAlgorithmSpec('ES512');
    const priv = await toPrivateKey(privateKey);
    const pub = await toPublicKey(publicKey);
    const sig = await signBytes(spec, DATA, priv);
    expect(sig.length).toBe(132);
    expect(await verifyBytes(spec, DATA, sig, pub)).toBe(true);
  });

  it('Ed25519 signs and verifies', async () => {
    const { privateKey, publicKey } = edPair('ed25519');
    const spec = getAlgorithmSpec('Ed25519');
    const priv = await toPrivateKey(privateKey);
    const pub = await toPublicKey(publicKey);
    const sig = await signBytes(spec, DATA, priv);
    expect(await verifyBytes(spec, DATA, sig, pub)).toBe(true);
  });

  it('Ed448 signs and verifies', async () => {
    const { privateKey, publicKey } = edPair('ed448');
    const spec = getAlgorithmSpec('Ed448');
    const priv = await toPrivateKey(privateKey);
    const pub = await toPublicKey(publicKey);
    const sig = await signBytes(spec, DATA, priv);
    expect(await verifyBytes(spec, DATA, sig, pub)).toBe(true);
  });

  it('HS256 signs and verifies symmetrically', async () => {
    const key = await importHmac(new Uint8Array(randomBytes(32)));
    const spec = getAlgorithmSpec('HS256');
    const sig = await signBytes(spec, DATA, key);
    expect(await verifyBytes(spec, DATA, sig, key)).toBe(true);
  });

  it('HS256 rejects a bad MAC with a length mismatch', async () => {
    const key = await importHmac(new Uint8Array(randomBytes(32)));
    const spec = getAlgorithmSpec('HS256');
    const sig = await signBytes(spec, DATA, key);
    const truncated = sig.subarray(0, sig.length - 1);
    expect(await verifyBytes(spec, DATA, truncated, key)).toBe(false);
  });
});

describe('signBytes + verifyBytes tamper detection', () => {
  it('RS256 verify fails when data changes', async () => {
    const { privateKey, publicKey } = rsaPair();
    const spec = getAlgorithmSpec('RS256');
    const priv = await toPrivateKey(privateKey);
    const pub = await toPublicKey(publicKey);
    const sig = await signBytes(spec, DATA, priv);
    const mutated = new TextEncoder().encode('canonical payloaD');
    expect(await verifyBytes(spec, mutated, sig, pub)).toBe(false);
  });

  it('ES256 verify fails on malformed signature length', async () => {
    const { privateKey, publicKey } = ecPair('prime256v1');
    const spec = getAlgorithmSpec('ES256');
    const priv = await toPrivateKey(privateKey);
    const pub = await toPublicKey(publicKey);
    const sig = await signBytes(spec, DATA, priv);
    const wrong = new Uint8Array(sig.length + 1);
    wrong.set(sig);
    expect(await verifyBytes(spec, DATA, wrong, pub)).toBe(false);
  });

  it('HS256 verify fails on tampered MAC', async () => {
    const key = await importHmac(new Uint8Array(randomBytes(32)));
    const spec = getAlgorithmSpec('HS256');
    const sig = await signBytes(spec, DATA, key);
    const tampered = new Uint8Array(sig);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    expect(await verifyBytes(spec, DATA, tampered, key)).toBe(false);
  });
});

describe('key-type gating', () => {
  it('rejects an RSA signing request with an EC key', async () => {
    const { privateKey } = ecPair('prime256v1');
    const spec = getAlgorithmSpec('RS256');
    const priv = await toPrivateKey(privateKey);
    await expect(signBytes(spec, DATA, priv)).rejects.toThrow(/RSA key/);
  });

  it('rejects ES256 with a P-384 key', async () => {
    const { privateKey } = ecPair('secp384r1');
    const spec = getAlgorithmSpec('ES256');
    const priv = await toPrivateKey(privateKey);
    await expect(signBytes(spec, DATA, priv)).rejects.toThrow(/P-256/);
  });

  it('rejects Ed25519 with an Ed448 key', async () => {
    const { privateKey } = edPair('ed448');
    const spec = getAlgorithmSpec('Ed25519');
    const priv = await toPrivateKey(privateKey);
    await expect(signBytes(spec, DATA, priv)).rejects.toThrow(/ed25519/i);
  });

  it('rejects HMAC signing with an asymmetric key', async () => {
    const { privateKey } = rsaPair();
    const spec = getAlgorithmSpec('HS256');
    // The HMAC import path explicitly rejects asymmetric KeyObjects.
    await expect(backend.importHmacKey(privateKey, 'sha-256')).rejects.toThrow(/symmetric/);
  });
});
