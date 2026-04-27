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
 * This layer owns every call into node:crypto. The tests sign and
 * verify canonical byte arrays directly so that any issue with
 * algorithm dispatch or key-type gating surfaces here instead of
 * being obscured by the higher-level JSF orchestrator.
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPairSync,
  randomBytes,
  createSecretKey,
  type KeyObject,
} from 'node:crypto';

import {
  getAlgorithmSpec,
  isRegisteredAlgorithm,
  signBytes,
  verifyBytes,
} from '../src/jsf/algorithms.js';
import { toPrivateKey, toPublicKey } from '../src/jwk.js';
import { JsfInputError } from '../src/errors.js';
import { ecPair, edPair, rsaPair, type KeyPair } from './helpers.js';

const DATA = new TextEncoder().encode('canonical payload');

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
  it('RS256 signs and verifies', () => {
    const { privateKey, publicKey } = rsaPair();
    const spec = getAlgorithmSpec('RS256');
    const priv = toPrivateKey(privateKey);
    const pub = toPublicKey(publicKey);
    const sig = signBytes(spec, DATA, priv.keyObject, priv.curve);
    expect(verifyBytes(spec, DATA, sig, pub.keyObject, pub.curve)).toBe(true);
  });

  it('PS256 signs and verifies with distinct ciphertexts per call', () => {
    const { privateKey, publicKey } = rsaPair();
    const spec = getAlgorithmSpec('PS256');
    const priv = toPrivateKey(privateKey);
    const pub = toPublicKey(publicKey);
    const sig1 = signBytes(spec, DATA, priv.keyObject, priv.curve);
    const sig2 = signBytes(spec, DATA, priv.keyObject, priv.curve);
    expect(sig1.equals(sig2)).toBe(false);
    expect(verifyBytes(spec, DATA, sig1, pub.keyObject, pub.curve)).toBe(true);
    expect(verifyBytes(spec, DATA, sig2, pub.keyObject, pub.curve)).toBe(true);
  });

  it('ES256 signs and verifies with a fixed-length raw R||S signature', () => {
    const { privateKey, publicKey } = ecPair('prime256v1');
    const spec = getAlgorithmSpec('ES256');
    const priv = toPrivateKey(privateKey);
    const pub = toPublicKey(publicKey);
    const sig = signBytes(spec, DATA, priv.keyObject, priv.curve);
    expect(sig.length).toBe(64);
    expect(verifyBytes(spec, DATA, sig, pub.keyObject, pub.curve)).toBe(true);
  });

  it('ES384 produces a 96-byte raw signature', () => {
    const { privateKey, publicKey } = ecPair('secp384r1');
    const spec = getAlgorithmSpec('ES384');
    const priv = toPrivateKey(privateKey);
    const pub = toPublicKey(publicKey);
    const sig = signBytes(spec, DATA, priv.keyObject, priv.curve);
    expect(sig.length).toBe(96);
    expect(verifyBytes(spec, DATA, sig, pub.keyObject, pub.curve)).toBe(true);
  });

  it('ES512 produces a 132-byte raw signature', () => {
    const { privateKey, publicKey } = ecPair('secp521r1');
    const spec = getAlgorithmSpec('ES512');
    const priv = toPrivateKey(privateKey);
    const pub = toPublicKey(publicKey);
    const sig = signBytes(spec, DATA, priv.keyObject, priv.curve);
    expect(sig.length).toBe(132);
    expect(verifyBytes(spec, DATA, sig, pub.keyObject, pub.curve)).toBe(true);
  });

  it('Ed25519 signs and verifies', () => {
    const { privateKey, publicKey } = edPair('ed25519');
    const spec = getAlgorithmSpec('Ed25519');
    const priv = toPrivateKey(privateKey);
    const pub = toPublicKey(publicKey);
    const sig = signBytes(spec, DATA, priv.keyObject, priv.curve);
    expect(verifyBytes(spec, DATA, sig, pub.keyObject, pub.curve)).toBe(true);
  });

  it('Ed448 signs and verifies', () => {
    const { privateKey, publicKey } = edPair('ed448');
    const spec = getAlgorithmSpec('Ed448');
    const priv = toPrivateKey(privateKey);
    const pub = toPublicKey(publicKey);
    const sig = signBytes(spec, DATA, priv.keyObject, priv.curve);
    expect(verifyBytes(spec, DATA, sig, pub.keyObject, pub.curve)).toBe(true);
  });

  it('HS256 signs and verifies symmetrically', () => {
    const key = createSecretKey(randomBytes(32));
    const spec = getAlgorithmSpec('HS256');
    const sig = signBytes(spec, DATA, key, null);
    expect(verifyBytes(spec, DATA, sig, key, null)).toBe(true);
  });

  it('HS256 rejects a bad MAC with a length mismatch', () => {
    const key = createSecretKey(randomBytes(32));
    const spec = getAlgorithmSpec('HS256');
    const sig = signBytes(spec, DATA, key, null);
    const truncated = sig.subarray(0, sig.length - 1);
    expect(verifyBytes(spec, DATA, truncated, key, null)).toBe(false);
  });
});

describe('signBytes + verifyBytes tamper detection', () => {
  it('RS256 verify fails when data changes', () => {
    const { privateKey, publicKey } = rsaPair();
    const spec = getAlgorithmSpec('RS256');
    const priv = toPrivateKey(privateKey);
    const pub = toPublicKey(publicKey);
    const sig = signBytes(spec, DATA, priv.keyObject, priv.curve);
    const mutated = new TextEncoder().encode('canonical payloaD');
    expect(verifyBytes(spec, mutated, sig, pub.keyObject, pub.curve)).toBe(false);
  });

  it('ES256 verify fails on malformed signature length', () => {
    const { privateKey, publicKey } = ecPair('prime256v1');
    const spec = getAlgorithmSpec('ES256');
    const priv = toPrivateKey(privateKey);
    const pub = toPublicKey(publicKey);
    const sig = signBytes(spec, DATA, priv.keyObject, priv.curve);
    const wrong = new Uint8Array(sig.length + 1);
    wrong.set(sig);
    expect(verifyBytes(spec, DATA, wrong, pub.keyObject, pub.curve)).toBe(false);
  });

  it('HS256 verify fails on tampered MAC', () => {
    const key = createSecretKey(randomBytes(32));
    const spec = getAlgorithmSpec('HS256');
    const sig = Buffer.from(signBytes(spec, DATA, key, null));
    sig[0] = (sig[0] ?? 0) ^ 0x01;
    expect(verifyBytes(spec, DATA, sig, key, null)).toBe(false);
  });
});

describe('key-type gating', () => {
  it('rejects an RSA signing request with an EC key', () => {
    const { privateKey } = ecPair('prime256v1');
    const spec = getAlgorithmSpec('RS256');
    const priv = toPrivateKey(privateKey);
    expect(() => signBytes(spec, DATA, priv.keyObject, priv.curve)).toThrow(/RSA key/);
  });

  it('rejects ES256 with a P-384 key', () => {
    const { privateKey } = ecPair('secp384r1');
    const spec = getAlgorithmSpec('ES256');
    const priv = toPrivateKey(privateKey);
    expect(() => signBytes(spec, DATA, priv.keyObject, priv.curve)).toThrow(/P-256/);
  });

  it('rejects Ed25519 with an Ed448 key', () => {
    const { privateKey } = edPair('ed448');
    const spec = getAlgorithmSpec('Ed25519');
    const priv = toPrivateKey(privateKey);
    expect(() => signBytes(spec, DATA, priv.keyObject, priv.curve)).toThrow(/ed25519/i);
  });

  it('rejects HMAC signing with an asymmetric key', () => {
    const { privateKey } = rsaPair();
    const spec = getAlgorithmSpec('HS256');
    const priv = toPrivateKey(privateKey);
    expect(() => signBytes(spec, DATA, priv.keyObject, priv.curve)).toThrow(/symmetric/);
  });
});
