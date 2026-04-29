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
 * Cross-backend wire interop.
 *
 * The library's central promise is that a signature produced on one
 * runtime verifies cleanly on the other. Wire-byte drift would break
 * every CycloneDX consumer that signs in Node and verifies in a
 * browser (or vice versa). These tests sign on backend A, verify on
 * backend B, for every algorithm the library supports.
 *
 * Both backends are imported by direct file path so they can run
 * side by side in a single Node test process.
 */

import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';

import { backend as nodeBackend } from '../src/internal/crypto/node.js';
import { backend as webBackend } from '../src/internal/crypto/web.js';
import type { CryptoBackend } from '../src/internal/crypto/types.js';
import { ecPair, edPair, rsaPair } from './helpers.js';

const DATA = new TextEncoder().encode('cross-runtime canonical payload');

const direction = (sign: CryptoBackend, verify: CryptoBackend) =>
  `${sign.id} → ${verify.id}`;

const PAIRS: Array<[CryptoBackend, CryptoBackend]> = [
  [nodeBackend, webBackend],
  [webBackend, nodeBackend],
];

describe('JSF message-mode RSA-PKCS1 interop', () => {
  for (const [signer, verifier] of PAIRS) {
    it(`RS256 ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = rsaPair(2048);
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const sig = await signer.signRsaPkcs1('sha-256', DATA, priv);
      expect(await verifier.verifyRsaPkcs1('sha-256', DATA, sig, pub)).toBe(true);
    });

    it(`RS512 ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = rsaPair(2048);
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const sig = await signer.signRsaPkcs1('sha-512', DATA, priv);
      expect(await verifier.verifyRsaPkcs1('sha-512', DATA, sig, pub)).toBe(true);
    });
  }
});

describe('JSF message-mode RSA-PSS interop', () => {
  for (const [signer, verifier] of PAIRS) {
    it(`PS256 ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = rsaPair(2048);
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const sig = await signer.signRsaPss('sha-256', DATA, 32, priv);
      expect(await verifier.verifyRsaPss('sha-256', DATA, 32, sig, pub)).toBe(true);
    });

    it(`PS384 ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = rsaPair(3072);
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const sig = await signer.signRsaPss('sha-384', DATA, 48, priv);
      expect(await verifier.verifyRsaPss('sha-384', DATA, 48, sig, pub)).toBe(true);
    });

    it(`PS512 ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = rsaPair(3072);
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const sig = await signer.signRsaPss('sha-512', DATA, 64, priv);
      expect(await verifier.verifyRsaPss('sha-512', DATA, 64, sig, pub)).toBe(true);
    });
  }
});

describe('JSF message-mode ECDSA interop', () => {
  for (const [signer, verifier] of PAIRS) {
    it(`ES256 ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = ecPair('prime256v1');
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const sig = await signer.signEcdsa('sha-256', DATA, priv);
      expect(sig.length).toBe(64);
      expect(await verifier.verifyEcdsa('sha-256', DATA, sig, pub)).toBe(true);
    });

    it(`ES384 ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = ecPair('secp384r1');
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const sig = await signer.signEcdsa('sha-384', DATA, priv);
      expect(sig.length).toBe(96);
      expect(await verifier.verifyEcdsa('sha-384', DATA, sig, pub)).toBe(true);
    });

    it(`ES512 ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = ecPair('secp521r1');
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const sig = await signer.signEcdsa('sha-512', DATA, priv);
      expect(sig.length).toBe(132);
      expect(await verifier.verifyEcdsa('sha-512', DATA, sig, pub)).toBe(true);
    });
  }
});

describe('JSF message-mode EdDSA interop', () => {
  for (const [signer, verifier] of PAIRS) {
    it(`Ed25519 ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = edPair('ed25519');
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const sig = await signer.signEddsa(DATA, priv);
      expect(await verifier.verifyEddsa(DATA, sig, pub)).toBe(true);
    });

    it(`Ed448 ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = edPair('ed448');
      // Ed448 lacks a JWK round-trip story across both backends; use
      // PKCS#8/SPKI PEM so each backend imports through its own path
      // (Web uses noble fallback, Node uses node:crypto).
      const privPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
      const pubPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
      const priv = await signer.importPrivateKey(privPem);
      const pub = await verifier.importPublicKey(pubPem);
      const sig = await signer.signEddsa(DATA, priv);
      expect(await verifier.verifyEddsa(DATA, sig, pub)).toBe(true);
    });
  }
});

describe('JSF message-mode HMAC interop', () => {
  for (const [signer, verifier] of PAIRS) {
    it(`HS256 ${direction(signer, verifier)}`, async () => {
      const keyBytes = new Uint8Array(randomBytes(32));
      const signKey = await signer.importHmacKey(keyBytes, 'sha-256');
      const verifyKey = await verifier.importHmacKey(keyBytes, 'sha-256');
      const mac = await signer.hmacSign('sha-256', signKey, DATA);
      expect(await verifier.hmacVerify('sha-256', verifyKey, DATA, mac)).toBe(true);
    });

    it(`HS512 ${direction(signer, verifier)}`, async () => {
      const keyBytes = new Uint8Array(randomBytes(64));
      const signKey = await signer.importHmacKey(keyBytes, 'sha-512');
      const verifyKey = await verifier.importHmacKey(keyBytes, 'sha-512');
      const mac = await signer.hmacSign('sha-512', signKey, DATA);
      expect(await verifier.hmacVerify('sha-512', verifyKey, DATA, mac)).toBe(true);
    });
  }
});

describe('JSS pre-hashed RSA-PKCS1 interop', () => {
  for (const [signer, verifier] of PAIRS) {
    it(`RS256-prehashed ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = rsaPair(2048);
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const digest = await signer.digest('sha-256', DATA);
      const sig = await signer.signRsaPkcs1Prehashed('sha-256', digest, priv);
      expect(sig.length).toBe(256);
      expect(await verifier.verifyRsaPkcs1Prehashed('sha-256', digest, sig, pub)).toBe(true);
    });

    it(`RS384-prehashed ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = rsaPair(3072);
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const digest = await signer.digest('sha-384', DATA);
      const sig = await signer.signRsaPkcs1Prehashed('sha-384', digest, priv);
      expect(await verifier.verifyRsaPkcs1Prehashed('sha-384', digest, sig, pub)).toBe(true);
    });
  }
});

describe('JSS pre-hashed RSA-PSS interop', () => {
  for (const [signer, verifier] of PAIRS) {
    it(`PS256-prehashed ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = rsaPair(2048);
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const digest = await signer.digest('sha-256', DATA);
      const sig = await signer.signRsaPssPrehashed('sha-256', digest, 32, priv);
      expect(await verifier.verifyRsaPssPrehashed('sha-256', digest, 32, sig, pub)).toBe(true);
    });

    it(`PS512-prehashed ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = rsaPair(3072);
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const digest = await signer.digest('sha-512', DATA);
      const sig = await signer.signRsaPssPrehashed('sha-512', digest, 64, priv);
      expect(await verifier.verifyRsaPssPrehashed('sha-512', digest, 64, sig, pub)).toBe(true);
    });
  }
});

describe('JSS pre-hashed ECDSA interop', () => {
  for (const [signer, verifier] of PAIRS) {
    it(`ES256-prehashed ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = ecPair('prime256v1');
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const digest = await signer.digest('sha-256', DATA);
      const sig = await signer.signEcdsaPrehashed('P-256', digest, priv);
      expect(sig.length).toBe(64);
      expect(await verifier.verifyEcdsaPrehashed('P-256', digest, sig, pub)).toBe(true);
    });

    it(`ES512-prehashed ${direction(signer, verifier)}`, async () => {
      const { privateKey, publicKey } = ecPair('secp521r1');
      const priv = await signer.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
      const pub = await verifier.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
      const digest = await signer.digest('sha-512', DATA);
      const sig = await signer.signEcdsaPrehashed('P-521', digest, priv);
      expect(sig.length).toBe(132);
      expect(await verifier.verifyEcdsaPrehashed('P-521', digest, sig, pub)).toBe(true);
    });
  }
});

describe('cross-backend digest equality', () => {
  it('SHA-256 matches across backends', async () => {
    const a = await nodeBackend.digest('sha-256', DATA);
    const b = await webBackend.digest('sha-256', DATA);
    expect(a).toEqual(b);
  });

  it('SHA-384 matches across backends', async () => {
    const a = await nodeBackend.digest('sha-384', DATA);
    const b = await webBackend.digest('sha-384', DATA);
    expect(a).toEqual(b);
  });

  it('SHA-512 matches across backends', async () => {
    const a = await nodeBackend.digest('sha-512', DATA);
    const b = await webBackend.digest('sha-512', DATA);
    expect(a).toEqual(b);
  });
});
