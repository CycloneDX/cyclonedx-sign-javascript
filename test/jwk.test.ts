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
 * JWK normalization and sanitization tests.
 *
 * Covers the shapes the public API promises to accept, the canonical
 * shape it exports, and a handful of failure modes. After the
 * dual-runtime refactor the key normalization functions are async and
 * return backend-neutral handles whose surface is `kind` / `curve` /
 * `rsaModulusBits` plus `exportJwk()` / `exportSpkiPem()`.
 */

import { describe, it, expect } from 'vitest';
import { createSecretKey, randomBytes } from 'node:crypto';

import {
  exportPublicJwk,
  sanitizePublicJwk,
  toPrivateKey,
  toPublicKey,
} from '../src/jwk.js';
import { JsfKeyError } from '../src/errors.js';
import { ecPair, edPair, rsaPair } from './helpers.js';

describe('JWK', () => {
  describe('toPrivateKey', () => {
    it('accepts a Node KeyObject directly', async () => {
      const { privateKey } = rsaPair();
      const out = await toPrivateKey(privateKey);
      expect(out.kind).toBe('rsa');
      expect(out.curve).toBeNull();
    });

    it('rejects a public KeyObject as a private key', async () => {
      const { publicKey } = rsaPair();
      await expect(toPrivateKey(publicKey)).rejects.toThrow(JsfKeyError);
    });

    it('accepts a PEM-encoded private key string', async () => {
      const { privateKey } = ecPair('prime256v1');
      const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
      const out = await toPrivateKey(pem);
      expect(out.kind).toBe('ec');
      expect(out.curve).toBe('P-256');
    });

    it('accepts a JWK object for an EC private key', async () => {
      const { privateKey } = ecPair('secp384r1');
      const jwk = privateKey.export({ format: 'jwk' }) as Record<string, unknown>;
      const out = await toPrivateKey(jwk as never);
      expect(out.kind).toBe('ec');
      expect(out.curve).toBe('P-384');
    });

    it('accepts a JWK JSON string for an EC private key', async () => {
      const { privateKey } = ecPair('secp521r1');
      const jwk = privateKey.export({ format: 'jwk' });
      const out = await toPrivateKey(JSON.stringify(jwk));
      expect(out.curve).toBe('P-521');
    });

    it('accepts HMAC bytes as a Buffer', async () => {
      const secret = randomBytes(32);
      const out = await toPrivateKey(secret);
      expect(out.kind).toBe('oct');
    });

    it('accepts HMAC bytes as a Uint8Array', async () => {
      const bytes = new Uint8Array([1, 2, 3, 4]);
      const out = await toPrivateKey(bytes);
      expect(out.kind).toBe('oct');
    });

    it('accepts an oct JWK and decodes k from base64url', async () => {
      const out = await toPrivateKey({ kty: 'oct', k: 'AQID' } as never);
      expect(out.kind).toBe('oct');
    });

    it('rejects oct JWK without k', async () => {
      await expect(toPrivateKey({ kty: 'oct' } as never)).rejects.toThrow(/k/);
    });

    it('rejects unknown key input shapes', async () => {
      await expect(toPrivateKey(42 as never)).rejects.toThrow(JsfKeyError);
      await expect(toPrivateKey(null as never)).rejects.toThrow(JsfKeyError);
    });

    it('reports the curve for Ed25519', async () => {
      const { privateKey } = edPair('ed25519');
      const out = await toPrivateKey(privateKey);
      expect(out.kind).toBe('ed25519');
      expect(out.curve).toBe('Ed25519');
    });

    it('reports the curve for Ed448', async () => {
      const { privateKey } = edPair('ed448');
      const out = await toPrivateKey(privateKey);
      expect(out.curve).toBe('Ed448');
    });
  });

  describe('toPublicKey', () => {
    it('extracts the public half from a private KeyObject', async () => {
      const { privateKey } = rsaPair();
      const out = await toPublicKey(privateKey);
      expect(out.kind).toBe('rsa');
    });

    it('accepts a PEM SPKI public key', async () => {
      const { publicKey } = ecPair('prime256v1');
      const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
      const out = await toPublicKey(pem);
      expect(out.kind).toBe('ec');
      expect(out.curve).toBe('P-256');
    });

    it('accepts a JWK object for an RSA public key', async () => {
      const { publicKey } = rsaPair();
      const jwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
      const out = await toPublicKey(jwk as never);
      expect(out.kind).toBe('rsa');
    });

    it('accepts a Node secret KeyObject as HMAC material', async () => {
      const secret = createSecretKey(randomBytes(16));
      const out = await toPublicKey(secret);
      expect(out.kind).toBe('oct');
    });

    it('rejects non-key input', async () => {
      await expect(toPublicKey(undefined as never)).rejects.toThrow(JsfKeyError);
    });
  });

  describe('exportPublicJwk', () => {
    it('produces an RSA JWK with only n and e', async () => {
      const { privateKey } = rsaPair();
      const jwk = await exportPublicJwk(privateKey);
      expect(jwk.kty).toBe('RSA');
      expect(jwk.n).toBeDefined();
      expect(jwk.e).toBeDefined();
      expect(jwk).not.toHaveProperty('d');
      expect(jwk).not.toHaveProperty('p');
      expect(jwk).not.toHaveProperty('alg');
    });

    it('produces an EC JWK with P-256 crv, x, y', async () => {
      const { privateKey } = ecPair('prime256v1');
      const jwk = await exportPublicJwk(privateKey);
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256');
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();
      expect(jwk).not.toHaveProperty('d');
    });

    it('produces an OKP JWK for Ed25519 with only crv and x', async () => {
      const { privateKey } = edPair('ed25519');
      const jwk = await exportPublicJwk(privateKey);
      expect(jwk.kty).toBe('OKP');
      expect(jwk.crv).toBe('Ed25519');
      expect(jwk.x).toBeDefined();
      expect(jwk).not.toHaveProperty('y');
      expect(jwk).not.toHaveProperty('d');
    });

    it('refuses to export an HMAC key', async () => {
      const secret = createSecretKey(randomBytes(16));
      await expect(exportPublicJwk(secret)).rejects.toThrow(/HMAC/i);
    });
  });

  describe('sanitizePublicJwk', () => {
    it('strips extraneous fields from RSA JWKs', () => {
      const input = {
        kty: 'RSA',
        n: 'AQAB',
        e: 'AQAB',
        alg: 'RS256',
        use: 'sig',
        kid: 'x',
        d: 'SECRET',
      };
      const out = sanitizePublicJwk(input);
      expect(out).toEqual({ kty: 'RSA', n: 'AQAB', e: 'AQAB' });
      expect(out).not.toHaveProperty('d');
      expect(out).not.toHaveProperty('alg');
    });

    it('strips extraneous fields from EC JWKs', () => {
      const input = { kty: 'EC', crv: 'P-256', x: 'a', y: 'b', kid: 'k', alg: 'ES256' };
      expect(sanitizePublicJwk(input)).toEqual({ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' });
    });

    it('requires all RSA parameters', () => {
      expect(() => sanitizePublicJwk({ kty: 'RSA', n: 'AQAB' })).toThrow(/missing required field e/);
    });

    it('requires all EC parameters', () => {
      expect(() => sanitizePublicJwk({ kty: 'EC', crv: 'P-256', x: 'a' })).toThrow(/field y/);
    });

    it('requires OKP crv and x only', () => {
      const out = sanitizePublicJwk({ kty: 'OKP', crv: 'Ed25519', x: 'abc' });
      expect(out).toEqual({ kty: 'OKP', crv: 'Ed25519', x: 'abc' });
    });

    it('rejects unknown kty values', () => {
      expect(() => sanitizePublicJwk({ kty: 'DSA' as unknown as string })).toThrow(/Unsupported JWK kty/);
    });
  });
});
