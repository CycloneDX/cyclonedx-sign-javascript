/**
 * JWK normalization and sanitization tests.
 *
 * These cover the shapes the public API promises to accept, the
 * canonical shape it exports, and a handful of failure modes that
 * application callers have asked about.
 */

import { describe, it, expect } from 'vitest';
import {
  createSecretKey,
  generateKeyPairSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';

import {
  exportPublicJwk,
  sanitizePublicJwk,
  toPrivateKey,
  toPublicKey,
} from '../src/jwk.js';
import { JsfKeyError } from '../src/errors.js';
import { ecPair, edPair, rsaPair, type KeyPair } from './helpers.js';

describe('JWK', () => {
  describe('toPrivateKey', () => {
    it('accepts a Node KeyObject directly', () => {
      const { privateKey } = rsaPair();
      const out = toPrivateKey(privateKey);
      expect(out.keyObject.type).toBe('private');
      expect(out.asymmetricKeyType).toBe('rsa');
      expect(out.curve).toBeNull();
    });

    it('rejects a public KeyObject as a private key', () => {
      const { publicKey } = rsaPair();
      expect(() => toPrivateKey(publicKey)).toThrow(JsfKeyError);
    });

    it('accepts a PEM-encoded private key string', () => {
      const { privateKey } = ecPair('prime256v1');
      const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
      const out = toPrivateKey(pem);
      expect(out.asymmetricKeyType).toBe('ec');
      expect(out.curve).toBe('P-256');
    });

    it('accepts a JWK object for an EC private key', () => {
      const { privateKey } = ecPair('secp384r1');
      const jwk = privateKey.export({ format: 'jwk' }) as Record<string, unknown>;
      const out = toPrivateKey(jwk as never);
      expect(out.asymmetricKeyType).toBe('ec');
      expect(out.curve).toBe('P-384');
    });

    it('accepts a JWK JSON string for an EC private key', () => {
      const { privateKey } = ecPair('secp521r1');
      const jwk = privateKey.export({ format: 'jwk' });
      const out = toPrivateKey(JSON.stringify(jwk));
      expect(out.curve).toBe('P-521');
    });

    it('accepts HMAC bytes as a Buffer', () => {
      const secret = randomBytes(32);
      const out = toPrivateKey(secret);
      expect(out.asymmetricKeyType).toBe('oct');
      expect(out.keyObject.type).toBe('secret');
    });

    it('accepts HMAC bytes as a Uint8Array', () => {
      const bytes = new Uint8Array([1, 2, 3, 4]);
      const out = toPrivateKey(bytes);
      expect(out.asymmetricKeyType).toBe('oct');
    });

    it('accepts an oct JWK and decodes k from base64url', () => {
      const out = toPrivateKey({ kty: 'oct', k: 'AQID' } as never);
      expect(out.asymmetricKeyType).toBe('oct');
    });

    it('rejects oct JWK without k', () => {
      expect(() => toPrivateKey({ kty: 'oct' } as never)).toThrow(/k property/);
    });

    it('rejects unknown key input shapes', () => {
      expect(() => toPrivateKey(42 as never)).toThrow(JsfKeyError);
      expect(() => toPrivateKey(null as never)).toThrow(JsfKeyError);
    });

    it('reports the curve for Ed25519', () => {
      const { privateKey } = edPair('ed25519');
      const out = toPrivateKey(privateKey);
      expect(out.asymmetricKeyType).toBe('ed25519');
      expect(out.curve).toBe('Ed25519');
    });

    it('reports the curve for Ed448', () => {
      const { privateKey } = edPair('ed448');
      const out = toPrivateKey(privateKey);
      expect(out.curve).toBe('Ed448');
    });
  });

  describe('toPublicKey', () => {
    it('extracts the public half from a private KeyObject', () => {
      const { privateKey } = rsaPair();
      const out = toPublicKey(privateKey);
      expect(out.keyObject.type).toBe('public');
      expect(out.asymmetricKeyType).toBe('rsa');
    });

    it('accepts a PEM SPKI public key', () => {
      const { publicKey } = ecPair('prime256v1');
      const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
      const out = toPublicKey(pem);
      expect(out.asymmetricKeyType).toBe('ec');
      expect(out.curve).toBe('P-256');
    });

    it('accepts a JWK object for an RSA public key', () => {
      const { publicKey } = rsaPair();
      const jwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
      const out = toPublicKey(jwk as never);
      expect(out.asymmetricKeyType).toBe('rsa');
    });

    it('accepts a Node secret KeyObject as HMAC material', () => {
      const secret = createSecretKey(randomBytes(16));
      const out = toPublicKey(secret);
      expect(out.asymmetricKeyType).toBe('oct');
    });

    it('rejects non-key input', () => {
      expect(() => toPublicKey(undefined as never)).toThrow(JsfKeyError);
    });
  });

  describe('exportPublicJwk', () => {
    it('produces an RSA JWK with only n and e', () => {
      const { privateKey } = rsaPair();
      const jwk = exportPublicJwk(privateKey);
      expect(jwk.kty).toBe('RSA');
      expect(jwk.n).toBeDefined();
      expect(jwk.e).toBeDefined();
      expect(jwk).not.toHaveProperty('d');
      expect(jwk).not.toHaveProperty('p');
      expect(jwk).not.toHaveProperty('alg');
    });

    it('produces an EC JWK with P-256 crv, x, y', () => {
      const { privateKey } = ecPair('prime256v1');
      const jwk = exportPublicJwk(privateKey);
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256');
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();
      expect(jwk).not.toHaveProperty('d');
    });

    it('produces an OKP JWK for Ed25519 with only crv and x', () => {
      const { privateKey } = edPair('ed25519');
      const jwk = exportPublicJwk(privateKey);
      expect(jwk.kty).toBe('OKP');
      expect(jwk.crv).toBe('Ed25519');
      expect(jwk.x).toBeDefined();
      expect(jwk).not.toHaveProperty('y');
      expect(jwk).not.toHaveProperty('d');
    });

    it('refuses to export an HMAC key', () => {
      const secret = createSecretKey(randomBytes(16));
      expect(() => exportPublicJwk(secret)).toThrow(/HMAC/i);
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
