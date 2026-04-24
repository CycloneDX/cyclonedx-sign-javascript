/**
 * End-to-end JSF envelope tests: sign, verify, tamper detection,
 * excludes handling, and the per-algorithm round-trip matrix.
 *
 * These tests exercise the public package surface — `sign` and
 * `verify` from `../src/jsf.js` — and treat the canonical bytes,
 * JWK, and algorithm layers as implementation details.
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPairSync,
  randomBytes,
  createSecretKey,
  type KeyObject,
} from 'node:crypto';

import { sign, verify, computeCanonicalInput } from '../src/jsf/index.js';
import {
  JsfEnvelopeError,
  JsfInputError,
  JsfVerifyError,
} from '../src/errors.js';
import type { JsonObject, JsfAlgorithm } from '../src/types.js';

interface KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

function rsaPair(): KeyPair {
  return generateKeyPairSync('rsa', { modulusLength: 2048 }) as unknown as KeyPair;
}
function ecPair(namedCurve: 'prime256v1' | 'secp384r1' | 'secp521r1'): KeyPair {
  return generateKeyPairSync('ec', { namedCurve }) as unknown as KeyPair;
}
function edPair(kind: 'ed25519' | 'ed448'): KeyPair {
  return (generateKeyPairSync as unknown as (k: string) => KeyPair)(kind);
}

function samplePayload(): JsonObject {
  return {
    subject: 'assessment-42',
    issuedAt: '2026-04-20T10:00:00Z',
    claims: [
      { id: 'c1', status: 'pass' },
      { id: 'c2', status: 'pass', notes: 'reviewed' },
    ],
    meta: { version: '1.0.0', source: 'assessors-studio' },
  };
}

describe('JSF sign and verify', () => {
  describe('per-algorithm round trip', () => {
    it('RS256 signs and verifies', () => {
      const { privateKey } = rsaPair();
      const signed = sign(samplePayload(), { algorithm: 'RS256', privateKey });
      expect(signed.signature).toBeDefined();
      const result = verify(signed);
      expect(result.valid).toBe(true);
      expect(result.algorithm).toBe('RS256');
    });

    it('RS384 signs and verifies', () => {
      const { privateKey } = rsaPair();
      const signed = sign(samplePayload(), { algorithm: 'RS384', privateKey });
      expect(verify(signed).valid).toBe(true);
    });

    it('RS512 signs and verifies', () => {
      const { privateKey } = rsaPair();
      const signed = sign(samplePayload(), { algorithm: 'RS512', privateKey });
      expect(verify(signed).valid).toBe(true);
    });

    it('PS256 signs and verifies', () => {
      const { privateKey } = rsaPair();
      const signed = sign(samplePayload(), { algorithm: 'PS256', privateKey });
      expect(verify(signed).valid).toBe(true);
    });

    it('PS384 signs and verifies', () => {
      const { privateKey } = rsaPair();
      const signed = sign(samplePayload(), { algorithm: 'PS384', privateKey });
      expect(verify(signed).valid).toBe(true);
    });

    it('PS512 signs and verifies', () => {
      const { privateKey } = rsaPair();
      const signed = sign(samplePayload(), { algorithm: 'PS512', privateKey });
      expect(verify(signed).valid).toBe(true);
    });

    it('ES256 signs and verifies', () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), { algorithm: 'ES256', privateKey });
      expect(verify(signed).valid).toBe(true);
    });

    it('ES384 signs and verifies', () => {
      const { privateKey } = ecPair('secp384r1');
      const signed = sign(samplePayload(), { algorithm: 'ES384', privateKey });
      expect(verify(signed).valid).toBe(true);
    });

    it('ES512 signs and verifies', () => {
      const { privateKey } = ecPair('secp521r1');
      const signed = sign(samplePayload(), { algorithm: 'ES512', privateKey });
      expect(verify(signed).valid).toBe(true);
    });

    it('Ed25519 signs and verifies', () => {
      const { privateKey } = edPair('ed25519');
      const signed = sign(samplePayload(), { algorithm: 'Ed25519', privateKey });
      expect(verify(signed).valid).toBe(true);
    });

    it('Ed448 signs and verifies', () => {
      const { privateKey } = edPair('ed448');
      const signed = sign(samplePayload(), { algorithm: 'Ed448', privateKey });
      expect(verify(signed).valid).toBe(true);
    });

    it('HS256 signs and verifies with an explicit verification key', () => {
      const key = createSecretKey(randomBytes(32));
      const signed = sign(samplePayload(), { algorithm: 'HS256', privateKey: key });
      expect(signed.signature).toBeDefined();
      const signer = signed.signature as { publicKey?: unknown };
      // HMAC envelopes never embed the key.
      expect(signer.publicKey).toBeUndefined();
      const result = verify(signed, { publicKey: key });
      expect(result.valid).toBe(true);
    });

    it('HS384 and HS512 round-trip', () => {
      const key = createSecretKey(randomBytes(32));
      const a = sign(samplePayload(), { algorithm: 'HS384', privateKey: key });
      expect(verify(a, { publicKey: key }).valid).toBe(true);
      const b = sign(samplePayload(), { algorithm: 'HS512', privateKey: key });
      expect(verify(b, { publicKey: key }).valid).toBe(true);
    });
  });

  describe('envelope shape', () => {
    it('does not mutate the input payload', () => {
      const { privateKey } = ecPair('prime256v1');
      const original = samplePayload();
      const copy = JSON.parse(JSON.stringify(original));
      sign(original, { algorithm: 'ES256', privateKey });
      expect(original).toEqual(copy);
    });

    it('attaches the signer under a custom signatureProperty when requested', () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), {
        algorithm: 'ES256',
        privateKey,
        signatureProperty: 'jsfSignature',
      });
      expect(signed.jsfSignature).toBeDefined();
      expect(signed.signature).toBeUndefined();
      const result = verify(signed, { signatureProperty: 'jsfSignature' });
      expect(result.valid).toBe(true);
    });

    it('embeds a publicKey by default for asymmetric algorithms', () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), { algorithm: 'ES256', privateKey });
      const signer = signed.signature as { publicKey?: { kty: string } };
      expect(signer.publicKey?.kty).toBe('EC');
    });

    it('omits the embedded publicKey when publicKey:false is set', () => {
      const { privateKey, publicKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), {
        algorithm: 'ES256',
        privateKey,
        publicKey: false,
      });
      const signer = signed.signature as { publicKey?: unknown };
      expect(signer.publicKey).toBeUndefined();
      // Verify still works when caller supplies the key externally.
      const result = verify(signed, { publicKey });
      expect(result.valid).toBe(true);
    });

    it('records keyId and certificatePath when provided', () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), {
        algorithm: 'ES256',
        privateKey,
        keyId: 'signer-01',
        certificatePath: ['BASE64-DER-CERT-1', 'BASE64-DER-CERT-2'],
      });
      const signer = signed.signature as {
        keyId: string;
        certificatePath: string[];
      };
      expect(signer.keyId).toBe('signer-01');
      expect(signer.certificatePath).toEqual(['BASE64-DER-CERT-1', 'BASE64-DER-CERT-2']);
      expect(verify(signed).valid).toBe(true);
    });
  });

  describe('tamper detection', () => {
    it('fails when a payload field changes after signing', () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), { algorithm: 'ES256', privateKey });
      const mutated = { ...signed, subject: 'assessment-99' };
      const result = verify(mutated);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toMatch(/did not verify/);
    });

    it('fails when a nested array element changes after signing', () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), { algorithm: 'ES256', privateKey });
      const mutated = JSON.parse(JSON.stringify(signed));
      mutated.claims[0].status = 'fail';
      expect(verify(mutated).valid).toBe(false);
    });

    it('fails when the base64url value is edited', () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), { algorithm: 'ES256', privateKey });
      const original = (signed.signature as { value: string }).value;
      // Flip one char by mapping A -> B. base64url is case sensitive so
      // this reliably alters the decoded bytes.
      const edited = original.startsWith('A')
        ? 'B' + original.slice(1)
        : 'A' + original.slice(1);
      const tampered = {
        ...signed,
        signature: { ...(signed.signature as object), value: edited },
      };
      expect(verify(tampered).valid).toBe(false);
    });

    it('does not verify a signature produced with a different key', () => {
      const pairA = ecPair('prime256v1');
      const pairB = ecPair('prime256v1');
      const signed = sign(samplePayload(), { algorithm: 'ES256', privateKey: pairA.privateKey });
      const spoofed = {
        ...signed,
        signature: {
          ...(signed.signature as object),
          publicKey: {
            kty: 'EC',
            crv: 'P-256',
            x: 'ZGVhZGJlZWY',
            y: 'ZGVhZGJlZWY',
          },
        },
      };
      const result = verify(spoofed, { publicKey: pairB.publicKey });
      expect(result.valid).toBe(false);
    });
  });

  describe('excludes behaviour', () => {
    it('allows excluded fields to change without breaking the signature', () => {
      const { privateKey } = ecPair('prime256v1');
      const payload = {
        subject: 'doc',
        body: 'hello',
        // transient field the signer does not want to commit to
        transient: 'initial',
      };
      const signed = sign(payload, {
        algorithm: 'ES256',
        privateKey,
        excludes: ['transient'],
      });
      const signer = signed.signature as { excludes: string[] };
      expect(signer.excludes).toEqual(['transient']);
      const mutated = { ...signed, transient: 'changed later' };
      expect(verify(mutated).valid).toBe(true);
    });

    it('still fails when a non-excluded field is tampered with', () => {
      const { privateKey } = ecPair('prime256v1');
      const payload = { subject: 'doc', body: 'hello', transient: 'x' };
      const signed = sign(payload, {
        algorithm: 'ES256',
        privateKey,
        excludes: ['transient'],
      });
      const mutated = { ...signed, body: 'altered' };
      expect(verify(mutated).valid).toBe(false);
    });
  });

  describe('verify constraints', () => {
    it('enforces an allowedAlgorithms allow-list', () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), { algorithm: 'ES256', privateKey });
      const result = verify(signed, { allowedAlgorithms: ['ES384', 'Ed25519'] });
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toMatch(/not on the allow-list/);
    });

    it('enforces requireEmbeddedPublicKey', () => {
      const { privateKey, publicKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), {
        algorithm: 'ES256',
        privateKey,
        publicKey: false,
      });
      const result = verify(signed, { publicKey, requireEmbeddedPublicKey: true });
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toMatch(/embedded publicKey/);
    });

    it('throws when no verifying key is available', () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), {
        algorithm: 'ES256',
        privateKey,
        publicKey: false,
      });
      expect(() => verify(signed)).toThrow(JsfVerifyError);
    });

    it('throws when the envelope is missing the signature property', () => {
      expect(() => verify({ foo: 'bar' })).toThrow(JsfEnvelopeError);
    });

    it('throws when the signer is not an object', () => {
      expect(() => verify({ signature: 'oops' } as JsonObject)).toThrow(JsfEnvelopeError);
    });

    it('throws when the signer is missing algorithm', () => {
      expect(() => verify({ signature: { value: 'x' } } as JsonObject)).toThrow(/algorithm/);
    });

    it('surfaces a malformed base64url value as an error', () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = sign(samplePayload(), { algorithm: 'ES256', privateKey });
      const broken = {
        ...signed,
        signature: { ...(signed.signature as object), value: '!!! not base64 !!!' },
      };
      const result = verify(broken);
      expect(result.valid).toBe(false);
      expect(result.errors.join(' ')).toMatch(/malformed/);
    });
  });

  describe('input validation on sign', () => {
    it('rejects a non-object payload', () => {
      const { privateKey } = rsaPair();
      expect(() => sign([] as unknown as JsonObject, { algorithm: 'RS256', privateKey })).toThrow(
        JsfInputError,
      );
    });

    it('rejects an unknown algorithm', () => {
      const { privateKey } = rsaPair();
      expect(() =>
        sign({ a: 1 }, { algorithm: 'ZZZ' as JsfAlgorithm, privateKey }),
      ).toThrow(/Unsupported algorithm/);
    });

    it('refuses to overwrite an existing signature property', () => {
      const { privateKey } = rsaPair();
      expect(() =>
        sign({ a: 1, signature: 'taken' }, { algorithm: 'RS256', privateKey }),
      ).toThrow(/refusing to overwrite/);
    });

    it('rejects empty keyId', () => {
      const { privateKey } = rsaPair();
      expect(() =>
        sign({ a: 1 }, { algorithm: 'RS256', privateKey, keyId: '' }),
      ).toThrow(/non-empty/);
    });

    it('rejects empty certificatePath', () => {
      const { privateKey } = rsaPair();
      expect(() =>
        sign({ a: 1 }, { algorithm: 'RS256', privateKey, certificatePath: [] }),
      ).toThrow(/non-empty/);
    });
  });

  describe('round-trip independence of input key order', () => {
    it('produces the same verification result regardless of key ordering', () => {
      const { privateKey } = edPair('ed25519');
      const a = { a: 1, b: 2, c: [3, 4] };
      const b = { c: [3, 4], a: 1, b: 2 };
      const signedA = sign(a, { algorithm: 'Ed25519', privateKey });
      // Swapping input key order must still yield a verifying envelope.
      const signedB = sign(b, { algorithm: 'Ed25519', privateKey });
      expect(verify(signedA).valid).toBe(true);
      expect(verify(signedB).valid).toBe(true);
    });
  });

  describe('computeCanonicalInput', () => {
    it('returns UTF-8 bytes representing the JCS canonical form', () => {
      const payload = { b: 2, a: 1 };
      const bytes = computeCanonicalInput(payload, { algorithm: 'ES256' });
      const asString = new TextDecoder().decode(bytes);
      // Top-level keys are sorted (a before b, and signature after both).
      expect(asString).toBe('{"a":1,"b":2,"signature":{"algorithm":"ES256"}}');
    });

    it('honours a custom signatureProperty', () => {
      const bytes = computeCanonicalInput({ a: 1 }, { algorithm: 'ES256' }, 'jsfSignature');
      expect(new TextDecoder().decode(bytes)).toBe(
        '{"a":1,"jsfSignature":{"algorithm":"ES256"}}',
      );
    });
  });
});
