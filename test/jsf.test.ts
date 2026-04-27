/**
 * End-to-end JSF envelope tests for the unified async API.
 *
 * These tests exercise the public package surface — `sign` and
 * `verify` from `../src/jsf/index.js` — and treat the canonical
 * bytes, JWK, and algorithm layers as implementation details.
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPairSync,
  randomBytes,
  createSecretKey,
  type KeyObject,
} from 'node:crypto';

import { sign, verify, computeCanonicalInputs } from '../src/jsf/index.js';
import {
  JsfEnvelopeError,
  JsfMultiSignerInputError,
  JsfVerifyError,
} from '../src/errors.js';
import type { JsonObject } from '../src/types.js';
import type { JsfAlgorithm } from '../src/jsf/types.js';

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

describe('JSF sign and verify (single mode)', () => {
  describe('per-algorithm round trip', () => {
    const pkOf = {
      RS256: () => rsaPair().privateKey,
      RS384: () => rsaPair().privateKey,
      RS512: () => rsaPair().privateKey,
      PS256: () => rsaPair().privateKey,
      PS384: () => rsaPair().privateKey,
      PS512: () => rsaPair().privateKey,
      ES256: () => ecPair('prime256v1').privateKey,
      ES384: () => ecPair('secp384r1').privateKey,
      ES512: () => ecPair('secp521r1').privateKey,
      Ed25519: () => edPair('ed25519').privateKey,
      Ed448: () => edPair('ed448').privateKey,
    } as const;

    for (const alg of Object.keys(pkOf) as Array<keyof typeof pkOf>) {
      it(`${alg} signs and verifies`, async () => {
        const privateKey = pkOf[alg]();
        const signed = await sign(samplePayload(), {
          signer: { algorithm: alg, privateKey },
        });
        expect(signed.signature).toBeDefined();
        const result = await verify(signed);
        expect(result.valid).toBe(true);
        expect(result.mode).toBe('single');
        expect(result.signers[0]?.algorithm).toBe(alg);
      });
    }

    it('HS256 signs and verifies with an explicit verification key', async () => {
      const key = createSecretKey(randomBytes(32));
      const signed = await sign(samplePayload(), {
        signer: { algorithm: 'HS256', privateKey: key },
      });
      const signer = signed.signature as { publicKey?: unknown };
      expect(signer.publicKey).toBeUndefined();
      const result = await verify(signed, { publicKey: key });
      expect(result.valid).toBe(true);
    });
  });

  describe('envelope shape', () => {
    it('does not mutate the input payload', async () => {
      const { privateKey } = ecPair('prime256v1');
      const original = samplePayload();
      const copy = JSON.parse(JSON.stringify(original));
      await sign(original, { signer: { algorithm: 'ES256', privateKey } });
      expect(original).toEqual(copy);
    });

    it('attaches the signer under a custom signatureProperty when requested', async () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = await sign(samplePayload(), {
        signer: { algorithm: 'ES256', privateKey },
        signatureProperty: 'jsfSignature',
      });
      expect(signed.jsfSignature).toBeDefined();
      expect(signed.signature).toBeUndefined();
      const result = await verify(signed, { signatureProperty: 'jsfSignature' });
      expect(result.valid).toBe(true);
    });

    it('embeds a publicKey by default for asymmetric algorithms', async () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = await sign(samplePayload(), {
        signer: { algorithm: 'ES256', privateKey },
      });
      const signer = signed.signature as { publicKey?: { kty: string } };
      expect(signer.publicKey?.kty).toBe('EC');
    });

    it('omits the embedded publicKey when publicKey:false is set', async () => {
      const { privateKey, publicKey } = ecPair('prime256v1');
      const signed = await sign(samplePayload(), {
        signer: { algorithm: 'ES256', privateKey, publicKey: false },
      });
      const signer = signed.signature as { publicKey?: unknown };
      expect(signer.publicKey).toBeUndefined();
      const result = await verify(signed, { publicKey });
      expect(result.valid).toBe(true);
    });

    it('records keyId and certificatePath when provided', async () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = await sign(samplePayload(), {
        signer: {
          algorithm: 'ES256',
          privateKey,
          keyId: 'signer-01',
          certificatePath: ['BASE64-DER-CERT-1', 'BASE64-DER-CERT-2'],
        },
      });
      const signer = signed.signature as {
        keyId: string;
        certificatePath: string[];
      };
      expect(signer.keyId).toBe('signer-01');
      expect(signer.certificatePath).toEqual(['BASE64-DER-CERT-1', 'BASE64-DER-CERT-2']);
      expect((await verify(signed)).valid).toBe(true);
    });
  });

  describe('tamper detection', () => {
    it('fails when a payload field changes after signing', async () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = await sign(samplePayload(), {
        signer: { algorithm: 'ES256', privateKey },
      });
      const mutated: JsonObject = { ...signed, subject: 'assessment-99' };
      const result = await verify(mutated);
      expect(result.valid).toBe(false);
      expect(result.signers[0]?.errors[0]).toMatch(/did not verify/);
    });

    it('fails when the base64url value is edited', async () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = await sign(samplePayload(), {
        signer: { algorithm: 'ES256', privateKey },
      });
      const original = (signed.signature as { value: string }).value;
      const edited = original.startsWith('A')
        ? 'B' + original.slice(1)
        : 'A' + original.slice(1);
      const tampered: JsonObject = {
        ...signed,
        signature: { ...(signed.signature as object), value: edited },
      };
      expect((await verify(tampered)).valid).toBe(false);
    });
  });

  describe('excludes behaviour', () => {
    it('allows excluded fields to change without breaking the signature', async () => {
      const { privateKey } = ecPair('prime256v1');
      const payload = {
        subject: 'doc',
        body: 'hello',
        transient: 'initial',
      };
      const signed = await sign(payload, {
        signer: { algorithm: 'ES256', privateKey },
        excludes: ['transient'],
      });
      const signer = signed.signature as { excludes: string[] };
      expect(signer.excludes).toEqual(['transient']);
      const mutated: JsonObject = { ...signed, transient: 'changed later' };
      expect((await verify(mutated)).valid).toBe(true);
    });

    it('still fails when a non-excluded field is tampered with', async () => {
      const { privateKey } = ecPair('prime256v1');
      const payload = { subject: 'doc', body: 'hello', transient: 'x' };
      const signed = await sign(payload, {
        signer: { algorithm: 'ES256', privateKey },
        excludes: ['transient'],
      });
      const mutated: JsonObject = { ...signed, body: 'altered' };
      expect((await verify(mutated)).valid).toBe(false);
    });
  });

  describe('verify constraints', () => {
    it('enforces an allowedAlgorithms allow-list', async () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = await sign(samplePayload(), {
        signer: { algorithm: 'ES256', privateKey },
      });
      const result = await verify(signed, { allowedAlgorithms: ['ES384', 'Ed25519'] });
      expect(result.valid).toBe(false);
      expect(result.signers[0]?.errors[0]).toMatch(/not on the allow-list/);
    });

    it('enforces requireEmbeddedPublicKey', async () => {
      const { privateKey, publicKey } = ecPair('prime256v1');
      const signed = await sign(samplePayload(), {
        signer: { algorithm: 'ES256', privateKey, publicKey: false },
      });
      const result = await verify(signed, { publicKey, requireEmbeddedPublicKey: true });
      expect(result.valid).toBe(false);
      expect(result.signers[0]?.errors[0]).toMatch(/embedded publicKey/);
    });

    it('throws when no verifying key is available', async () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = await sign(samplePayload(), {
        signer: { algorithm: 'ES256', privateKey, publicKey: false },
      });
      await expect(verify(signed)).rejects.toThrow(JsfVerifyError);
    });

    it('throws when the envelope is missing the signature property', async () => {
      await expect(verify({ foo: 'bar' })).rejects.toThrow(JsfEnvelopeError);
    });

    it('throws when the signer is not an object', async () => {
      await expect(verify({ signature: 'oops' } as JsonObject)).rejects.toThrow(JsfEnvelopeError);
    });

    it('throws when the signer is missing algorithm', async () => {
      await expect(
        verify({ signature: { value: 'x' } } as JsonObject),
      ).rejects.toThrow(/algorithm/);
    });

    it('surfaces a malformed base64url value as an error', async () => {
      const { privateKey } = ecPair('prime256v1');
      const signed = await sign(samplePayload(), {
        signer: { algorithm: 'ES256', privateKey },
      });
      const broken: JsonObject = {
        ...signed,
        signature: { ...(signed.signature as object), value: '!!! not base64 !!!' },
      };
      const result = await verify(broken);
      expect(result.valid).toBe(false);
      expect(result.signers[0]?.errors.join(' ')).toMatch(/malformed/);
    });
  });

  describe('input validation on sign', () => {
    it('rejects a non-object payload', async () => {
      const { privateKey } = rsaPair();
      await expect(
        sign([] as unknown as JsonObject, {
          signer: { algorithm: 'RS256', privateKey },
        }),
      ).rejects.toThrow(/JSON object/);
    });

    it('rejects an unknown algorithm', async () => {
      const { privateKey } = rsaPair();
      await expect(
        sign({ a: 1 }, {
          signer: { algorithm: 'ZZZ' as JsfAlgorithm, privateKey },
        }),
      ).rejects.toThrow(/Unsupported algorithm/);
    });

    it('refuses to overwrite an existing signature property', async () => {
      const { privateKey } = rsaPair();
      await expect(
        sign({ a: 1, signature: 'taken' } as JsonObject, {
          signer: { algorithm: 'RS256', privateKey },
        }),
      ).rejects.toThrow(/refusing to overwrite/);
    });

    it('rejects providing both signer and signers', async () => {
      const { privateKey } = rsaPair();
      await expect(
        sign({ a: 1 }, {
          signer: { algorithm: 'RS256', privateKey },
          signers: [{ algorithm: 'RS256', privateKey }],
        }),
      ).rejects.toThrow(JsfMultiSignerInputError);
    });

    it('rejects empty signers array', async () => {
      await expect(
        sign({ a: 1 }, { signers: [] }),
      ).rejects.toThrow(JsfMultiSignerInputError);
    });

    it('mode set with a single signer produces a length-1 wrapper (for later append)', async () => {
      const { privateKey } = rsaPair();
      const signed = await sign({ a: 1 }, {
        signers: [{ algorithm: 'RS256', privateKey }],
        mode: 'chain',
      });
      // Wrapper (not a bare signaturecore) so subsequent appendChainSigner works.
      expect(Array.isArray((signed.signature as { chain?: unknown[] }).chain)).toBe(true);
    });

    it('requires mode when more than one signer is provided', async () => {
      const { privateKey } = rsaPair();
      await expect(
        sign({ a: 1 }, {
          signers: [
            { algorithm: 'RS256', privateKey },
            { algorithm: 'RS256', privateKey },
          ],
        }),
      ).rejects.toThrow(/mode.*required/);
    });
  });

  describe('round-trip independence of input key order', () => {
    it('produces the same verification result regardless of key ordering', async () => {
      const { privateKey } = edPair('ed25519');
      const a = { a: 1, b: 2, c: [3, 4] };
      const b = { c: [3, 4], a: 1, b: 2 };
      const signedA = await sign(a, { signer: { algorithm: 'Ed25519', privateKey } });
      const signedB = await sign(b, { signer: { algorithm: 'Ed25519', privateKey } });
      expect((await verify(signedA)).valid).toBe(true);
      expect((await verify(signedB)).valid).toBe(true);
    });
  });

  describe('computeCanonicalInputs', () => {
    it('returns one byte sequence per signer in single mode', () => {
      const payload = { b: 2, a: 1 };
      const bytes = computeCanonicalInputs(payload, {
        mode: 'single',
        signers: [{ algorithm: 'ES256' }],
        finalized: [false],
      });
      expect(bytes).toHaveLength(1);
      const asString = new TextDecoder().decode(bytes[0]);
      expect(asString).toBe('{"a":1,"b":2,"signature":{"algorithm":"ES256"}}');
    });

    it('honours a custom signatureProperty', () => {
      const bytes = computeCanonicalInputs(
        { a: 1 },
        { mode: 'single', signers: [{ algorithm: 'ES256' }], finalized: [false] },
        'jsfSignature',
      );
      expect(new TextDecoder().decode(bytes[0])).toBe(
        '{"a":1,"jsfSignature":{"algorithm":"ES256"}}',
      );
    });
  });
});
