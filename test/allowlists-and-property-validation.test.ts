/**
 * Tests for the verifier-side acceptance allowlists (JSF § 5) and the
 * unconditional JSF § 6 rule that rejects undefined properties inside
 * the JSF signature object.
 *
 * JSF § 6 is normative verifier behavior. Envelopes whose
 * signaturecore or wrapper carries an undeclared property fail
 * verification with an envelope-level error in `result.errors[]`.
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';

import { sign, verify } from '../src/jsf/index.js';
import type { JsonObject, JsonValue } from '../src/types.js';

interface KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

function ecPair(): KeyPair {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' }) as unknown as KeyPair;
}

describe('allowedExcludes', () => {
  it('lenient default accepts any excludes', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { a: 1, transient: 'x' },
      {
        signer: { algorithm: 'ES256', privateKey },
        excludes: ['transient'],
      },
    );
    const result = await verify(signed);
    expect(result.valid).toBe(true);
  });

  it('rejects an envelope whose excludes contains an unauthorized name', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { a: 1, transient: 'x' },
      {
        signer: { algorithm: 'ES256', privateKey },
        excludes: ['transient'],
      },
    );
    const result = await verify(signed, { allowedExcludes: ['public'] });
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toMatch(/transient/);
  });

  it('accepts when every excludes entry is on the allowlist', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { a: 1, transient: 'x' },
      {
        signer: { algorithm: 'ES256', privateKey },
        excludes: ['transient'],
      },
    );
    const result = await verify(signed, { allowedExcludes: ['transient', 'other'] });
    expect(result.valid).toBe(true);
  });
});

describe('allowedExtensions', () => {
  it('rejects an envelope whose extensions list has an unauthorized name', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { a: 1 },
      {
        signer: {
          algorithm: 'ES256',
          privateKey,
          extensionValues: { ext1: 'v', ext2: 'w' },
        },
      },
    );
    const result = await verify(signed, { allowedExtensions: ['ext1'] });
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toMatch(/ext2/);
  });

  it('accepts when every extension is on the allowlist', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { a: 1 },
      {
        signer: {
          algorithm: 'ES256',
          privateKey,
          extensionValues: { ext1: 'v', ext2: 'w' },
        },
      },
    );
    const result = await verify(signed, { allowedExtensions: ['ext1', 'ext2'] });
    expect(result.valid).toBe(true);
  });
});

describe('JSF § 6: undefined properties inside the signature object are rejected (always)', () => {
  it('rejects an undeclared signaturecore property', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { a: 1 },
      { signer: { algorithm: 'ES256', privateKey } },
    );
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    (wire.signature as Record<string, JsonValue>).noise = 1;
    const result = await verify(wire);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toMatch(/noise/);
    expect(result.errors.join(' ')).toMatch(/JSF § 6/);
  });

  it('rejects an undeclared wrapper property', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign(
      { a: 1 },
      {
        signers: [
          { algorithm: 'ES256', privateKey: a.privateKey },
          { algorithm: 'ES256', privateKey: b.privateKey },
        ],
        mode: 'multi',
      },
    );
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    (wire.signature as Record<string, JsonValue>).bogusWrapperProp = 1;
    const result = await verify(wire);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toMatch(/bogusWrapperProp/);
  });

  it('accepts a valid envelope with declared extensions', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { a: 1 },
      {
        signer: {
          algorithm: 'ES256',
          privateKey,
          extensionValues: { ext1: 'v' },
        },
      },
    );
    const result = await verify(signed);
    expect(result.valid).toBe(true);
  });
});
