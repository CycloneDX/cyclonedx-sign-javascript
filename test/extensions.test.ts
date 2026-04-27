/**
 * JSF extensions (Global Signature Option) tests covering:
 *   - declared extension property values round-trip
 *   - optional-per-signer values in multi/chain
 *   - reserved-word / duplicate / undeclared rejections at sign time
 *   - reserved-word / undeclared rejection at verify time
 *   - tamper inside an extension property value fails verify
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';

import { sign, verify } from '../src/jsf/index.js';
import { JsfInputError } from '../src/errors.js';
import type { JsonObject, JsonValue } from '../src/types.js';
import { ecPair, type KeyPair } from './helpers.js';

describe('JSF extensions: single mode', () => {
  it('declared extension values round-trip on the signaturecore', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { subject: 'doc' },
      {
        signer: {
          algorithm: 'ES256',
          privateKey,
          extensionValues: {
            issuedAt: '2026-04-01T00:00:00Z',
            'https://example.com/role': 'lead-assessor' } } },
    );
    const sig = signed.signature as Record<string, JsonValue>;
    expect(sig.extensions).toEqual([
      'issuedAt',
      'https://example.com/role',
    ]);
    expect(sig.issuedAt).toBe('2026-04-01T00:00:00Z');
    expect(sig['https://example.com/role']).toBe('lead-assessor');
    const result = await verify(signed);
    expect(result.valid).toBe(true);
    expect(result.extensions).toEqual([
      'issuedAt',
      'https://example.com/role',
    ]);
    expect(result.signers[0]?.extensionValues).toEqual({
      issuedAt: '2026-04-01T00:00:00Z',
      'https://example.com/role': 'lead-assessor' });
  });

  it('rejects an extension name that collides with a JSF reserved word', async () => {
    const { privateKey } = ecPair();
    await expect(
      sign(
        { x: 1 },
        {
          signer: {
            algorithm: 'ES256',
            privateKey,
            extensionValues: { chain: 'oops' } } },
      ),
    ).rejects.toThrow(/reserved word/);
  });

  it('rejects duplicate extension names', async () => {
    const { privateKey } = ecPair();
    await expect(
      sign(
        { x: 1 },
        {
          signer: { algorithm: 'ES256', privateKey, extensionValues: { ext1: 'a' } },
          extensions: ['ext1', 'ext1'] },
      ),
    ).rejects.toThrow(/more than once/);
  });

  it('mutating an extension value breaks verification', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { x: 1 },
      {
        signer: {
          algorithm: 'ES256',
          privateKey,
          extensionValues: { ext1: 'pristine' } } },
    );
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    (wire.signature as Record<string, JsonValue>).ext1 = 'tampered';
    expect((await verify(wire)).valid).toBe(false);
  });
});

describe('JSF extensions: multi and chain optional-per-signer', () => {
  it('multi: signer 1 omits one extension, both still verify', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign(
      { name: 'Joe' },
      {
        signers: [
          {
            algorithm: 'ES256',
            privateKey: a.privateKey,
            extensionValues: { otherExt: 'Cool', extra: 1 } },
          {
            algorithm: 'ES256',
            privateKey: b.privateKey,
            extensionValues: { otherExt: 'Other Data' } },
        ],
        mode: 'multi' },
    );
    expect((signed.signature as { extensions: string[] }).extensions).toEqual(
      expect.arrayContaining(['otherExt', 'extra']),
    );
    const result = await verify(signed);
    expect(result.valid).toBe(true);
    expect(result.signers[0]?.extensionValues).toEqual({
      otherExt: 'Cool',
      extra: 1 });
    expect(result.signers[1]?.extensionValues).toEqual({
      otherExt: 'Other Data' });
  });

  it('chain: signer 0 has an extension, signer 1 inherits the wrapper-level list', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign(
      { name: 'Joe' },
      {
        signers: [
          {
            algorithm: 'ES256',
            privateKey: a.privateKey,
            extensionValues: { ext1: 'one' } },
          {
            algorithm: 'ES256',
            privateKey: b.privateKey,
            // signer 1 has no extension values
          },
        ],
        mode: 'chain' },
    );
    const result = await verify(signed);
    expect(result.valid).toBe(true);
    expect(result.signers[0]?.extensionValues).toEqual({ ext1: 'one' });
    expect(result.signers[1]?.extensionValues).toBeUndefined();
  });
});

describe('JSF extensions: input validation', () => {
  it('rejects extensionValues with a key not in the declared extensions list', async () => {
    const { privateKey } = ecPair();
    await expect(
      sign(
        { x: 1 },
        {
          signer: {
            algorithm: 'ES256',
            privateKey,
            extensionValues: { undeclared: 1 } },
          extensions: ['ext1'] },
      ),
    ).rejects.toThrow(JsfInputError);
  });

  it('verify rejects an envelope whose extensions list contains a reserved word', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { x: 1 },
      {
        signer: { algorithm: 'ES256', privateKey, extensionValues: { ext1: 'v' } } },
    );
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    (wire.signature as Record<string, JsonValue>).extensions = ['signers'];
    const result = await verify(wire);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toMatch(/reserved word/);
  });
});
