/**
 * Interop with the Cyberphone JSF 0.82 reference vectors.
 *
 * Vectors live in test/fixtures/jsf/interop/jsf-spec/. Each envelope
 * was produced by the JSF spec author's reference implementation and
 * is committed verbatim. This suite verifies them with the keys
 * shipped alongside the envelopes.
 *
 * For the JWK-embedded variants the verifier needs no extra input.
 * For the keyId variants we resolve the key from the matching
 * `*privatekey.jwk` (whose `kid` matches the keyId in the envelope's
 * signaturecore objects).
 *
 * For multi and chain envelopes we also assert the per-signer
 * cryptographic outcome and the wrapper-level metadata.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { verify } from '../src/jsf/index.js';
import type { JsonObject } from '../src/types.js';
import type { JwkPublicKey, KeyInput } from '../src/types.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DIR = join(HERE, 'fixtures', 'jsf', 'interop', 'jsf-spec');

function read(name: string): JsonObject {
  return JSON.parse(readFileSync(join(DIR, name), 'utf8')) as JsonObject;
}

interface JwkPrivate extends JwkPublicKey {
  kid?: string;
  d?: string;
}

function readJwk(name: string): JwkPrivate {
  return JSON.parse(readFileSync(join(DIR, name), 'utf8')) as JwkPrivate;
}

function publicJwkFromPrivate(jwk: JwkPrivate): JwkPublicKey {
  // Strip private fields and metadata. Library would also accept the
  // private JWK directly via toPublicKey, but mirror what a real
  // verifier would do.
  if (jwk.kty === 'EC') {
    return { kty: 'EC', crv: jwk.crv!, x: jwk.x!, y: jwk.y! };
  }
  if (jwk.kty === 'OKP') {
    return { kty: 'OKP', crv: jwk.crv!, x: jwk.x! };
  }
  if (jwk.kty === 'RSA') {
    return { kty: 'RSA', n: jwk.n!, e: jwk.e! };
  }
  throw new Error(`unsupported kty ${jwk.kty}`);
}

describe('JSF spec interop: single-mode JWK vectors', () => {
  it('p256#es256@kid.json verifies (kid resolved from p256privatekey.jwk)', async () => {
    const env = read('p256#es256@kid.json');
    const pub = publicJwkFromPrivate(readJwk('p256privatekey.jwk'));
    const result = await verify(env, { publicKey: pub });
    expect(result.valid).toBe(true);
    expect(result.signers[0]?.keyId).toBe('example.com:p256');
  });

  it('r2048#rs256@jwk.json verifies (key embedded)', async () => {
    const env = read('r2048#rs256@jwk.json');
    const result = await verify(env);
    expect(result.valid).toBe(true);
    expect(result.signers[0]?.algorithm).toBe('RS256');
  });

  it('r2048#rs256@kid.json verifies (kid resolved from r2048privatekey.jwk)', async () => {
    const env = read('r2048#rs256@kid.json');
    const pub = publicJwkFromPrivate(readJwk('r2048privatekey.jwk'));
    const result = await verify(env, { publicKey: pub });
    expect(result.valid).toBe(true);
  });

  it('p256#es256@excl-jwk.json verifies and round-trips excludes', async () => {
    const env = read('p256#es256@excl-jwk.json');
    const result = await verify(env);
    expect(result.valid).toBe(true);
    // In single mode, excludes and extensions live on the signaturecore.
    // Library reports them on the result via the per-signer result.
    expect(result.excludes).toEqual(['myUnsignedData']);
  });

  it('p256#es256@exts-jwk.json verifies and round-trips extensions', async () => {
    const env = read('p256#es256@exts-jwk.json');
    const result = await verify(env);
    expect(result.valid).toBe(true);
    expect(result.extensions).toEqual([
      'otherExt',
      'https://example.com/extension',
    ]);
    expect(result.signers[0]?.extensionValues).toEqual({
      otherExt: 'Cool Stuff',
      'https://example.com/extension': { 'life-is-great': true },
    });
  });

  it('p256#es256@name-jwk.json verifies under the custom property name', async () => {
    const env = read('p256#es256@name-jwk.json');
    // The name vector uses a non-default signature property name.
    // Read the envelope to discover which key holds the JSF object.
    const candidateKey = Object.keys(env).find((k) =>
      typeof (env as Record<string, unknown>)[k] === 'object' &&
      (env as Record<string, Record<string, unknown>>)[k]?.algorithm !== undefined,
    );
    expect(candidateKey).toBeDefined();
    const result = await verify(env, { signatureProperty: candidateKey! });
    expect(result.valid).toBe(true);
  });
});

describe('JSF spec interop: multi-signer vectors', () => {
  it('mult-jwk verifies both signers with their embedded JWKs', async () => {
    const env = read('p256#es256,r2048#rs256@mult-jwk.json');
    const result = await verify(env);
    expect(result.mode).toBe('multi');
    expect(result.signers).toHaveLength(2);
    expect(result.valid).toBe(true);
    expect(result.signers[0]?.algorithm).toBe('ES256');
    expect(result.signers[1]?.algorithm).toBe('RS256');
  });

  it('mult-exts-kid verifies and reports per-signer extension values', async () => {
    const env = read('p256#es256,r2048#rs256@mult-exts-kid.json');
    const p256 = publicJwkFromPrivate(readJwk('p256privatekey.jwk'));
    const r2048 = publicJwkFromPrivate(readJwk('r2048privatekey.jwk'));
    const result = await verify(env, {
      publicKeys: new Map<number, KeyInput>([
        [0, p256],
        [1, r2048],
      ]),
    });
    expect(result.valid).toBe(true);
    expect(result.extensions).toEqual([
      'otherExt',
      'https://example.com/extension',
    ]);
    // The vector has the second signer omit one extension property.
    expect(result.signers[0]?.extensionValues).toEqual({
      otherExt: 'Cool Stuff',
      'https://example.com/extension': { 'life-is-great': true },
    });
    expect(result.signers[1]?.extensionValues).toEqual({
      otherExt: 'Other Data',
    });
  });

  it('mult-excl-kid verifies and reports excludes', async () => {
    const env = read('p256#es256,r2048#rs256@mult-excl-kid.json');
    const p256 = publicJwkFromPrivate(readJwk('p256privatekey.jwk'));
    const r2048 = publicJwkFromPrivate(readJwk('r2048privatekey.jwk'));
    const result = await verify(env, {
      publicKeys: new Map<number, KeyInput>([
        [0, p256],
        [1, r2048],
      ]),
    });
    expect(result.valid).toBe(true);
    expect(result.excludes).toEqual(['myUnsignedData']);
  });
});

describe('JSF spec interop: chain vectors', () => {
  it('chai-jwk verifies', async () => {
    const env = read('p256#es256,r2048#rs256@chai-jwk.json');
    const result = await verify(env);
    expect(result.mode).toBe('chain');
    expect(result.signers).toHaveLength(2);
    expect(result.valid).toBe(true);
  });

  it('chai-exts-kid verifies, including the optional second-signer extension', async () => {
    const env = read('p256#es256,r2048#rs256@chai-exts-kid.json');
    const p256 = publicJwkFromPrivate(readJwk('p256privatekey.jwk'));
    const r2048 = publicJwkFromPrivate(readJwk('r2048privatekey.jwk'));
    const result = await verify(env, {
      publicKeys: new Map<number, KeyInput>([
        [0, p256],
        [1, r2048],
      ]),
    });
    expect(result.valid).toBe(true);
    expect(result.extensions).toEqual([
      'otherExt',
      'https://example.com/extension',
    ]);
    // Per the spec note, signer 1 has only one of the two declared
    // extension property values.
    expect(result.signers[0]?.extensionValues).toEqual({
      otherExt: 'Cool Stuff',
      'https://example.com/extension': { 'life-is-great': true },
    });
    expect(result.signers[1]?.extensionValues).toEqual({
      otherExt: 'Other Data',
    });
  });
});
