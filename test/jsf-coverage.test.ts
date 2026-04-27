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
 * Targeted gap-fill tests for JSF coverage.
 *
 * Each block here covers a code path that the existing suites
 * (jsf.test.ts, multi-chain.test.ts, extensions.test.ts,
 * allowlists-and-property-validation.test.ts, fixtures.test.ts) do
 * not exercise directly. Comments link back to the JSF clause or
 * implementation file the test pins down.
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPairSync,
  createSecretKey,
  randomBytes,
  type KeyObject,
} from 'node:crypto';

import {
  sign,
  verify,
  appendChainSigner,
  appendMultiSigner,
  computeCanonicalInputs,
  isAsymmetricAlgorithm,
  JSF_ASYMMETRIC_ALGORITHMS,
} from '../src/jsf/index.js';
import { JsfEnvelopeError, JsfInputError } from '../src/errors.js';
import type { JsonObject, JsonValue } from '../src/types.js';
import { ecPair, rsaPair, type KeyPair } from './helpers.js';

// --- 1. HMAC in multi and chain modes ----------------------------------

describe('HMAC in multi / chain', () => {
  it('multi: two HMAC signers (different secrets) verify with the publicKeys override', async () => {
    const a = createSecretKey(randomBytes(32));
    const b = createSecretKey(randomBytes(32));
    const signed = await sign({ subject: 'mac' }, {
      signers: [
        { algorithm: 'HS256', privateKey: a },
        { algorithm: 'HS256', privateKey: b },
      ],
      mode: 'multi',
    });
    const r = await verify(signed, {
      publicKeys: new Map([[0, a], [1, b]]),
    });
    expect(r.valid).toBe(true);
  });

  it('chain: HS256 + ES256 mixed signers', async () => {
    const a = createSecretKey(randomBytes(32));
    const b = ecPair();
    const signed = await sign({ subject: 'mix' }, {
      signers: [
        { algorithm: 'HS256', privateKey: a },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'chain',
    });
    const r = await verify(signed, {
      publicKeys: new Map([[0, a]]), // signer 1's key is embedded
    });
    expect(r.valid).toBe(true);
  });
});

// --- 2. Extension value types -----------------------------------------

describe('extension value type matrix', () => {
  it.each([
    ['string', 'hello'],
    ['number', 42],
    ['number-zero', 0],
    ['boolean-true', true],
    ['boolean-false', false],
    ['null', null],
    ['nested-object', { a: { b: 1 } }],
    ['array-of-strings', ['x', 'y']],
    ['mixed-array', [1, 'two', { three: 3 }, null, true]],
  ] as Array<[string, JsonValue]>)('round-trips %s extension value', async (_, value) => {
    const { privateKey } = ecPair();
    const signed = await sign({ a: 1 }, {
      signer: {
        algorithm: 'ES256',
        privateKey,
        extensionValues: { v: value as JsonValue },
      },
    });
    const r = await verify(signed);
    expect(r.valid).toBe(true);
    expect(r.signers[0]?.extensionValues?.v).toEqual(value);
  });
});

// --- 3. extensions list order is signed --------------------------------

describe('extensions list order is signed', () => {
  it('reordering the wrapper-level extensions list post-sign breaks verify', async () => {
    const { privateKey } = ecPair();
    const signed = await sign({ a: 1 }, {
      signer: {
        algorithm: 'ES256',
        privateKey,
        extensionValues: { ext1: 'a', ext2: 'b' },
      },
    });
    // The extensions list lives inside the signaturecore for single mode.
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const sig = wire.signature as { extensions: string[] };
    sig.extensions = sig.extensions.slice().reverse();
    const r = await verify(wire);
    expect(r.valid).toBe(false);
  });
});

// --- 4. Custom signatureProperty for multi and chain ------------------

describe('custom signatureProperty for multi / chain', () => {
  it('multi under jsfSignature property', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign({ a: 1 }, {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'multi',
      signatureProperty: 'jsfSignature',
    });
    expect(signed.signature).toBeUndefined();
    expect(Array.isArray((signed.jsfSignature as { signers: unknown[] }).signers)).toBe(true);
    const r = await verify(signed, { signatureProperty: 'jsfSignature' });
    expect(r.valid).toBe(true);
  });

  it('chain under custom property name; appendChainSigner respects it', async () => {
    const a = ecPair();
    const b = ecPair();
    const initial = await sign({ a: 1 }, {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'chain',
      signatureProperty: 'attestation',
    });
    const grown = await appendChainSigner(
      initial,
      { algorithm: 'ES256', privateKey: b.privateKey },
      { signatureProperty: 'attestation', publicKeys: new Map([[0, a.publicKey]]) },
    );
    const r = await verify(grown, { signatureProperty: 'attestation' });
    expect(r.valid).toBe(true);
    expect(r.signers).toHaveLength(2);
  });
});

// --- 5. computeCanonicalInputs for multi and chain --------------------

describe('computeCanonicalInputs for multi and chain', () => {
  it('multi mode: returns one byte sequence per signer', () => {
    const inputs = computeCanonicalInputs({ a: 1 }, {
      mode: 'multi',
      signers: [
        { algorithm: 'ES256' },
        { algorithm: 'RS256' },
      ],
      finalized: [false, false],
    });
    expect(inputs).toHaveLength(2);
    const s0 = new TextDecoder().decode(inputs[0]);
    const s1 = new TextDecoder().decode(inputs[1]);
    // In multi mode each canonical form contains ONLY that signer.
    expect(s0).toContain('"signers":[{"algorithm":"ES256"}]');
    expect(s1).toContain('"signers":[{"algorithm":"RS256"}]');
  });

  it('chain mode: signer i sees lower-order full + itself stripped', () => {
    const inputs = computeCanonicalInputs({ a: 1 }, {
      mode: 'chain',
      signers: [
        { algorithm: 'ES256', value: 'AAAA' } as never,
        { algorithm: 'RS256' },
      ],
      finalized: [true, false],
    });
    expect(inputs).toHaveLength(2);
    const s1 = new TextDecoder().decode(inputs[1]);
    // signer 1's canonical form contains signer 0 IN FULL (with value)
    // followed by signer 1 minus value.
    expect(s1).toContain('"value":"AAAA"');
    expect(s1).toContain('{"algorithm":"RS256"}');
  });
});

// --- 6. Tamper signaturecore metadata in multi / chain ----------------

describe('tamper signaturecore metadata in multi / chain', () => {
  it('multi: tampering keyId on a signer fails its verification', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign({ a: 1 }, {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey, keyId: 'a' },
        { algorithm: 'ES256', privateKey: b.privateKey, keyId: 'b' },
      ],
      mode: 'multi',
    });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const arr = (wire.signature as { signers: { keyId: string }[] }).signers;
    arr[0]!.keyId = 'mallory';
    const r = await verify(wire);
    expect(r.signers[0]?.valid).toBe(false);
  });

  it('chain: tampering certificatePath on signer 0 fails signer 0 AND signer 1', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign({ a: 1 }, {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey, certificatePath: ['B64-CERT-1'] },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'chain',
    });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const arr = (wire.signature as { chain: { certificatePath: string[] }[] }).chain;
    arr[0]!.certificatePath = ['B64-CERT-DIFFERENT'];
    const r = await verify(wire);
    expect(r.signers[0]?.valid).toBe(false);
    expect(r.signers[1]?.valid).toBe(false);
  });

  it('chain: swapping publicKey on signer 0 with a different valid key fails signer 0 AND signer 1', async () => {
    const a = ecPair();
    const b = ecPair();
    const c = ecPair(); // valid JWK we will swap in
    const signed = await sign({ a: 1 }, {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'chain',
    });
    // Swap signer 0's embedded publicKey with c's. The JWK is valid
    // (parses and is on-curve) so verify proceeds to crypto check.
    // Both fail: signer 0 because the value was signed by a but the
    // verifier is now told to use c; signer 1 because the prior
    // signer's canonical form changed.
    const cJwk = c.publicKey.export({ format: 'jwk' });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const arr = (wire.signature as { chain: { publicKey: unknown }[] }).chain;
    arr[0]!.publicKey = cJwk;
    const r = await verify(wire);
    expect(r.signers[0]?.valid).toBe(false);
    expect(r.signers[1]?.valid).toBe(false);
  });
});

// --- 7. Mixed wrapper / empty wrappers --------------------------------

describe('illegal wrapper shapes', () => {
  it('rejects empty signers array on detect', async () => {
    const env: JsonObject = { a: 1, signature: { signers: [] } };
    await expect(verify(env)).rejects.toThrow(JsfEnvelopeError);
  });

  it('rejects empty chain array on detect', async () => {
    const env: JsonObject = { a: 1, signature: { chain: [] } };
    await expect(verify(env)).rejects.toThrow(JsfEnvelopeError);
  });

  it('wrapper with both signers and chain: signers wins; JSF § 6 rejects the unknown chain key', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign({ a: 1 }, {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'multi',
    });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    (wire.signature as Record<string, unknown>).chain = [];
    const r = await verify(wire);
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/chain/);
  });
});

// --- 8. requireEmbeddedPublicKey in multi / chain ---------------------

describe('requireEmbeddedPublicKey in multi / chain', () => {
  it('multi: rejects when one signer omitted its publicKey', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign({ a: 1 }, {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey, publicKey: false, keyId: 'b' },
      ],
      mode: 'multi',
    });
    const r = await verify(signed, {
      requireEmbeddedPublicKey: true,
      publicKeys: new Map([[1, b.publicKey]]),
    });
    expect(r.valid).toBe(false);
    expect(r.signers[1]?.errors.join(' ')).toMatch(/embedded publicKey/);
  });
});

// --- 9. JSF_ASYMMETRIC_ALGORITHMS guard --------------------------------

describe('JSF_ASYMMETRIC_ALGORITHMS guard', () => {
  it('lists every asymmetric algorithm and excludes HMAC', () => {
    const expected = [
      'RS256','RS384','RS512',
      'PS256','PS384','PS512',
      'ES256','ES384','ES512',
      'Ed25519','Ed448',
    ];
    expect([...JSF_ASYMMETRIC_ALGORITHMS]).toEqual(expected);
    for (const alg of expected) {
      expect(isAsymmetricAlgorithm(alg)).toBe(true);
    }
    for (const alg of ['HS256', 'HS384', 'HS512']) {
      expect(isAsymmetricAlgorithm(alg)).toBe(false);
    }
    expect(isAsymmetricAlgorithm('BOGUS')).toBe(false);
  });
});

// --- 10. Append with publicKeys override map --------------------------

describe('append with publicKeys override map', () => {
  it('appendChainSigner verifies signer 0 with provided publicKey when not embedded', async () => {
    const a = ecPair();
    const b = ecPair();
    // signer 0 with publicKey: false plus keyId
    const initial = await sign({ a: 1 }, {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey, publicKey: false, keyId: 'a' }],
      mode: 'chain',
    });
    // Without publicKeys override, append's verify-first defense fails.
    await expect(
      appendChainSigner(initial, { algorithm: 'ES256', privateKey: b.privateKey }),
    ).rejects.toThrow();
    // With publicKeys override the verify-first succeeds and append proceeds.
    const grown = await appendChainSigner(
      initial,
      { algorithm: 'ES256', privateKey: b.privateKey },
      { publicKeys: new Map([[0, a.publicKey]]) },
    );
    const r = await verify(grown, {
      publicKeys: new Map([[0, a.publicKey]]),
    });
    expect(r.valid).toBe(true);
  });

  it('appendMultiSigner with publicKeys override', async () => {
    const a = ecPair();
    const b = ecPair();
    const initial = await sign({ a: 1 }, {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey, publicKey: false, keyId: 'a' }],
      mode: 'multi',
    });
    const both = await appendMultiSigner(
      initial,
      { algorithm: 'ES256', privateKey: b.privateKey },
      { publicKeys: new Map([[0, a.publicKey]]) },
    );
    const r = await verify(both, {
      publicKeys: new Map([[0, a.publicKey]]),
    });
    expect(r.valid).toBe(true);
  });
});

// --- 11. Multi / chain with excludes and tampered excluded field ------

describe('excludes in multi / chain', () => {
  it('multi: excluded field can change without breaking verification', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign({ a: 1, t: 'x' }, {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'multi',
      excludes: ['t'],
    });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    wire.t = 'changed';
    const r = await verify(wire);
    expect(r.valid).toBe(true);
  });

  it('chain: tampering a NON-excluded payload field breaks all signers', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign({ a: 1, body: 'pristine', t: 'x' }, {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'chain',
      excludes: ['t'],
    });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    wire.body = 'tampered';
    const r = await verify(wire);
    expect(r.signers[0]?.valid).toBe(false);
    expect(r.signers[1]?.valid).toBe(false);
  });
});

// --- 12. Misc input-validation gaps -----------------------------------

describe('miscellaneous input validation', () => {
  it('rejects non-string algorithm at parse time', async () => {
    await expect(
      verify({ signature: { algorithm: 42, value: 'x' } } as unknown as JsonObject),
    ).rejects.toThrow(JsfEnvelopeError);
  });

  it('rejects malformed signers array element (not an object)', async () => {
    await expect(
      verify({ signature: { signers: ['oops'] } } as unknown as JsonObject),
    ).rejects.toThrow(JsfEnvelopeError);
  });

  it('rejects when payload is null', async () => {
    const { privateKey } = rsaPair();
    await expect(
      sign(null as unknown as JsonObject, { signer: { algorithm: 'RS256', privateKey } }),
    ).rejects.toThrow(JsfInputError);
  });
});
