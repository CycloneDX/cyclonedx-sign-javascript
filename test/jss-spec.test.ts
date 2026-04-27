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
 * JSS conformance tests against the ITU-T X.590 (10/2023) worked
 * examples and Appendix II reference key.
 *
 * Per the user's constraint, the spec is the only authoritative test
 * material available. We therefore anchor against:
 *
 *   - Clause 7.1.4 canonical bytes (exact match).
 *   - Clause 7.1.5 SHA-256 hex (exact match).
 *   - Clause 7.2.4 counter canonical bytes (exact match).
 *   - Clause 7.2.5 counter SHA-256 hex (exact match).
 *   - Appendix II.1 / II.2 keys for round trip sign + verify.
 *
 * The spec's published values in clauses 7.1.6 and 7.2.6 do NOT
 * verify against the Appendix II public key (independently confirmed
 * with Node crypto, also confirmed by the dotnet-jss source comment).
 * This is a known erratum in the X.590 published text. We commit the
 * fixtures verbatim and add an EXPECTED-FAIL test so a future spec
 * revision that fixes the erratum is caught automatically.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createHash,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto';

import { canonicalize } from '../src/jcs.js';
import { sign, verify, countersign } from '../src/jss/index.js';
import { JssEnvelopeError, JssInputError } from '../src/errors.js';
import type { JsonObject } from '../src/types.js';
import { edPair, rsaPair, type KeyPair } from './helpers.js';
const HERE = dirname(fileURLToPath(import.meta.url));
const SPEC = join(HERE, 'fixtures', 'jss', 'spec');

const SPEC_PUB_PEM = readFileSync(join(SPEC, 'appendix-ii-public-key.pem'), 'utf8');
const SPEC_PRIV_PEM = readFileSync(join(SPEC, 'appendix-ii-private-key.pem'), 'utf8');
const SPEC_PUB_BODY = SPEC_PUB_PEM
  .replace(/-----[^-]+-----/g, '')
  .replace(/\s+/g, '')
  .replace(/=+$/, '');

describe('JSS § 7.1: signing operation', () => {
  it('clause 7.1.4 canonical bytes match the spec exactly', () => {
    const expected = readFileSync(join(SPEC, 'clause-7.1.4-canonical.txt'), 'utf8').trimEnd();
    const doc: JsonObject = {
      statement: 'Hello signed world!',
      otherProperties: ['home', 'food'],
      signatures: [{
        algorithm: 'Ed25519',
        hash_algorithm: 'sha-256',
        public_key: SPEC_PUB_BODY,
      }],
    };
    const text = new TextDecoder().decode(canonicalize(doc));
    expect(text).toBe(expected);
  });

  it('clause 7.1.5 SHA-256 hex matches the spec exactly', () => {
    const expectedHex = readFileSync(join(SPEC, 'clause-7.1.5-hash.hex'), 'utf8').trim();
    const canonical = readFileSync(join(SPEC, 'clause-7.1.4-canonical.txt'), 'utf8').trimEnd();
    const hex = createHash('sha256').update(canonical, 'utf8').digest('hex');
    expect(hex).toBe(expectedHex);
  });

  it('round trip with Appendix II key: signs and verifies', async () => {
    const payload: JsonObject = {
      statement: 'Hello signed world!',
      otherProperties: ['home', 'food'],
    };
    const signed = await sign(payload, {
      signer: {
        algorithm: 'Ed25519',
        hash_algorithm: 'sha-256',
        privateKey: SPEC_PRIV_PEM,
        public_key: 'auto',
      },
    });
    const sig = signed.signatures as { algorithm: string; hash_algorithm: string; public_key: string; value: string }[];
    expect(sig).toHaveLength(1);
    expect(sig[0]?.public_key).toBe(SPEC_PUB_BODY);
    const result = await verify(signed);
    expect(result.valid).toBe(true);
  });

  it('Ed25519 is deterministic: identical signatures for identical inputs', async () => {
    const payload: JsonObject = { a: 1 };
    const a = await sign(payload, { signer: { algorithm: 'Ed25519', privateKey: SPEC_PRIV_PEM, public_key: 'auto' } });
    const b = await sign(payload, { signer: { algorithm: 'Ed25519', privateKey: SPEC_PRIV_PEM, public_key: 'auto' } });
    const av = (a.signatures as { value: string }[])[0]?.value;
    const bv = (b.signatures as { value: string }[])[0]?.value;
    expect(av).toBe(bv);
  });
});

describe('JSS § 7.2: counter signing operation', () => {
  it('clause 7.2.4 counter canonical bytes match the spec exactly', () => {
    const expected = readFileSync(join(SPEC, 'clause-7.2.4-canonical.txt'), 'utf8').trimEnd();
    const doc: JsonObject = {
      statement: 'Hello signed world!',
      otherProperties: ['home', 'food'],
      signatures: [{
        algorithm: '-- some signing algorithm --',
        hash_algorithm: '-- some hashing algorithm --',
        public_key: '-- some public key --',
        signature: {
          algorithm: 'Ed25519',
          hash_algorithm: 'sha-256',
          public_key: SPEC_PUB_BODY,
        },
        value: '-- some existing digital signature --',
      }],
    };
    const text = new TextDecoder().decode(canonicalize(doc));
    expect(text).toBe(expected);
  });

  it('clause 7.2.5 counter SHA-256 hex matches the spec exactly', () => {
    const expectedHex = readFileSync(join(SPEC, 'clause-7.2.5-hash.hex'), 'utf8').trim();
    const canonical = readFileSync(join(SPEC, 'clause-7.2.4-canonical.txt'), 'utf8').trimEnd();
    const hex = createHash('sha256').update(canonical, 'utf8').digest('hex');
    expect(hex).toBe(expectedHex);
  });

  it('round trip counter sign with the Appendix II key', async () => {
    const payload: JsonObject = { statement: 'Hello signed world!', otherProperties: ['home', 'food'] };
    const signed = await sign(payload, {
      signer: { algorithm: 'Ed25519', privateKey: SPEC_PRIV_PEM, public_key: 'auto' },
    });
    const cs = await countersign(signed, {
      signer: { algorithm: 'Ed25519', privateKey: SPEC_PRIV_PEM, public_key: 'auto' },
      publicKeys: new Map([[0, SPEC_PUB_PEM]]),
    });
    const top = await verify(cs);
    expect(top.valid).toBe(true);
    const both = await verify(cs, { verifyCounterSignatures: true });
    expect(both.valid).toBe(true);
    expect(both.signers[0]?.countersignature?.valid).toBe(true);
  });
});

describe('JSS spec erratum: clause 7.1.6 / 7.2.6 published values', () => {
  it('clause 8.1.1 fixture envelope (containing the published 7.1.6 value) does NOT verify against the Appendix II public key', async () => {
    // Independently confirmed: the spec-published Ed25519 signature
    // values do not verify with the Appendix II key. dotnet-jss
    // reaches the same conclusion. This is an erratum in the X.590
    // text; both this library and dotnet-jss are correct.
    const env = JSON.parse(readFileSync(join(SPEC, 'clause-8.1.1-signed.json'), 'utf8')) as JsonObject;
    const result = await verify(env);
    expect(result.valid).toBe(false);
  });
});

describe('JSS algorithms', () => {
  it.each(['Ed25519', 'Ed448', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'] as const)(
    '%s round trip',
    async (algorithm) => {
      const key = algorithm.startsWith('Ed')
        ? edPair(algorithm.toLowerCase() as 'ed25519' | 'ed448').privateKey
        : rsaPair().privateKey;
      const signed = await sign({ subject: `rt-${algorithm}` }, {
        signer: { algorithm, privateKey: key, public_key: 'auto' },
      });
      const r = await verify(signed);
      expect(r.valid).toBe(true);
      expect(r.signers[0]?.algorithm).toBe(algorithm);
    },
  );

  it.each([
    ['ES256', 'prime256v1', 'sha-256', 64],
    ['ES384', 'secp384r1', 'sha-384', 96],
    ['ES512', 'secp521r1', 'sha-512', 132],
  ] as const)('%s round trip (signature length %i bytes)', async (algorithm, curve, hash, sigBytes) => {
    const key = generateKeyPairSync('ec', { namedCurve: curve }) as unknown as KeyPair;
    const signed = await sign({ subject: `rt-${algorithm}` }, {
      signer: { algorithm, hash_algorithm: hash, privateKey: key.privateKey, public_key: 'auto' },
    });
    const r = await verify(signed);
    expect(r.valid).toBe(true);
    expect(r.signers[0]?.algorithm).toBe(algorithm);
    // IEEE P-1363 (r || s) per JWA RFC 7518 § 3.4.
    const value = (signed.signatures as { value: string }[])[0]?.value ?? '';
    const padded = value.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - (padded.length % 4)) % 4;
    const decoded = Buffer.from(padded + '='.repeat(pad), 'base64');
    expect(decoded.length).toBe(sigBytes);
  });
});

describe('JSS multi-signature (X.590 § 7.1, independent semantics)', () => {
  it('two signers in the array, both verify', async () => {
    const a = edPair('ed25519');
    const b = rsaPair();
    const signed = await sign({ subject: 'multi' }, {
      signers: [
        { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
        { algorithm: 'RS256', privateKey: b.privateKey, public_key: 'auto' },
      ],
    });
    expect((signed.signatures as unknown[]).length).toBe(2);
    const r = await verify(signed);
    expect(r.valid).toBe(true);
  });

  it('tamper signer 0 fails ONLY signer 0 (independent, not chained)', async () => {
    const a = edPair('ed25519');
    const b = edPair('ed25519');
    const signed = await sign({ subject: 'multi' }, {
      signers: [
        { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
        { algorithm: 'Ed25519', privateKey: b.privateKey, public_key: 'auto' },
      ],
    });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const arr = (wire.signatures as { value: string }[]);
    const v = arr[0]!.value;
    arr[0]!.value = (v.startsWith('A') ? 'B' : 'A') + v.slice(1);
    const r = await verify(wire);
    expect(r.valid).toBe(false);
    expect(r.signers[0]?.valid).toBe(false);
    expect(r.signers[1]?.valid).toBe(true);
  });

  it('policy any accepts when one signer fails', async () => {
    const a = edPair('ed25519');
    const b = edPair('ed25519');
    const signed = await sign({ subject: 'm' }, {
      signers: [
        { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
        { algorithm: 'Ed25519', privateKey: b.privateKey, public_key: 'auto' },
      ],
    });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    (wire.signatures as { value: string }[])[0]!.value = 'AAAA';
    expect((await verify(wire)).valid).toBe(false);
    expect((await verify(wire, { policy: 'any' })).valid).toBe(true);
  });
});

describe('JSS counter signature', () => {
  it('round trip counter sign verifies both layers', async () => {
    const a = edPair('ed25519');
    const b = edPair('ed25519');
    const signed = await sign({ subject: 'cs' }, {
      signer: { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
    });
    const cs = await countersign(signed, {
      signer: { algorithm: 'Ed25519', privateKey: b.privateKey, public_key: 'auto' },
      publicKeys: new Map([[0, a.publicKey]]),
    });
    const top = await verify(cs);
    expect(top.valid).toBe(true);
    const both = await verify(cs, { verifyCounterSignatures: true });
    expect(both.valid).toBe(true);
    expect(both.signers[0]?.countersignature?.valid).toBe(true);
  });

  it('refuses to counter sign a signaturecore that already has a counter signature', async () => {
    const a = edPair('ed25519');
    const b = edPair('ed25519');
    const c = edPair('ed25519');
    const signed = await sign({ subject: 'cs' }, {
      signer: { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
    });
    const cs = await countersign(signed, {
      signer: { algorithm: 'Ed25519', privateKey: b.privateKey, public_key: 'auto' },
      publicKeys: new Map([[0, a.publicKey]]),
    });
    await expect(
      countersign(cs, {
        signer: { algorithm: 'Ed25519', privateKey: c.privateKey, public_key: 'auto' },
        publicKeys: new Map([[0, a.publicKey]]),
      }),
    ).rejects.toThrow(/already has a counter signature/);
  });

  it('refuses tampered prior signer (verify-first defense, CWE-345 / CWE-347)', async () => {
    const a = edPair('ed25519');
    const b = edPair('ed25519');
    const signed = await sign({ subject: 'cs' }, {
      signer: { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
    });
    const tampered = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const arr = tampered.signatures as { value: string }[];
    const v = arr[0]!.value;
    arr[0]!.value = (v.startsWith('A') ? 'B' : 'A') + v.slice(1);
    // Caller passes the genuine signer-0 trusted key; verify-first
    // uses it, sees the tampered value does not match, and refuses.
    await expect(
      countersign(tampered, {
        signer: { algorithm: 'Ed25519', privateKey: b.privateKey, public_key: 'auto' },
        publicKeys: new Map([[0, a.publicKey]]),
      }),
    ).rejects.toThrow(JssEnvelopeError);
  });

  it('refuses to countersign without publicKeys or skipVerifyExisting', async () => {
    const a = edPair('ed25519');
    const b = edPair('ed25519');
    const signed = await sign({ subject: 'cs' }, {
      signer: { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
    });
    await expect(
      countersign(signed, {
        signer: { algorithm: 'Ed25519', privateKey: b.privateKey, public_key: 'auto' },
      }),
    ).rejects.toThrow(/publicKeys|skipVerifyExisting/);
  });

  it('refuses to countersign when an attacker substitutes BOTH value AND embedded public_key', async () => {
    const a = edPair('ed25519');     // legitimate prior signer
    const eve = edPair('ed25519');   // attacker
    const b = edPair('ed25519');     // legitimate counter-signer
    // Attacker builds a fake "signed" envelope with their own keypair
    // and embeds the matching public_key. Embedded-key fallback would
    // have rubber-stamped this; strict mode requires caller-supplied
    // trusted keys and refuses.
    const fake = await sign({ subject: 'cs' }, {
      signer: { algorithm: 'Ed25519', privateKey: eve.privateKey, public_key: 'auto' },
    });
    await expect(
      countersign(fake, {
        signer: { algorithm: 'Ed25519', privateKey: b.privateKey, public_key: 'auto' },
        publicKeys: new Map([[0, a.publicKey]]),
      }),
    ).rejects.toThrow(/did not verify/);
  });

  it('skipVerifyExisting opts out of the verify-first defense', async () => {
    const a = edPair('ed25519');
    const b = edPair('ed25519');
    const signed = await sign({ subject: 'cs' }, {
      signer: { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
    });
    const tampered = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const arr = tampered.signatures as { value: string }[];
    const v = arr[0]!.value;
    arr[0]!.value = (v.startsWith('A') ? 'B' : 'A') + v.slice(1);
    const cs = await countersign(tampered, {
      signer: { algorithm: 'Ed25519', privateKey: b.privateKey, public_key: 'auto' },
      skipVerifyExisting: true,
    });
    // The counter sig itself is valid over the tampered prior; the
    // top-level signer is still tampered.
    const r = await verify(cs);
    expect(r.valid).toBe(false);
  });
});

describe('JSS § 6.3: custom metadata', () => {
  it('custom metadata properties round trip and are part of the canonical form', async () => {
    const a = edPair('ed25519');
    const signed = await sign({ subject: 'meta' }, {
      signer: {
        algorithm: 'Ed25519',
        privateKey: a.privateKey,
        public_key: 'auto',
        metadata: {
          type: 'jss',
          signee: 'Alice',
          created: '2026-04-27T12:00:00Z',
        },
      },
    });
    const arr = signed.signatures as Record<string, unknown>[];
    expect(arr[0]?.type).toBe('jss');
    expect(arr[0]?.signee).toBe('Alice');
    const r = await verify(signed);
    expect(r.valid).toBe(true);
    expect(r.signers[0]?.metadata?.signee).toBe('Alice');
  });

  it('tampering metadata breaks verification (metadata is signed)', async () => {
    const a = edPair('ed25519');
    const signed = await sign({ subject: 'meta' }, {
      signer: {
        algorithm: 'Ed25519',
        privateKey: a.privateKey,
        public_key: 'auto',
        metadata: { signee: 'Alice' },
      },
    });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    (wire.signatures as Record<string, string>[])[0]!.signee = 'Mallory';
    const r = await verify(wire);
    expect(r.valid).toBe(false);
  });
});

describe('JSS § 6.2.1: input validation', () => {
  it('rejects signer with no key identification property', async () => {
    const a = edPair('ed25519');
    await expect(
      sign({ a: 1 }, {
        signer: { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: false },
      }),
    ).rejects.toThrow(JssInputError);
  });

  it('rejects unsupported algorithm', async () => {
    const a = edPair('ed25519');
    await expect(
      sign({ a: 1 }, {
        signer: { algorithm: 'BOGUS' as 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
      }),
    ).rejects.toThrow(/Unsupported JSS algorithm/);
  });

  it('rejects unsupported hash_algorithm', async () => {
    const a = edPair('ed25519');
    await expect(
      sign({ a: 1 }, {
        signer: {
          algorithm: 'Ed25519',
          hash_algorithm: 'bogus' as 'sha-256',
          privateKey: a.privateKey,
          public_key: 'auto',
        },
      }),
    ).rejects.toThrow(/Unsupported JSS hash algorithm/);
  });

  it('rejects empty signers array', async () => {
    await expect(sign({ a: 1 }, { signers: [] })).rejects.toThrow(/at least one signer/);
  });

  it('rejects providing both signer and signers', async () => {
    const a = edPair('ed25519');
    await expect(
      sign({ a: 1 }, {
        signer: { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
        signers: [{ algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' }],
      }),
    ).rejects.toThrow(/either `signer` or `signers`/);
  });
});

describe('JSS verify constraints', () => {
  it('allowedAlgorithms blocks signers not on the list', async () => {
    const a = edPair('ed25519');
    const signed = await sign({ a: 1 }, {
      signer: { algorithm: 'Ed25519', privateKey: a.privateKey, public_key: 'auto' },
    });
    const r = await verify(signed, { allowedAlgorithms: ['RS256'] });
    expect(r.valid).toBe(false);
    expect(r.signers[0]?.errors.join(' ')).toMatch(/not on the allow-list/);
  });

  it('allowedHashAlgorithms blocks signers not on the list', async () => {
    const a = edPair('ed25519');
    const signed = await sign({ a: 1 }, {
      signer: { algorithm: 'Ed25519', hash_algorithm: 'sha-256', privateKey: a.privateKey, public_key: 'auto' },
    });
    const r = await verify(signed, { allowedHashAlgorithms: ['sha-512'] });
    expect(r.valid).toBe(false);
  });

  it('requireEmbeddedKeyMaterial rejects signers with no embedded key', async () => {
    const a = edPair('ed25519');
    const signed = await sign({ a: 1 }, {
      signer: {
        algorithm: 'Ed25519',
        privateKey: a.privateKey,
        public_key: false,
        thumbprint: 'AAAA', // satisfy § 6.2.1 at sign time
      },
    });
    // Strip the thumbprint to simulate an envelope with no key material.
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const arr = wire.signatures as Record<string, unknown>[];
    delete arr[0]!.thumbprint;
    const r = await verify(wire, { requireEmbeddedKeyMaterial: true, publicKey: a.publicKey });
    expect(r.valid).toBe(false);
    expect(r.signers[0]?.errors.join(' ')).toMatch(/embedded key material/);
  });
});
