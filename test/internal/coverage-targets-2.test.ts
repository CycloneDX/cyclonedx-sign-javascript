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
 * Round 2 of coverage-driven tests, focused on JSS sign / verify
 * branches that the round-1 file did not reach.
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');
const WEBPKI = join(FIXTURES, 'jsf', 'interop', 'webpki');

function readTextFixture(file: string): string {
  return readFileSync(join(WEBPKI, file), 'utf8');
}

// ---------------------------------------------------------------------------
// JSS verify with embedded public_cert_chain
// ---------------------------------------------------------------------------

describe('jss/sign.ts: verify with public_cert_chain', () => {
  it('verifies a JSS envelope whose public_cert_chain leaf cert encodes the signing key', async () => {
    const { sign, verify } = await import('../../src/jss/index.js');
    // Use the WebPKI P-256 cert chain — the fixture's leaf cert
    // matches the signing private key. Sign a small payload with that
    // private key, then attach the cert chain to the signaturecore so
    // verify() resolves through the cert path rather than embedded
    // public_key.
    const privPem = readTextFixture('p256privatekey.pem');
    const certPem = readTextFixture('p256certpath.pem');
    const certBlocks = certPem
      .split(/-----BEGIN CERTIFICATE-----/)
      .filter((b) => b.includes('-----END CERTIFICATE-----'))
      .map((b) => b.replace(/-----END CERTIFICATE-----[\s\S]*$/, '').replace(/\s+/g, ''));

    const signed = await sign({ x: 1 } as never, {
      signer: {
        algorithm: 'ES256',
        privateKey: privPem,
        public_key: false,
        public_cert_chain: certBlocks,
      },
    });
    // Verify should succeed by using the leaf cert's public key.
    const result = await verify(signed);
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// JSS sign / verify edge paths
// ---------------------------------------------------------------------------

describe('jss/sign.ts: edge paths', () => {
  it('sign rejects a non-object payload', async () => {
    const { sign } = await import('../../src/jss/index.js');
    await expect(sign(null as never, { signer: { algorithm: 'Ed25519' } } as never))
      .rejects.toThrow(/JSS sign requires/);
  });

  it('verify rejects a non-object payload', async () => {
    const { verify } = await import('../../src/jss/index.js');
    await expect(verify('string' as never)).rejects.toThrow(/JSS verify requires/);
  });

  it('countersign rejects a non-object payload', async () => {
    const { countersign } = await import('../../src/jss/index.js');
    await expect(countersign('string' as never, { signer: { algorithm: 'Ed25519' } } as never))
      .rejects.toThrow(/JSS countersign requires/);
  });

  it('countersign rejects when signer option is missing', async () => {
    const { countersign } = await import('../../src/jss/index.js');
    await expect(countersign({ x: 1 } as never, {} as never))
      .rejects.toThrow(/options\.signer/);
  });

  it('sign throws when signers array is empty', async () => {
    const { sign } = await import('../../src/jss/index.js');
    await expect(sign({ x: 1 } as never, { signers: [] } as never))
      .rejects.toThrow();
  });

  it('sign rejects providing both signer and signers', async () => {
    const { sign } = await import('../../src/jss/index.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    await expect(sign({ x: 1 } as never, {
      signer: { algorithm: 'Ed25519', privateKey: pem },
      signers: [{ algorithm: 'Ed25519', privateKey: pem }],
    } as never)).rejects.toThrow();
  });

  it('sign appends to an existing signatures array', async () => {
    const { sign } = await import('../../src/jss/index.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const first = await sign({ x: 1 } as never, {
      signer: { algorithm: 'Ed25519', privateKey: pem, public_key: 'auto' },
    });
    const second = await sign(first, {
      signer: { algorithm: 'Ed25519', privateKey: pem, public_key: 'auto' },
    });
    expect((second.signatures as unknown[]).length).toBe(2);
  });

  it('extractExisting rejects a non-array signature property', async () => {
    const { sign } = await import('../../src/jss/index.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    await expect(sign({ x: 1, signatures: 'oops' } as never, {
      signer: { algorithm: 'Ed25519', privateKey: pem, public_key: 'auto' },
    })).rejects.toThrow(/must be an array/);
  });

  it('extractExisting rejects an array element that is not an object', async () => {
    const { sign } = await import('../../src/jss/index.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    await expect(sign({ x: 1, signatures: ['nope'] } as never, {
      signer: { algorithm: 'Ed25519', privateKey: pem, public_key: 'auto' },
    })).rejects.toThrow(/not an object/);
  });
});

// ---------------------------------------------------------------------------
// JSS verify with missing / malformed signaturecore fields
// ---------------------------------------------------------------------------

describe('jss/sign.ts: verify with malformed signaturecores', () => {
  it('verify reports per-signer error when value is missing', async () => {
    const { verify } = await import('../../src/jss/index.js');
    const env = {
      x: 1,
      signatures: [{
        algorithm: 'Ed25519',
        hash_algorithm: 'sha-256',
      }],
    };
    const r = await verify(env as never);
    expect(r.valid).toBe(false);
    expect(r.signers[0]?.errors.join(' ')).toMatch(/missing value/);
  });

  it('verify reports per-signer error when value is malformed base64url', async () => {
    const { verify } = await import('../../src/jss/index.js');
    const env = {
      x: 1,
      signatures: [{
        algorithm: 'Ed25519',
        hash_algorithm: 'sha-256',
        public_key: 'AA',
        value: '!!!not base64url!!!',
      }],
    };
    const r = await verify(env as never);
    expect(r.valid).toBe(false);
  });

  it('verify reports per-signer error when algorithm is unknown', async () => {
    const { verify } = await import('../../src/jss/index.js');
    const env = {
      x: 1,
      signatures: [{
        algorithm: 'NOPE',
        hash_algorithm: 'sha-256',
        public_key: 'AA',
        value: 'AA',
      }],
    };
    const r = await verify(env as never);
    expect(r.valid).toBe(false);
    expect(r.signers[0]?.errors.join(' ')).toMatch(/unsupported algorithm/);
  });

  it('verify reports per-signer error when hash_algorithm is unknown', async () => {
    const { verify } = await import('../../src/jss/index.js');
    const env = {
      x: 1,
      signatures: [{
        algorithm: 'Ed25519',
        hash_algorithm: 'sha3-256',
        public_key: 'AA',
        value: 'AA',
      }],
    };
    const r = await verify(env as never);
    expect(r.valid).toBe(false);
  });

  it('verify rejects an envelope whose signatures slot is missing entirely', async () => {
    const { verify } = await import('../../src/jss/index.js');
    await expect(verify({ x: 1 } as never)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// JSS sign options coverage: requireEmbeddedKeyMaterial, allowedAlgorithms
// ---------------------------------------------------------------------------

describe('jss/sign.ts: verify with allowlists', () => {
  it('verify rejects when signer algorithm is not on allowedAlgorithms', async () => {
    const { sign, verify } = await import('../../src/jss/index.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const signed = await sign({ x: 1 } as never, {
      signer: { algorithm: 'Ed25519', privateKey: pem, public_key: 'auto' },
    });
    const r = await verify(signed, { allowedAlgorithms: ['ES256'] } as never);
    expect(r.valid).toBe(false);
    expect(r.signers[0]?.errors.join(' ')).toMatch(/allow-list/);
  });

  it('verify rejects when hash is not on allowedHashAlgorithms', async () => {
    const { sign, verify } = await import('../../src/jss/index.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const signed = await sign({ x: 1 } as never, {
      signer: { algorithm: 'Ed25519', privateKey: pem, public_key: 'auto' },
    });
    const r = await verify(signed, { allowedHashAlgorithms: ['sha-512'] } as never);
    expect(r.valid).toBe(false);
  });

  it('verify rejects when no embedded key material and requireEmbeddedKeyMaterial is set', async () => {
    // JSS § 6.2.1 forbids signing without at least one key-id field;
    // bypass that constraint by hand-crafting an envelope where the
    // sign-side embedded data has been stripped after the fact.
    const { sign, verify } = await import('../../src/jss/index.js');
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const pubPem  = publicKey.export({ format: 'pem',  type: 'spki'  }).toString();
    const signed = await sign({ x: 1 } as never, {
      signer: { algorithm: 'Ed25519', privateKey: privPem, public_key: 'auto' },
    });
    // Strip the embedded key material so the descriptor has none of
    // the four key-id fields populated when verify runs.
    const stripped = JSON.parse(JSON.stringify(signed)) as { signatures: Record<string, unknown>[] };
    delete stripped.signatures[0]!.public_key;
    const r = await verify(stripped as never, {
      publicKey: pubPem,
      requireEmbeddedKeyMaterial: true,
    } as never);
    expect(r.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// JSS verify policies
// ---------------------------------------------------------------------------

describe('jss/sign.ts: verify policy', () => {
  it('atLeast policy passes when threshold met', async () => {
    const { sign, verify } = await import('../../src/jss/index.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    let env = await sign({ x: 1 } as never, {
      signer: { algorithm: 'Ed25519', privateKey: pem, public_key: 'auto' },
    });
    env = await sign(env, {
      signer: { algorithm: 'Ed25519', privateKey: pem, public_key: 'auto' },
    });
    const r = await verify(env, { policy: { atLeast: 2 } } as never);
    expect(r.valid).toBe(true);
  });

  it('any policy passes when at least one signer is valid', async () => {
    const { sign, verify } = await import('../../src/jss/index.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const env = await sign({ x: 1 } as never, {
      signer: { algorithm: 'Ed25519', privateKey: pem, public_key: 'auto' },
    });
    const r = await verify(env, { policy: 'any' } as never);
    expect(r.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// JSS computeCanonicalInputs helper
// ---------------------------------------------------------------------------

describe('jss/sign.ts: computeCanonicalInputs', () => {
  it('throws when signers is empty', async () => {
    // computeCanonicalInputs requires the caller to supply state with
    // at least one signer; assert the error path.
    const { computeCanonicalInputs } = await import('../../src/jss/sign.js');
    expect(() => computeCanonicalInputs({ x: 1 } as never, [] as never))
      .toThrow();
  });
});

// ---------------------------------------------------------------------------
// JSS verifyCounterSignatures branch
// ---------------------------------------------------------------------------

describe('jss/sign.ts: verifyCounterSignatures option', () => {
  it('reports countersignature.valid in the result', async () => {
    const { sign, verify, countersign } = await import('../../src/jss/index.js');
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const pubPem  = publicKey.export({ format: 'pem',  type: 'spki'  }).toString();
    const signed = await sign({ x: 1 } as never, {
      signer: { algorithm: 'Ed25519', privateKey: privPem, public_key: 'auto' },
    });
    const cs = await countersign(signed, {
      signer: { algorithm: 'Ed25519', privateKey: privPem, public_key: 'auto' },
      publicKeys: new Map([[0, pubPem]]),
    });
    const r = await verify(cs, { verifyCounterSignatures: true } as never);
    expect(r.signers[0]?.countersignature?.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// JSF orchestrate verifier failure paths
// ---------------------------------------------------------------------------

describe('jsf/orchestrate.ts: verifier construction failure path', () => {
  it('verify throws when no public key is available', async () => {
    const { verify } = await import('../../src/jsf/index.js');
    const env = {
      x: 1,
      signature: { algorithm: 'ES256', value: 'aa' },     // no embedded key, no caller key
    };
    await expect(verify(env as never)).rejects.toThrow(/public key/);
  });

  it('verify reports per-signer error when descriptor.value is empty', async () => {
    const { verify } = await import('../../src/jsf/index.js');
    const env = {
      x: 1,
      signature: { algorithm: 'ES256', value: '' },
    };
    const r = await verify(env as never);
    expect(r.valid).toBe(false);
  });
});
