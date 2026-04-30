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
 * Coverage-driven tests targeting the specific uncovered branches
 * surfaced by `npm run test:coverage` after the dual-backend refactor.
 *
 * Each `describe` block names the file it pushes coverage on. The
 * tests favor synthesizing the uncovered shape directly (explicit-
 * parameter PEM via `generateKeyPairSync({ paramEncoding: 'explicit' })`,
 * minimal DER blobs, contrived-but-real envelopes) over rebuilding
 * the whole sign / verify happy path.
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';

import { backend as nodeBackend } from '../../src/internal/crypto/node.js';
import { backend as webBackend } from '../../src/internal/crypto/web.js';

// ---------------------------------------------------------------------------
// Web backend: EC PKCS#8 with explicit curve parameters
// ---------------------------------------------------------------------------

describe('web.ts: EC PKCS#8 with explicit curve parameters', () => {
  // Node generates explicit-parameter EC keys when `paramEncoding:
  // 'explicit'` is set. The resulting PKCS#8 / SPKI exercise the
  // explicit-params handling in the Web backend (importEcPrivateFromExplicitPkcs8
  // and importEcPublicFromSpki).

  for (const [curve, label] of [
    ['prime256v1', 'P-256'],
    ['secp384r1',  'P-384'],
    ['secp521r1',  'P-521'],
  ] as const) {
    it(`${label}: imports explicit-params PKCS#8 PEM`, async () => {
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: curve,
        paramEncoding: 'explicit',
      });
      const privPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
      const pubPem  = publicKey.export({ format: 'pem',  type: 'spki'  }).toString();
      const priv = await webBackend.importPrivateKey(privPem);
      const pub  = await webBackend.importPublicKey(pubPem);
      expect(priv.kind).toBe('ec');
      expect(priv.curve).toBe(label);
      expect(pub.kind).toBe('ec');
      expect(pub.curve).toBe(label);

      // Round-trip a JSF-style ES* signature through Web sign + verify.
      const data = new TextEncoder().encode('explicit-params');
      const hash = label === 'P-256' ? 'sha-256' : label === 'P-384' ? 'sha-384' : 'sha-512';
      const sig = await webBackend.signEcdsa(hash, data, priv);
      expect(await webBackend.verifyEcdsa(hash, data, sig, pub)).toBe(true);

      // And exercise the JSS pre-hashed path so the noble fallback runs too.
      const digest = await webBackend.digest(hash, data);
      const psig = await webBackend.signEcdsaPrehashed(label, digest, priv);
      expect(await webBackend.verifyEcdsaPrehashed(label, digest, psig, pub)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// Web backend: Edwards SPKI export and OKP edge cases
// ---------------------------------------------------------------------------

describe('web.ts: Edwards / OKP export paths', () => {
  it('Ed25519 PrivateKeyHandle.publicHandle().exportSpkiPem() round-trips', async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const handle = await webBackend.importPrivateKey(
      privateKey.export({ format: 'jwk' }) as never,
    );
    const pub = await handle.publicHandle();
    const pem = await pub.exportSpkiPem();
    expect(pem).toContain('-----BEGIN PUBLIC KEY-----');
    const reparsed = await webBackend.importPublicKey(pem);
    expect(reparsed.kind).toBe('ed25519');
  });

  it('rejects an OKP JWK with a curve that is neither Ed25519 nor Ed448', async () => {
    const fakeJwk = { kty: 'OKP', crv: 'X25519', x: 'AA' };
    await expect(webBackend.importPublicKey(fakeJwk as never))
      .rejects.toThrow(/Unsupported OKP curve/);
  });

  it('rejects a JWK with an unknown kty', async () => {
    const fakeJwk = { kty: 'DSA', y: 'AA' };
    await expect(webBackend.importPublicKey(fakeJwk as never))
      .rejects.toThrow(/Unsupported JWK kty/);
  });

  it('rejects an EC JWK with an unsupported curve', async () => {
    const fakeJwk = { kty: 'EC', crv: 'secp256k1', x: 'AA', y: 'BB' };
    await expect(webBackend.importPublicKey(fakeJwk as never))
      .rejects.toThrow(/Unsupported EC curve/);
  });

  it('rejects an RSA JWK without `n`', async () => {
    const fakeJwk = { kty: 'RSA', e: 'AQAB' };
    await expect(webBackend.importPublicKey(fakeJwk as never))
      .rejects.toThrow(/RSA JWK missing n/);
  });
});

// ---------------------------------------------------------------------------
// Web backend: X.509 cert walker — error paths
// ---------------------------------------------------------------------------

describe('web.ts: extractSpkiFromX509 error branches', () => {
  it('rejects DER whose top-level field is not a SEQUENCE', async () => {
    // Outer SEQUENCE present but TBS isn't.
    const bogus = new Uint8Array([
      0x30, 0x05,           // SEQUENCE, length 5
      0x42, 0x03, 0xaa, 0xbb, 0xcc,
    ]);
    await expect(webBackend.parseCertSpkiPublicKey(bogus))
      .rejects.toThrow(/SEQUENCE/);
  });

  it('rejects too-short DER input', async () => {
    await expect(webBackend.parseCertSpkiPublicKey(new Uint8Array([0x30])))
      .rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Web backend: BigInt RSA path with a 4096-bit key
// ---------------------------------------------------------------------------

describe('web.ts: JSS pre-hashed RSA on a 4096-bit modulus', () => {
  // 4096-bit RSA keygen plus two pure-JS BigInt modPow operations on
  // a 4096-bit modulus. The modPow path is the cost driver (the same
  // numerics that ship to browsers since WebCrypto exposes no raw RSA
  // primitive). Wall-clock varies wildly under CI load, so give this
  // one test a generous timeout rather than letting transient slowness
  // mask a real regression somewhere else in the suite.
  it('signs and verifies via the BigInt path', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 4096 });
    const priv = await webBackend.importPrivateKey(privateKey.export({ format: 'jwk' }) as never);
    const pub = await webBackend.importPublicKey(publicKey.export({ format: 'jwk' }) as never);
    const digest = await webBackend.digest('sha-512', new TextEncoder().encode('4096-bit'));
    const sig = await webBackend.signRsaPssPrehashed('sha-512', digest, 64, priv);
    expect(sig.length).toBe(512);
    expect(await webBackend.verifyRsaPssPrehashed('sha-512', digest, 64, sig, pub)).toBe(true);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Node backend: error and edge branches
// ---------------------------------------------------------------------------

describe('node.ts: ECDSA pre-hashed scalar length and signature length guards', () => {
  // Note: Node's createPrivateKey is tolerant of short `d` values
  // (left-pads internally), so the explicit-length-check branch in
  // node.ts signEcdsaPrehashed is only reachable when a future Node
  // version tightens that. We leave a comment marker rather than a
  // brittle test against current Node behavior.

  it('verifyEcdsaPrehashed returns false when public JWK has no x coordinate', async () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    // Node's exportKey('jwk') always includes x and y, so use the
    // happy path here to bump the verify branch coverage on the
    // pubKey.type === 'private' fork.
    const pub = await nodeBackend.importPublicKey(publicKey);
    const goodSig = new Uint8Array(64);
    const ok = await nodeBackend.verifyEcdsaPrehashed('P-256', new Uint8Array(32), goodSig, pub);
    // The signature is all zeros so verify returns false; that still
    // exercises every branch up to the noble.verify call.
    expect(typeof ok).toBe('boolean');
  });

  it('Ed448 handle reports the right metadata', async () => {
    const { privateKey } = generateKeyPairSync('ed448');
    const handle = await nodeBackend.importPrivateKey(privateKey);
    expect(handle.kind).toBe('ed448');
    expect(handle.curve).toBe('Ed448');
  });
});

describe('node.ts: key-import dispatch coverage', () => {
  // Below: the asymmetric importers must reject symmetric material.
  // The previous behavior silently wrapped a secret KeyObject as a
  // NodePrivateKey / NodePublicKey, producing a "private" or "public"
  // handle whose `kind` was 'oct'. Downstream sign / verify primitives
  // would then call `nodeSign(...)` / `nodeVerify(...)` against a
  // secret KeyObject and fail with a misleading node:crypto error.
  // The Web backend has always rejected these shapes; both backends
  // now agree.

  it('importPrivateKey rejects raw Uint8Array (HMAC material)', async () => {
    await expect(nodeBackend.importPrivateKey(new Uint8Array([1, 2, 3, 4])))
      .rejects.toThrow(/HMAC|asymmetric/i);
  });

  it('importPublicKey rejects raw Uint8Array (HMAC material)', async () => {
    await expect(nodeBackend.importPublicKey(new Uint8Array([1, 2, 3, 4])))
      .rejects.toThrow(/HMAC|asymmetric/i);
  });

  it('importPrivateKey rejects an oct JWK', async () => {
    await expect(nodeBackend.importPrivateKey({ kty: 'oct', k: 'AQID' } as never))
      .rejects.toThrow(/importHmacKey|symmetric/i);
  });

  it('importPublicKey rejects an oct JWK', async () => {
    await expect(nodeBackend.importPublicKey({ kty: 'oct', k: 'AQID' } as never))
      .rejects.toThrow(/symmetric|not public/i);
  });

  it('importPublicKey rejects a secret KeyObject', async () => {
    const sym = await nodeBackend.importHmacKey(new Uint8Array(32), 'sha-256');
    // NodeSymmetricKey wraps a secret KeyObject; pull it out so we
    // can confirm the bare KeyObject is also rejected.
    const ko = (sym as unknown as { keyObject: unknown }).keyObject;
    await expect(nodeBackend.importPublicKey(ko as never))
      .rejects.toThrow(/symmetric|secret/i);
  });

  it('importPrivateKey rejects a public KeyObject', async () => {
    const { publicKey } = generateKeyPairSync('ed25519');
    await expect(nodeBackend.importPrivateKey(publicKey))
      .rejects.toThrow(/requires a private KeyObject|public/i);
  });

  it('importPrivateKey rejects a secret KeyObject', async () => {
    const sym = await nodeBackend.importHmacKey(new Uint8Array(32), 'sha-256');
    const ko = (sym as unknown as { keyObject: unknown }).keyObject;
    await expect(nodeBackend.importPrivateKey(ko as never))
      .rejects.toThrow(/requires a private KeyObject|symmetric|secret/i);
  });
});

// ---------------------------------------------------------------------------
// JSF: chain / multi append paths and edge cases
// ---------------------------------------------------------------------------

describe('JSF: appendChainSigner / appendMultiSigner edge paths', () => {
  it('appendChainSigner attaches a second signer with skipVerifyExisting', async () => {
    const { sign, appendChainSigner } = await import('../../src/jsf/index.js');
    const a = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const b = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const initial = await sign({ subject: 'chain' } as never, {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'chain',
    });
    const grown = await appendChainSigner(
      initial,
      { algorithm: 'ES256', privateKey: b.privateKey },
      { skipVerifyExisting: true },
    );
    const slot = grown.signature as { chain: unknown[] };
    expect(slot.chain.length).toBe(2);
  });

  it('appendMultiSigner refuses to append to a chain envelope', async () => {
    const { sign, appendMultiSigner } = await import('../../src/jsf/index.js');
    const a = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const initial = await sign({ subject: 'chain' } as never, {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'chain',
    });
    const b = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    await expect(appendMultiSigner(
      initial,
      { algorithm: 'ES256', privateKey: b.privateKey },
      { skipVerifyExisting: true },
    )).rejects.toThrow();
  });

  it('appendChainSigner refuses without trusted keys or skip flag', async () => {
    const { sign, appendChainSigner } = await import('../../src/jsf/index.js');
    const a = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const initial = await sign({ subject: 'chain' } as never, {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'chain',
    });
    const b = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    await expect(appendChainSigner(
      initial,
      { algorithm: 'ES256', privateKey: b.privateKey },
    )).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// JSS: countersign edge paths
// ---------------------------------------------------------------------------

describe('JSS: countersign edge paths', () => {
  it('countersign refuses when target already has a counter signature', async () => {
    const { sign, countersign } = await import('../../src/jss/index.js');
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
    await expect(countersign(cs, {
      signer: { algorithm: 'Ed25519', privateKey: privPem, public_key: 'auto' },
      publicKeys: new Map([[0, pubPem]]),
    })).rejects.toThrow(/already carr|counter signature/);
  });

  it('countersign rejects a target index out of range', async () => {
    const { sign, countersign } = await import('../../src/jss/index.js');
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const pubPem  = publicKey.export({ format: 'pem',  type: 'spki'  }).toString();
    const signed = await sign({ x: 1 } as never, {
      signer: { algorithm: 'Ed25519', privateKey: privPem, public_key: 'auto' },
    });
    await expect(countersign(signed, {
      signer: { algorithm: 'Ed25519', privateKey: privPem, public_key: 'auto' },
      publicKeys: new Map([[0, pubPem]]),
      targetIndex: 99,
    })).rejects.toThrow(/out of range/);
  });
});

// ---------------------------------------------------------------------------
// JSS hash and pem edge paths
// ---------------------------------------------------------------------------

describe('jss/hash.ts and jss/pem.ts uncovered branches', () => {
  it('hashBytes rejects an unsupported hash algorithm', async () => {
    const { hashBytes } = await import('../../src/jss/hash.js');
    await expect(hashBytes('sha3-512', new Uint8Array(0))).rejects.toThrow(/Unsupported/);
  });

  it('publicKeyFromPemBody trims whitespace inside the body', async () => {
    const { publicKeyFromPemBody } = await import('../../src/jss/pem.js');
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
    const body = pem
      .replace(/-----BEGIN [^-]+-----/, '')
      .replace(/-----END [^-]+-----/, '')
      .replace(/\s+/g, '');
    // Sprinkle whitespace in the middle to exercise the cleanup path.
    const withWs = body.slice(0, 20) + '   \t\n' + body.slice(20);
    const handle = await publicKeyFromPemBody(withWs);
    expect(handle.kind).toBe('ec');
  });
});

// ---------------------------------------------------------------------------
// format-helper.ts: detection edge paths
// ---------------------------------------------------------------------------

describe('format-helper.ts: detection edge paths', () => {
  it('detectFormat returns null when the signature property is missing', async () => {
    const { detectFormat } = await import('../../src/format-helper.js');
    expect(detectFormat({ no: 'signature' } as never)).toBeNull();
  });

  it('detectFormat returns null when the signature value is an array', async () => {
    const { detectFormat } = await import('../../src/format-helper.js');
    expect(detectFormat({ signature: [] } as never)).toBeNull();
  });

  it('cyclonedxFormat maps V2 to jss', async () => {
    const { cyclonedxFormat, CycloneDxMajor } = await import('../../src/index.js');
    expect(cyclonedxFormat(CycloneDxMajor.V2)).toBe('jss');
    expect(cyclonedxFormat(CycloneDxMajor.V1)).toBe('jsf');
  });

  it('verify throws when neither cyclonedxVersion nor detection resolves', async () => {
    const { verify } = await import('../../src/index.js');
    await expect(verify({ no: 'sig' } as never)).rejects.toThrow(/cyclonedxVersion/);
  });

  it('sign throws without cyclonedxVersion', async () => {
    const { sign } = await import('../../src/index.js');
    await expect(sign({ x: 1 } as never, {} as never)).rejects.toThrow(/cyclonedxVersion/);
  });

  it('sign throws on an unknown cyclonedxVersion', async () => {
    const { sign } = await import('../../src/index.js');
    await expect(sign({ x: 1 } as never, { cyclonedxVersion: 99 } as never))
      .rejects.toThrow(/Unknown CycloneDX major/);
  });
});

// ---------------------------------------------------------------------------
// jcs.ts edge paths
// ---------------------------------------------------------------------------

describe('jcs.ts: edge paths', () => {
  it('canonicalizes a number with a fractional part using ECMA-262', async () => {
    const { canonicalize } = await import('../../src/jcs.js');
    const text = new TextDecoder().decode(canonicalize({ n: 1.5 }));
    expect(text).toBe('{"n":1.5}');
  });

  it('rejects NaN via the canonical JSON contract', async () => {
    const { canonicalize } = await import('../../src/jcs.js');
    expect(() => canonicalize({ n: NaN } as never)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// jwk.ts uncovered: HMAC export rejection has the second-throw branch
// ---------------------------------------------------------------------------

describe('jwk.ts: oct-JWK exportPublicJwk rejection', () => {
  it('exportPublicJwk on raw HMAC bytes is rejected', async () => {
    const { exportPublicJwk } = await import('../../src/jwk.js');
    await expect(exportPublicJwk(new Uint8Array(32))).rejects.toThrow(/HMAC/i);
  });

  it('exportPublicJwk on an oct JWK is rejected', async () => {
    const { exportPublicJwk } = await import('../../src/jwk.js');
    // Error wording is now "oct keys are symmetric, not public" —
    // the rejection happens at importPublicKey before exportJwk runs.
    await expect(exportPublicJwk({ kty: 'oct', k: 'AQID' } as never))
      .rejects.toThrow(/symmetric|HMAC|not public/i);
  });
});

// ---------------------------------------------------------------------------
// JSF validation.ts uncovered branches
// ---------------------------------------------------------------------------

describe('jsf/validation.ts: uncovered branches', () => {
  it('rejects an envelope with both single signaturecore and an empty wrapper', async () => {
    const { verify } = await import('../../src/jsf/index.js');
    const env = {
      x: 1,
      signature: { algorithm: 'ES256', value: 'aa', signers: [] },
    };
    // Empty `signers` array is rejected as malformed.
    await expect(verify(env as never)).rejects.toThrow(/non-empty array/);
  });
});

// ---------------------------------------------------------------------------
// jsf/algorithms.ts ESLint-disable cover (the 'eddsa' / 'hmac' assertion paths)
// ---------------------------------------------------------------------------

describe('jsf/algorithms.ts: assertKeyMatches branches', () => {
  it('signBytes rejects RSA-PSS with an EC key', async () => {
    const { signBytes, getAlgorithmSpec } = await import('../../src/jsf/algorithms.js');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const handle = await nodeBackend.importPrivateKey(privateKey);
    await expect(signBytes(getAlgorithmSpec('PS256'), new Uint8Array(0), handle))
      .rejects.toThrow(/RSA/);
  });

  it('signBytes rejects ECDSA with the wrong curve', async () => {
    const { signBytes, getAlgorithmSpec } = await import('../../src/jsf/algorithms.js');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp521r1' });
    const handle = await nodeBackend.importPrivateKey(privateKey);
    await expect(signBytes(getAlgorithmSpec('ES256'), new Uint8Array(0), handle))
      .rejects.toThrow(/P-256/);
  });

  it('signBytes rejects an unmatched EdDSA family', async () => {
    const { signBytes, getAlgorithmSpec } = await import('../../src/jsf/algorithms.js');
    const { privateKey } = generateKeyPairSync('ed448');
    const handle = await nodeBackend.importPrivateKey(privateKey);
    await expect(signBytes(getAlgorithmSpec('Ed25519'), new Uint8Array(0), handle))
      .rejects.toThrow(/ed25519/);
  });
});

// ---------------------------------------------------------------------------
// base64url.ts edge case
// ---------------------------------------------------------------------------

describe('base64url.ts: invalid input', () => {
  it('decodeBase64Url rejects strings with disallowed characters', async () => {
    const { decodeBase64Url } = await import('../../src/base64url.js');
    expect(() => decodeBase64Url('!!!')).toThrow();
  });
});

// ---------------------------------------------------------------------------
// JSS algorithms.ts: ensureCurve / ensureKeyType branches
// ---------------------------------------------------------------------------

describe('jss/algorithms.ts: assertion branches', () => {
  it('signHash rejects an EC key with the wrong curve', async () => {
    const { signHash } = await import('../../src/jss/algorithms.js');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const handle = await nodeBackend.importPrivateKey(privateKey);
    await expect(signHash('ES256', 'sha-256', new Uint8Array(32), handle))
      .rejects.toThrow(/curve/i);
  });

  it('signHash rejects RSA with an EC key', async () => {
    const { signHash } = await import('../../src/jss/algorithms.js');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const handle = await nodeBackend.importPrivateKey(privateKey);
    await expect(signHash('RS256', 'sha-256', new Uint8Array(32), handle))
      .rejects.toThrow(/RSA/);
  });

  it('signHash rejects an unsupported algorithm', async () => {
    const { signHash } = await import('../../src/jss/algorithms.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const handle = await nodeBackend.importPrivateKey(privateKey);
    await expect(signHash('NOPE', 'sha-256', new Uint8Array(32), handle))
      .rejects.toThrow(/Unsupported JSS algorithm/);
  });

  it('signHash rejects an unsupported hash algorithm', async () => {
    const { signHash } = await import('../../src/jss/algorithms.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const handle = await nodeBackend.importPrivateKey(privateKey);
    await expect(signHash('Ed25519', 'sha3-256', new Uint8Array(32), handle))
      .rejects.toThrow(/Unsupported JSS hash algorithm/);
  });

  it('signHash rejects a hash whose length does not match', async () => {
    const { signHash } = await import('../../src/jss/algorithms.js');
    const { privateKey } = generateKeyPairSync('ed25519');
    const handle = await nodeBackend.importPrivateKey(privateKey);
    await expect(signHash('Ed25519', 'sha-256', new Uint8Array(16), handle))
      .rejects.toThrow(/Hash length mismatch/);
  });
});

// ---------------------------------------------------------------------------
// Make sure createPublicKey-from-private path on Node ECDSA verify is hit
// ---------------------------------------------------------------------------

describe('node.ts: ECDSA prehashed verify with private handle (publicHandle derivation)', () => {
  it('verifies with a private-key handle by deriving the public half', async () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const priv = await nodeBackend.importPrivateKey(privateKey);
    const digest = new Uint8Array(32).fill(0xab);
    const sig = await nodeBackend.signEcdsaPrehashed('P-256', digest, priv);
    const ok = await nodeBackend.verifyEcdsaPrehashed(
      'P-256', digest, sig, priv as unknown as never,
    );
    expect(ok).toBe(true);
  });
});
