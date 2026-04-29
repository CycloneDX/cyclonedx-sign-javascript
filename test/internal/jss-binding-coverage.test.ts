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
 * Direct tests for `JssBinding`'s key-plumbing methods.
 *
 * `JSS_BINDING.toSigner` / `toVerifier` are part of the public
 * binding surface (exported via `@cyclonedx/sign/jss`) but the
 * library's own JSS sign loop bypasses them in favour of a
 * tighter inline implementation. They still need to work for any
 * adapter consumer (HSM, KMS) that drives the binding directly.
 */

import { describe, it, expect } from 'vitest';
import { JSS_BINDING } from '../../src/jss/binding.js';
import { canonicalize } from '../../src/jcs.js';
import { JssInputError, JssEnvelopeError } from '../../src/errors.js';
import { ecPair, edPair, rsaPair } from '../helpers.js';
import {
  publicKeyFromPemBody,
  pemBodyFromPublicKey,
  toPrivateKey,
  toPublicKey,
} from '../../src/jss/pem.js';

const PAYLOAD = { hello: 'world' };

describe('JssBinding.toSigner / toVerifier', () => {
  it('produces a Signer that signs canonical bytes', async () => {
    const { privateKey } = edPair('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const signer = await JSS_BINDING.toSigner({
      algorithm: 'Ed25519',
      privateKey: pem,
    });
    const canonical = canonicalize(PAYLOAD as never);
    const sig = await signer.sign(canonical);
    expect(sig.length).toBeGreaterThan(0);
  });

  it('passes through a pre-built Signer when the caller provides one', async () => {
    const fakeSigner = {
      async sign(_bytes: Uint8Array) { return new Uint8Array([1, 2, 3]); },
    };
    const out = await JSS_BINDING.toSigner({
      algorithm: 'Ed25519',
      signer: fakeSigner,
    });
    const sig = await out.sign(new Uint8Array(0));
    expect(sig).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('rejects toSigner with neither privateKey nor signer', async () => {
    await expect(JSS_BINDING.toSigner({ algorithm: 'Ed25519' }))
      .rejects.toThrow(JssInputError);
  });

  it('rejects toSigner with an unsupported algorithm', async () => {
    const { privateKey } = edPair('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    await expect(JSS_BINDING.toSigner({ algorithm: 'NOT_REAL', privateKey: pem }))
      .rejects.toThrow(JssInputError);
  });

  it('rejects toSigner with an unsupported hash_algorithm via extensionValues', async () => {
    const { JSS_HASH_ALGO_KEY } = await import('../../src/jss/binding.js');
    const { privateKey } = edPair('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    await expect(JSS_BINDING.toSigner({
      algorithm: 'Ed25519',
      privateKey: pem,
      extensionValues: { [JSS_HASH_ALGO_KEY]: 'sha3-256' },
    })).rejects.toThrow(JssInputError);
  });

  it('produces a Verifier that round-trips with the matching signer', async () => {
    const { privateKey, publicKey } = edPair('ed25519');
    const privPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const pubPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
    const signer = await JSS_BINDING.toSigner({ algorithm: 'Ed25519', privateKey: privPem });
    const verifier = await JSS_BINDING.toVerifier({ algorithm: 'Ed25519', publicKey: pubPem });
    const canonical = canonicalize(PAYLOAD as never);
    const sig = await signer.sign(canonical);
    const ok = await verifier.verify(canonical, sig);
    expect(ok).toBe(true);
  });

  it('rejects toVerifier with an unsupported algorithm', async () => {
    await expect(JSS_BINDING.toVerifier({ algorithm: 'NOT_REAL' }))
      .rejects.toThrow(JssInputError);
  });

  it('Verifier rejects an unsupported hash_algorithm at verify time', async () => {
    const { publicKey } = edPair('ed25519');
    const pubPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
    const verifier = await JSS_BINDING.toVerifier({
      algorithm: 'Ed25519',
      publicKey: pubPem,
    } as never);
    // Force an unsupported hash by attaching `hashAlgorithm` directly.
    const verifierBad = await JSS_BINDING.toVerifier({
      algorithm: 'Ed25519',
      publicKey: pubPem,
      hashAlgorithm: 'sha3-256',
    } as never);
    await expect(verifierBad.verify(new Uint8Array(0), new Uint8Array(0)))
      .rejects.toThrow(/hash algorithm/i);
    void verifier;
  });

  it('Verifier rejects when no public key is available', async () => {
    const verifier = await JSS_BINDING.toVerifier({ algorithm: 'Ed25519' });
    await expect(verifier.verify(new Uint8Array(0), new Uint8Array(0)))
      .rejects.toThrow(JssInputError);
  });

  it('resolveEmbeddedPublicKey returns null (JSS embeds via PEM body, not JWK)', async () => {
    const out = await JSS_BINDING.resolveEmbeddedPublicKey({
      algorithm: 'Ed25519',
    });
    expect(out).toBeNull();
  });
});

describe('JssBinding.emit defensive checks', () => {
  it('refuses to overwrite an existing signature property', () => {
    expect(() => JSS_BINDING.emit(
      { signatures: 'existing' as unknown as never },
      { mode: 'multi', options: {}, signers: [], finalized: [] },
      'signatures',
    )).toThrow(JssInputError);
  });
});

describe('JSS pem.ts edge paths', () => {
  it('publicKeyFromPemBody rejects empty input', async () => {
    await expect(publicKeyFromPemBody('')).rejects.toThrow(JssInputError);
  });

  it('publicKeyFromPemBody rejects non-base64 content', async () => {
    await expect(publicKeyFromPemBody('not base64 !!!')).rejects.toThrow(JssEnvelopeError);
  });

  it('pemBodyFromPublicKey strips PEM headers and trailing padding', async () => {
    const { publicKey } = ecPair('prime256v1');
    const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
    const handle = await toPublicKey(pem);
    const body = await pemBodyFromPublicKey(handle);
    expect(body).not.toContain('-----BEGIN');
    expect(body).not.toContain('-----END');
    expect(body.endsWith('=')).toBe(false);
  });

  it('toPrivateKey rejects an invalid input', async () => {
    await expect(toPrivateKey(42 as never)).rejects.toThrow(JssInputError);
  });

  it('toPublicKey rejects an invalid input', async () => {
    await expect(toPublicKey(42 as never)).rejects.toThrow(JssInputError);
  });

  it('publicKeyFromPemBody round-trips a PEM body', async () => {
    const { publicKey } = rsaPair(2048);
    const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
    const handle = await toPublicKey(pem);
    const body = await pemBodyFromPublicKey(handle);
    const reparsed = await publicKeyFromPemBody(body);
    expect(reparsed.kind).toBe('rsa');
  });
});
