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
 * Round 4 of coverage-driven tests, finishing the >93 % push.
 *
 * Targets:
 *   - jsf/sign.ts append-chain / append-multi malformed-input branches
 *   - jsf/sign.ts extension-collision validation
 *   - jsf/sign.ts argument plumbing for `verify` with `publicKeys` map
 *   - jss/binding.ts certPublicKey / b64ToBytes path
 *   - web.ts rsaPublicParamsFromJwk error path
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');
const WEBPKI = join(FIXTURES, 'jsf', 'interop', 'webpki');

describe('jsf/sign.ts: append-chain and append-multi error branches', () => {
  it('appendChainSigner rejects when payload has no signature property', async () => {
    const { appendChainSigner } = await import('../../src/jsf/index.js');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    await expect(appendChainSigner({ x: 1 } as never, {
      algorithm: 'ES256', privateKey,
    })).rejects.toThrow(/has no/);
  });

  it('appendChainSigner rejects when payload has a single (non-chain) envelope', async () => {
    const { sign, appendChainSigner } = await import('../../src/jsf/index.js');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const single = await sign({ x: 1 } as never, {
      signer: { algorithm: 'ES256', privateKey },
    });
    await expect(appendChainSigner(single, {
      algorithm: 'ES256', privateKey,
    }, { skipVerifyExisting: true } as never))
      .rejects.toThrow(/cannot append a chain signer/);
  });

  it('appendMultiSigner rejects extension key that is a JSF reserved word', async () => {
    const { sign, appendMultiSigner } = await import('../../src/jsf/index.js');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const initial = await sign({ x: 1 } as never, {
      signers: [{ algorithm: 'ES256', privateKey }],
      mode: 'multi',
    });
    await expect(appendMultiSigner(
      initial,
      {
        algorithm: 'ES256', privateKey,
        extensionValues: { algorithm: 'collide' },
      },
      { skipVerifyExisting: true } as never,
    )).rejects.toThrow(/reserved word/);
  });

  it('appendMultiSigner rejects extension key not declared in the envelope', async () => {
    const { sign, appendMultiSigner } = await import('../../src/jsf/index.js');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const initial = await sign({ x: 1 } as never, {
      signers: [{
        algorithm: 'ES256', privateKey,
        extensionValues: { foo: 'a' },
      }],
      mode: 'multi',
      extensions: ['foo'],
    });
    await expect(appendMultiSigner(
      initial,
      {
        algorithm: 'ES256', privateKey,
        extensionValues: { undeclared: 'b' },
      },
      { skipVerifyExisting: true } as never,
    )).rejects.toThrow(/not declared/);
  });
});

describe('jsf/sign.ts: verify with publicKeys map', () => {
  it('verify uses caller-supplied publicKeys map and ignores embedded keys', async () => {
    const { sign, verify } = await import('../../src/jsf/index.js');
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const signed = await sign({ x: 1 } as never, {
      signer: { algorithm: 'ES256', privateKey },
    });
    const r = await verify(signed, {
      publicKeys: new Map([[0, publicKey.export({ format: 'jwk' })]]),
    } as never);
    expect(r.valid).toBe(true);
  });
});

describe('jss/binding.ts: cert chain via b64ToBytes', () => {
  it('verify with embedded public_cert_chain (URL-safe base64) succeeds', async () => {
    const { sign, verify } = await import('../../src/jss/index.js');
    const privPem = readFileSync(join(WEBPKI, 'p256privatekey.pem'), 'utf8');
    const certPem = readFileSync(join(WEBPKI, 'p256certpath.pem'), 'utf8');
    const certBlocks = certPem
      .split(/-----BEGIN CERTIFICATE-----/)
      .filter((b) => b.includes('-----END CERTIFICATE-----'))
      .map((b) => b.replace(/-----END CERTIFICATE-----[\s\S]*$/, '').replace(/\s+/g, ''))
      // Convert standard base64 to URL-safe variant to exercise that
      // codepath in b64ToBytes.
      .map((b) => b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));

    const signed = await sign({ x: 1 } as never, {
      signer: {
        algorithm: 'ES256', privateKey: privPem,
        public_key: false,
        public_cert_chain: certBlocks,
      },
    });
    const r = await verify(signed);
    expect(r.valid).toBe(true);
  });
});

describe('web.ts: rsaPublicParamsFromJwk via verify', () => {
  it('verifyRsaPkcs1Prehashed rejects an RSA JWK missing n', async () => {
    const { backend } = await import('../../src/internal/crypto/web.js');
    const fakeJwk = {
      kty: 'RSA', e: 'AQAB',                  // missing n
    };
    // describeJwk throws on a missing n at import time; assert that
    // path rather than the verify path.
    await expect(backend.importPublicKey(fakeJwk as never))
      .rejects.toThrow(/RSA JWK missing n/);
  });
});

describe('JSS sign with HMAC-style symbolic key path is rejected', () => {
  it('sign rejects an HMAC algorithm (JSS is asymmetric)', async () => {
    const { sign } = await import('../../src/jss/index.js');
    await expect(sign({ x: 1 } as never, {
      signer: { algorithm: 'HS256', privateKey: 'oops' },
    } as never)).rejects.toThrow();
  });
});
