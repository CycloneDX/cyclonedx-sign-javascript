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
 * Construct every exported error class so each constructor and the
 * resulting instanceof relationships are exercised. Without these
 * the rarely-thrown subclasses sit at 0 % coverage even though they
 * are part of the public API.
 */

import { describe, it, expect } from 'vitest';
import {
  SignatureError,
  JcsError,
  JsfError,
  JsfInputError,
  JsfKeyError,
  JsfEnvelopeError,
  JsfSignError,
  JsfVerifyError,
  JsfMultiSignerInputError,
  JsfChainOrderError,
  JssError,
  JssNotImplementedError,
  JssInputError,
  JssEnvelopeError,
} from '../../src/errors.js';

describe('error class hierarchy', () => {
  it('SignatureError is the root and extends Error', () => {
    const e = new SignatureError('boom');
    expect(e).toBeInstanceOf(Error);
    expect(e.message).toBe('boom');
  });

  it('JcsError extends SignatureError', () => {
    const e = new JcsError('canon');
    expect(e).toBeInstanceOf(SignatureError);
    expect(e).toBeInstanceOf(JcsError);
  });

  it('JsfError and its subtree extend SignatureError', () => {
    const cases = [
      new JsfError('jsf'),
      new JsfInputError('input'),
      new JsfKeyError('key'),
      new JsfEnvelopeError('env'),
      new JsfVerifyError('verify'),
      new JsfMultiSignerInputError('multi'),
      new JsfChainOrderError('chain'),
    ];
    for (const e of cases) {
      expect(e).toBeInstanceOf(SignatureError);
      expect(e).toBeInstanceOf(JsfError);
    }
    // Specific narrowing
    expect(new JsfMultiSignerInputError('m')).toBeInstanceOf(JsfInputError);
    expect(new JsfChainOrderError('c')).toBeInstanceOf(JsfEnvelopeError);
  });

  it('JsfSignError carries a cause', () => {
    const cause = new Error('underlying');
    const e = new JsfSignError('wrapped', cause);
    expect(e.cause).toBe(cause);
    expect(e.message).toBe('wrapped');
    // cause-less form
    const e2 = new JsfSignError('no cause');
    expect(e2.cause).toBeUndefined();
  });

  it('JssError and its subtree extend SignatureError', () => {
    const cases = [
      new JssError('jss'),
      new JssNotImplementedError(),
      new JssNotImplementedError('explicit'),
      new JssInputError('input'),
      new JssEnvelopeError('env'),
    ];
    for (const e of cases) {
      expect(e).toBeInstanceOf(SignatureError);
      expect(e).toBeInstanceOf(JssError);
    }
  });

  it('JssNotImplementedError has a default message', () => {
    const e = new JssNotImplementedError();
    expect(e.message).toMatch(/not yet implemented/);
  });
});

describe('Web backend RSA JWK helpers reject malformed input', () => {
  it('rejects RSA private params extraction when kty is wrong', async () => {
    // Force the error path by constructing a non-RSA JWK and feeding
    // it through signRsaPkcs1Prehashed (which calls
    // rsaPrivateParamsFromJwk under the hood).
    const { backend: webBackend } = await import('../../src/internal/crypto/web.js');
    const { ecPair } = await import('../helpers.js');
    const { privateKey } = ecPair('prime256v1');
    const fakeRsaHandle = await webBackend.importPrivateKey(
      privateKey.export({ format: 'jwk' }) as never,
    );
    await expect(webBackend.signRsaPkcs1Prehashed('sha-256', new Uint8Array(32), fakeRsaHandle))
      .rejects.toThrow(/RSA/);
  });

  it('rejects RSA public params extraction when kty is wrong', async () => {
    const { backend: webBackend } = await import('../../src/internal/crypto/web.js');
    const { ecPair } = await import('../helpers.js');
    const { publicKey } = ecPair('prime256v1');
    const fakeRsaHandle = await webBackend.importPublicKey(
      publicKey.export({ format: 'jwk' }) as never,
    );
    // The kty=EC handle's rsaModulusBits is null, so the verify
    // returns false on that guard before reaching the params helper.
    const ok = await webBackend.verifyRsaPssPrehashed(
      'sha-256',
      new Uint8Array(32),
      32,
      new Uint8Array(256),
      fakeRsaHandle,
    );
    expect(ok).toBe(false);
  });
});

describe('Web backend X.509 walker error paths', () => {
  it('rejects DER that does not start with the outer Certificate SEQUENCE', async () => {
    const { backend: webBackend } = await import('../../src/internal/crypto/web.js');
    const bogus = new Uint8Array([0x42, 0x00, 0x00]);
    await expect(webBackend.parseCertSpkiPublicKey(bogus))
      .rejects.toThrow(/SEQUENCE/);
  });
});
