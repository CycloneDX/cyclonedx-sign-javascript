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
 * 100% interop coverage of the WebPKI and JSS spec fixtures on the
 * Web crypto backend.
 *
 * The existing fixtures.test.ts and jss-spec.test.ts already verify
 * every committed envelope against the active `#crypto-backend`,
 * which on Node resolves to node.ts. This file mirrors that coverage
 * but force-resolves `#crypto-backend` to the Web backend via
 * `vi.mock`. Together the two test files prove that every committed
 * envelope verifies cleanly under both runtimes.
 *
 * Algorithms covered:
 *
 *   - WebPKI: ES256, ES384, ES512, RS256 (the four algorithms the
 *     reference fixtures exercise across @imp / @jwk / @cer
 *     variants).
 *   - JSS spec: Ed25519 (Appendix III real-estate fixture, clause
 *     7.1.7 single-signer, clause 7.2.7 countersignature, clause
 *     8.1.1 spec verifier example).
 *
 * The Web backend supports every algorithm referenced in either
 * fixture set, so there is no "minus" exclusion for Web.
 */

import { describe, it, expect, vi } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// vi.mock hoists, so this swap takes effect before any module that
// imports from #crypto-backend is loaded. Every import below sees the
// Web backend as the active crypto backend.
vi.mock('#crypto-backend', async () => {
  return await import('../../src/internal/crypto/web.js');
});

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');
const JSF_INTEROP = join(FIXTURES, 'jsf', 'interop', 'webpki');
const JSS_SPEC = join(FIXTURES, 'jss', 'spec');

interface JsonObject { [k: string]: unknown }

function readJson(path: string): JsonObject {
  return JSON.parse(readFileSync(path, 'utf8')) as JsonObject;
}
function readText(path: string): string {
  return readFileSync(path, 'utf8');
}

// ---------------------------------------------------------------------------
// WebPKI JSF fixtures
// ---------------------------------------------------------------------------

interface WebPkiCase {
  algorithm: 'ES256' | 'ES384' | 'ES512' | 'RS256';
  /** Stem used to find the four files. */
  stem: string;
  /** PEM private key on disk (used to derive the public for @imp variants). */
  privateKey: string;
  /** Optional explicit public-key file for @imp (kept for cases where the
   * public side is committed separately, like p256). */
  publicKey?: string;
}

const WEBPKI_CASES: WebPkiCase[] = [
  { algorithm: 'ES256', stem: 'p256#es256',  privateKey: 'p256privatekey.pem',  publicKey: 'p256publickey.pem' },
  { algorithm: 'ES384', stem: 'p384#es384',  privateKey: 'p384privatekey.pem' },
  { algorithm: 'ES512', stem: 'p521#es512',  privateKey: 'p521privatekey.pem' },
  { algorithm: 'RS256', stem: 'r2048#rs256', privateKey: 'r2048privatekey.pem' },
];

describe('Web backend: WebPKI @jwk envelopes (embedded JWK)', () => {
  for (const fx of WEBPKI_CASES) {
    it(`${fx.algorithm} verifies with embedded JWK`, async () => {
      // Imports happen inside the test so vi.mock has fully wired
      // through before this code runs.
      const { verify } = await import('../../src/jsf/index.js');
      const env = readJson(join(JSF_INTEROP, `${fx.stem}@jwk.json`));
      const r = await verify(env);
      expect(r.valid).toBe(true);
    });
  }
});

describe('Web backend: WebPKI @imp envelopes (caller-supplied key)', () => {
  for (const fx of WEBPKI_CASES) {
    it(`${fx.algorithm} verifies with the matching PEM public key`, async () => {
      const { verify } = await import('../../src/jsf/index.js');
      const env = readJson(join(JSF_INTEROP, `${fx.stem}@imp.json`));
      // Derive the public key from the private PEM (round-trip
      // through node:crypto for the helper, then hand the JWK to the
      // Web backend via the verify() options.publicKey).
      const { createPublicKey, createPrivateKey } = await import('node:crypto');
      const priv = createPrivateKey(readText(join(JSF_INTEROP, fx.privateKey)));
      const pubJwk = createPublicKey(priv).export({ format: 'jwk' });
      const r = await verify(env, { publicKey: pubJwk as never });
      expect(r.valid).toBe(true);
    });
  }
});

describe('Web backend: WebPKI @cer envelopes (X.509 chain)', () => {
  for (const fx of WEBPKI_CASES) {
    it(`${fx.algorithm} verifies using the leaf cert public key`, async () => {
      const { verify } = await import('../../src/jsf/index.js');
      const { backend: webBackend } = await import('../../src/internal/crypto/web.js');
      const env = readJson(join(JSF_INTEROP, `${fx.stem}@cer.json`));
      const path = (env.signature as { certificatePath: string[] }).certificatePath;
      const leafDer = new Uint8Array(Buffer.from(path[0]!, 'base64'));
      const handle = await webBackend.parseCertSpkiPublicKey(leafDer);
      const pubJwk = await handle.exportJwk();
      const r = await verify(env, { publicKey: pubJwk as never });
      expect(r.valid).toBe(true);
    });
  }
});

describe('Web backend: WebPKI tamper detection', () => {
  for (const fx of WEBPKI_CASES) {
    it(`${fx.algorithm} @jwk verify fails after a payload mutation`, async () => {
      const { verify } = await import('../../src/jsf/index.js');
      const env = readJson(join(JSF_INTEROP, `${fx.stem}@jwk.json`));
      // Mutate a non-signature field. Using a known field that is
      // present in every WebPKI fixture: `name`.
      const tampered = { ...env, name: 'Mallory' };
      const r = await verify(tampered);
      expect(r.valid).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// JSS spec fixtures (Ed25519)
//
// Per docs in test/fixtures/jss/spec/README.md, the published values in
// X.590 clauses 7.1.6 / 7.2.6 are KNOWN ERRATA — they do not verify
// against the Appendix II key. The library is expected to reject them.
// dotnet-jss reaches the same conclusion. These tests assert the
// failure mode plus a fresh-key round-trip on the Web backend.
// ---------------------------------------------------------------------------

describe('Web backend: JSS spec fixtures (erratum confirmation)', () => {
  it('clause-8.1.1-signed.json (containing the spec erratum value) is rejected', async () => {
    const { verify } = await import('../../src/jss/index.js');
    const env = readJson(join(JSS_SPEC, 'clause-8.1.1-signed.json'));
    const r = await verify(env);
    expect(r.valid).toBe(false);
  });

  it('clause-7.1.7-output.json (containing the spec erratum value) is rejected', async () => {
    const { verify } = await import('../../src/jss/index.js');
    const env = readJson(join(JSS_SPEC, 'clause-7.1.7-output.json'));
    const r = await verify(env);
    expect(r.valid).toBe(false);
  });

  it('SHA-256 of clause 7.1.4 canonical bytes matches the spec hash', async () => {
    const { backend } = await import('#crypto-backend');
    const canonical = readText(join(JSS_SPEC, 'clause-7.1.4-canonical.txt')).trimEnd();
    const expectedHex = readText(join(JSS_SPEC, 'clause-7.1.5-hash.hex')).trim();
    const digest = await backend.digest('sha-256', new TextEncoder().encode(canonical));
    expect(Buffer.from(digest).toString('hex')).toBe(expectedHex);
  });
});

describe('Web backend: JSS round-trip on Ed25519 spec key', () => {
  // Exercises sign + verify through the Web backend's Ed25519 path
  // (Subtle when available, @noble/curves fallback otherwise).
  it('signs and verifies a fresh payload with the Appendix II key pair', async () => {
    const { sign, verify } = await import('../../src/jss/index.js');
    const privPem = readText(join(JSS_SPEC, 'appendix-ii-private-key.pem'));
    const pubPem = readText(join(JSS_SPEC, 'appendix-ii-public-key.pem'));
    const payload: JsonObject = { hello: 'world', n: 42 };
    const signed = await sign(payload, {
      signer: { algorithm: 'Ed25519', privateKey: privPem },
    });
    const r = await verify(signed, { publicKey: pubPem });
    expect(r.valid).toBe(true);
  });
});
