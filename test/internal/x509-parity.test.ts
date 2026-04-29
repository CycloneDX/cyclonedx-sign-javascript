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
 * X.509 leaf-cert parsing parity between the Node and Web backends.
 *
 * The Node backend uses `node:crypto.X509Certificate` to recover a
 * verifying key from a DER cert. The Web backend has no equivalent
 * in `crypto.subtle`, so it ships a small DER walker
 * (`extractSpkiFromX509`) that locates the SubjectPublicKeyInfo in a
 * raw certificate. These two paths must agree on the byte level for
 * cert-chain envelopes to verify identically across runtimes.
 *
 * The test set is the WebPKI reference fixtures committed under
 * test/fixtures/jsf/interop/webpki. Each fixture group has:
 *
 *   - `<curve>certpath.pem`  — the full PEM cert chain (leaf first)
 *   - `<curve>#<alg>@cer.json` — a JSF envelope whose `signature.
 *     certificatePath` carries the same chain in base64url DER form,
 *     plus a real signature over the canonicalized payload.
 *
 * For every fixture this file:
 *
 *   1. Pulls the leaf cert DER out of the PEM and out of the JSON.
 *   2. Parses both DERs through the Node and Web backends.
 *   3. Asserts the extracted JWKs are byte-identical across backends.
 *   4. Verifies the envelope using each recovered key, asserting the
 *      signature actually checks out — proving the recovered key is
 *      not just structurally similar but cryptographically correct.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { backend as nodeBackend } from '../../src/internal/crypto/node.js';
import { backend as webBackend } from '../../src/internal/crypto/web.js';
import { verify, CycloneDxMajor } from '../../src/index.js';
import type { JsonObject } from '../../src/types.js';

const FIXTURES_DIR = join(__dirname, '..', 'fixtures', 'jsf', 'interop', 'webpki');

interface CertFixture {
  /** Human-readable label for the test name. */
  label: string;
  /** PEM cert chain on disk. */
  pem: string;
  /** Matching @cer.json envelope. */
  envelope: string;
}

const FIXTURES: CertFixture[] = [
  { label: 'P-256 ES256',  pem: 'p256certpath.pem',  envelope: 'p256#es256@cer.json' },
  { label: 'P-384 ES384',  pem: 'p384certpath.pem',  envelope: 'p384#es384@cer.json' },
  { label: 'P-521 ES512',  pem: 'p521certpath.pem',  envelope: 'p521#es512@cer.json' },
  { label: 'RSA 2048 RS256', pem: 'r2048certpath.pem', envelope: 'r2048#rs256@cer.json' },
];

/** Read the first certificate from a multi-cert PEM bundle. */
function readLeafCertDerFromPem(file: string): Uint8Array {
  const pem = readFileSync(join(FIXTURES_DIR, file), 'utf8');
  const match = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(pem);
  if (!match) throw new Error(`no certificate block in ${file}`);
  const body = match[1]!.replace(/\s+/g, '');
  return new Uint8Array(Buffer.from(body, 'base64'));
}

/** Read the leaf cert DER out of a JSF `@cer.json` envelope. */
function readLeafCertDerFromEnvelope(envelope: JsonObject): Uint8Array {
  const sig = envelope['signature'] as { certificatePath?: string[] } | undefined;
  const path = sig?.certificatePath;
  if (!Array.isArray(path) || path.length === 0) {
    throw new Error('envelope has no certificatePath');
  }
  const leafB64Url = path[0]!;
  // The fixture uses URL-safe base64 (- and _); Node's Buffer parser
  // tolerates both standard and URL-safe forms.
  return new Uint8Array(Buffer.from(leafB64Url, 'base64'));
}

function readEnvelope(file: string): JsonObject {
  return JSON.parse(readFileSync(join(FIXTURES_DIR, file), 'utf8')) as JsonObject;
}

describe('WebPKI X.509 leaf-cert parity: Node vs Web backend', () => {
  for (const fx of FIXTURES) {
    it(`${fx.label}: both backends extract the same JWK from the cert PEM`, async () => {
      const der = readLeafCertDerFromPem(fx.pem);
      const nodeHandle = await nodeBackend.parseCertSpkiPublicKey(der);
      const webHandle = await webBackend.parseCertSpkiPublicKey(der);
      // Metadata first — these come from independent code paths.
      expect(nodeHandle.kind).toBe(webHandle.kind);
      expect(nodeHandle.curve).toBe(webHandle.curve);
      expect(nodeHandle.rsaModulusBits).toBe(webHandle.rsaModulusBits);
      // Then the canonical JWK shape.
      const nodeJwk = await nodeHandle.exportJwk();
      const webJwk = await webHandle.exportJwk();
      expect(nodeJwk).toEqual(webJwk);
    });

    it(`${fx.label}: both backends extract the same JWK from the @cer envelope leaf`, async () => {
      const env = readEnvelope(fx.envelope);
      const der = readLeafCertDerFromEnvelope(env);
      const nodeHandle = await nodeBackend.parseCertSpkiPublicKey(der);
      const webHandle = await webBackend.parseCertSpkiPublicKey(der);
      const nodeJwk = await nodeHandle.exportJwk();
      const webJwk = await webHandle.exportJwk();
      expect(nodeJwk).toEqual(webJwk);
    });

    it(`${fx.label}: PEM-bundle leaf and envelope leaf decode to the same DER`, () => {
      const fromPem = readLeafCertDerFromPem(fx.pem);
      const fromEnv = readLeafCertDerFromEnvelope(readEnvelope(fx.envelope));
      expect(fromEnv).toEqual(fromPem);
    });
  }
});

describe('WebPKI @cer.json envelopes verify with cert-recovered keys', () => {
  for (const fx of FIXTURES) {
    it(`${fx.label}: envelope verifies with the Node-backend-recovered key`, async () => {
      const env = readEnvelope(fx.envelope);
      const der = readLeafCertDerFromEnvelope(env);
      const handle = await nodeBackend.parseCertSpkiPublicKey(der);
      const pubJwk = await handle.exportJwk();
      // Use the high-level verify(); JSF detection picks up the
      // envelope shape from the `signature` slot.
      const result = await verify(env, {
        cyclonedxVersion: CycloneDxMajor.V1,
        publicKey: pubJwk as never,
      });
      expect(result.valid).toBe(true);
    });

    it(`${fx.label}: envelope verifies with the Web-backend-recovered key`, async () => {
      const env = readEnvelope(fx.envelope);
      const der = readLeafCertDerFromEnvelope(env);
      const handle = await webBackend.parseCertSpkiPublicKey(der);
      const pubJwk = await handle.exportJwk();
      const result = await verify(env, {
        cyclonedxVersion: CycloneDxMajor.V1,
        publicKey: pubJwk as never,
      });
      expect(result.valid).toBe(true);
    });
  }
});

describe('Web backend X.509 walker robustness', () => {
  it('correctly skips the v3 [0] EXPLICIT version tag in modern certs', async () => {
    // The P-256 fixture is a v3 cert with an explicit version field.
    // If extractSpkiFromX509 mishandled the [0] tag, parsing would
    // either produce wrong bytes or fall over. Confirming the
    // recovered key matches Node's parser is the load-bearing
    // assertion here; this `it` block exists to label the case so
    // the failure mode is recognizable in test output.
    const der = readLeafCertDerFromPem('p256certpath.pem');
    const webHandle = await webBackend.parseCertSpkiPublicKey(der);
    expect(webHandle.kind).toBe('ec');
    expect(webHandle.curve).toBe('P-256');
  });

  it('handles a 521-bit EC cert (multi-byte DER lengths)', async () => {
    // P-521 SPKIs have multi-byte length encodings (0x81 prefix), so
    // the DER length parser is exercised with a non-trivial path.
    const der = readLeafCertDerFromPem('p521certpath.pem');
    const webHandle = await webBackend.parseCertSpkiPublicKey(der);
    expect(webHandle.kind).toBe('ec');
    expect(webHandle.curve).toBe('P-521');
  });

  it('handles an RSA 2048 cert (no EC curve OID to interpret)', async () => {
    const der = readLeafCertDerFromPem('r2048certpath.pem');
    const webHandle = await webBackend.parseCertSpkiPublicKey(der);
    expect(webHandle.kind).toBe('rsa');
    expect(webHandle.rsaModulusBits).toBe(2048);
  });
});
