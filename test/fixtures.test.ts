/**
 * Fixture based tests for the JSF package.
 *
 * These tests complement the ephemeral-key tests in jsf.test.ts. The
 * rest of the suite generates fresh keys every run and signs + verifies
 * in the same test body, which proves internal consistency but cannot
 * detect silent drift in canonicalization or signature assembly. The
 * fixtures here close that gap:
 *
 *   1. Own-fixtures: we committed one signed envelope per algorithm
 *      under test/fixtures/jsf/envelopes/ plus the matching PEM keys
 *      under test/fixtures/keys/. The tests call verify() against the
 *      committed envelope. Any change that causes our verify() to
 *      reject material we ourselves produced is flagged.
 *
 *   2. Round trip on fixed keys: for each algorithm we also sign the
 *      same payload using the committed PEM private key and assert
 *      that verify() accepts it. Takes RNG out of the loop so any
 *      failure is reproducible.
 *
 *   3. Interop: the test/fixtures/jsf/interop/webpki/ directory holds
 *      envelopes produced by the JSF reference implementation,
 *      node-webpki.org. We run verify() on each and assert valid. A
 *      failure here points to a real deviation from the JSF spec as
 *      the reference implementation interprets it.
 *
 *   4. Tamper detection: every own-fixtures verification is followed
 *      by a payload mutation and a re-verification that must fail.
 *      Without this the valid==true assertions would be trivially
 *      satisfied by any function that always returns valid.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createPrivateKey,
  createPublicKey,
  X509Certificate,
  type KeyObject,
} from 'node:crypto';

import { sign, verify } from '../src/jsf/index.js';
import type { JsonObject } from '../src/types.js';
import type { JsfAlgorithm } from '../src/jsf/types.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, 'fixtures');
const KEYS_DIR = join(FIXTURES, 'keys');
const JSF_FIXTURES = join(FIXTURES, 'jsf');
const SIGS_DIR = join(JSF_FIXTURES, 'envelopes');
const INTEROP_DIR = join(JSF_FIXTURES, 'interop', 'webpki');

const HMAC_SECRET_HEX =
  '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

function readKey(name: string): string {
  return readFileSync(join(KEYS_DIR, `${name}.pem`), 'utf8');
}

function readFixture(file: string): JsonObject {
  return JSON.parse(readFileSync(join(SIGS_DIR, file), 'utf8')) as JsonObject;
}

function readInterop(file: string): JsonObject {
  return JSON.parse(readFileSync(join(INTEROP_DIR, file), 'utf8')) as JsonObject;
}

function derivePublicPem(privatePem: string): string {
  const priv = createPrivateKey(privatePem);
  const pub = createPublicKey(priv);
  return pub.export({ type: 'spki', format: 'pem' }).toString();
}

/**
 * Extract the leaf certificate's public key as a KeyObject. The
 * JSF @cer envelopes carry `signature.certificatePath` as an array
 * of base64 (non-url-safe) DER strings with the leaf first.
 */
function leafPublicKeyFrom(envelope: JsonObject): KeyObject {
  const signer = envelope['signature'] as { certificatePath?: string[] };
  const path = signer.certificatePath;
  if (!Array.isArray(path) || path.length === 0) {
    throw new Error('envelope has no certificatePath');
  }
  const leafB64 = path[0];
  if (!leafB64) throw new Error('certificatePath[0] empty');
  const der = Buffer.from(leafB64, 'base64');
  const cert = new X509Certificate(der);
  return cert.publicKey;
}

// ---------------------------------------------------------------------------
// 1 + 2. Own-fixture verify and round-trip-on-fixed-keys
// ---------------------------------------------------------------------------

interface AsymmetricCase {
  algorithm: JsfAlgorithm;
  privateKeyFile: string;
}

const ASYMMETRIC: AsymmetricCase[] = [
  { algorithm: 'RS256', privateKeyFile: 'rsa2048-private' },
  { algorithm: 'RS384', privateKeyFile: 'rsa2048-private' },
  { algorithm: 'RS512', privateKeyFile: 'rsa2048-private' },
  { algorithm: 'PS256', privateKeyFile: 'rsa2048-private' },
  { algorithm: 'PS384', privateKeyFile: 'rsa2048-private' },
  { algorithm: 'PS512', privateKeyFile: 'rsa2048-private' },
  { algorithm: 'ES256', privateKeyFile: 'p256-private' },
  { algorithm: 'ES384', privateKeyFile: 'p384-private' },
  { algorithm: 'ES512', privateKeyFile: 'p521-private' },
  { algorithm: 'Ed25519', privateKeyFile: 'ed25519-private' },
  { algorithm: 'Ed448', privateKeyFile: 'ed448-private' },
];

describe('Fixture: committed envelopes verify', () => {
  for (const { algorithm } of ASYMMETRIC) {
    it(`${algorithm} envelope verifies with its embedded publicKey`, async () => {
      const env = readFixture(`${algorithm}.json`);
      const result = await verify(env);
      expect(result.valid).toBe(true);
      expect(result.signers[0]?.algorithm).toBe(algorithm);
    });

    it(`${algorithm} envelope rejects a tampered payload`, async () => {
      const env = readFixture(`${algorithm}.json`);
      // Mutate a top-level field; the signature must no longer verify.
      const tampered: JsonObject = { ...env, subject: 'assessment-tampered' };
      const result = await verify(tampered);
      expect(result.valid).toBe(false);
      expect(result.signers[0]?.errors.length).toBeGreaterThan(0);
    });
  }

  for (const alg of ['HS256', 'HS384', 'HS512'] as const) {
    it(`${alg} envelope verifies with the shared secret`, async () => {
      const env = readFixture(`${alg}.json`);
      const secret = Buffer.from(HMAC_SECRET_HEX, 'hex');
      const result = await verify(env, { publicKey: secret });
      expect(result.valid).toBe(true);
      expect(result.signers[0]?.algorithm).toBe(alg);
    });

    it(`${alg} envelope rejects a tampered payload`, async () => {
      const env = readFixture(`${alg}.json`);
      const secret = Buffer.from(HMAC_SECRET_HEX, 'hex');
      const tampered: JsonObject = { ...env, subject: 'assessment-tampered' };
      expect((await verify(tampered, { publicKey: secret })).valid).toBe(false);
    });
  }
});

describe('Fixture: round trip using committed PEM keys', () => {
  const payload: JsonObject = {
    subject: 'round-trip',
    meta: { note: 'uses committed private key material' },
  };

  for (const { algorithm, privateKeyFile } of ASYMMETRIC) {
    it(`${algorithm} signs and verifies with the committed key`, async () => {
      const pem = readKey(privateKeyFile);
      const signed = await sign(payload, {
        signer: { algorithm, privateKey: pem },
      });
      const result = await verify(signed);
      expect(result.valid).toBe(true);
      expect(result.signers[0]?.algorithm).toBe(algorithm);
    });
  }
});

// ---------------------------------------------------------------------------
// 3. Interop with node-webpki.org reference fixtures
// ---------------------------------------------------------------------------

interface InteropCase {
  file: string;
  algorithm: JsfAlgorithm;
  keySource: 'embedded' | 'derived-from-private' | 'committed-public' | 'leaf-cert';
  privateKeyFile?: string;
  publicKeyFile?: string;
}

const INTEROP: InteropCase[] = [
  // @jwk variants: envelope carries the publicKey directly, so verify
  // needs no extra input.
  { file: 'p256#es256@jwk.json', algorithm: 'ES256', keySource: 'embedded' },
  { file: 'p384#es384@jwk.json', algorithm: 'ES384', keySource: 'embedded' },
  { file: 'p521#es512@jwk.json', algorithm: 'ES512', keySource: 'embedded' },
  { file: 'r2048#rs256@jwk.json', algorithm: 'RS256', keySource: 'embedded' },

  // @imp variants: envelope has no publicKey, so the verifier must
  // supply one out of band. For P-256 upstream ships a PEM public key;
  // for the others we derive it from the committed private key.
  {
    file: 'p256#es256@imp.json',
    algorithm: 'ES256',
    keySource: 'committed-public',
    publicKeyFile: 'p256publickey.pem',
  },
  {
    file: 'p384#es384@imp.json',
    algorithm: 'ES384',
    keySource: 'derived-from-private',
    privateKeyFile: 'p384privatekey.pem',
  },
  {
    file: 'p521#es512@imp.json',
    algorithm: 'ES512',
    keySource: 'derived-from-private',
    privateKeyFile: 'p521privatekey.pem',
  },
  {
    file: 'r2048#rs256@imp.json',
    algorithm: 'RS256',
    keySource: 'derived-from-private',
    privateKeyFile: 'r2048privatekey.pem',
  },

  // @cer variants: envelope carries an X.509 certificate chain. We
  // extract the leaf cert's public key and verify against that. Chain
  // building and revocation are out of scope for this package.
  { file: 'p256#es256@cer.json', algorithm: 'ES256', keySource: 'leaf-cert' },
  { file: 'p384#es384@cer.json', algorithm: 'ES384', keySource: 'leaf-cert' },
  { file: 'p521#es512@cer.json', algorithm: 'ES512', keySource: 'leaf-cert' },
  { file: 'r2048#rs256@cer.json', algorithm: 'RS256', keySource: 'leaf-cert' },
];

describe('Interop: node-webpki.org reference fixtures verify', () => {
  for (const c of INTEROP) {
    it(`${c.file} verifies`, async () => {
      const env = readInterop(c.file);
      let result;
      switch (c.keySource) {
        case 'embedded':
          result = await verify(env);
          break;
        case 'committed-public': {
          if (!c.publicKeyFile) throw new Error('missing publicKeyFile');
          const pem = readFileSync(join(INTEROP_DIR, c.publicKeyFile), 'utf8');
          result = await verify(env, { publicKey: pem });
          break;
        }
        case 'derived-from-private': {
          if (!c.privateKeyFile) throw new Error('missing privateKeyFile');
          const privPem = readFileSync(join(INTEROP_DIR, c.privateKeyFile), 'utf8');
          const pubPem = derivePublicPem(privPem);
          result = await verify(env, { publicKey: pubPem });
          break;
        }
        case 'leaf-cert': {
          const pub = leafPublicKeyFrom(env);
          result = await verify(env, { publicKey: pub });
          break;
        }
      }
      expect(result.valid).toBe(true);
      expect(result.signers[0]?.algorithm).toBe(c.algorithm);
    });
  }

  it('every committed interop fixture is covered by a test case', () => {
    const jsonFiles = readdirSync(INTEROP_DIR)
      .filter((name) => name.endsWith('.json'))
      .filter((name) => !name.includes('ecdh-es'));
    const covered = new Set(INTEROP.map((c) => c.file));
    const uncovered = jsonFiles.filter((n) => !covered.has(n));
    expect(uncovered).toEqual([]);
  });

  it('tampered interop payload is rejected', async () => {
    const env = readInterop('p256#es256@jwk.json');
    const tampered: JsonObject = { ...env, name: 'Mallory' };
    const result = await verify(tampered);
    expect(result.valid).toBe(false);
  });
});
