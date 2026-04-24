#!/usr/bin/env node
/**
 * Regenerate the committed JSF envelope fixtures under
 * ./signatures/ using the committed PEM keys under ./keys/.
 *
 * Usage:
 *   node test/fixtures/build-signatures.mjs
 *
 * RSA-PSS and ECDSA signatures are randomized, so re-running this
 * script will change the `signature.value` strings for those
 * algorithms. That is expected. The consumer test only calls verify()
 * against the committed envelope, so any well-formed run of this
 * script produces a test suite that passes.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { sign } from '../../dist/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const KEYS = join(HERE, 'keys');
const OUT = join(HERE, 'signatures');
mkdirSync(OUT, { recursive: true });

const PAYLOAD = {
  subject: 'assessment-42',
  issuedAt: '2026-04-20T10:00:00Z',
  claims: [
    { id: 'c1', status: 'pass' },
    { id: 'c2', status: 'pass', notes: 'reviewed' },
  ],
  meta: { version: '1.0.0', source: 'assessors-studio' },
};

const HMAC_SECRET_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

const ASYMMETRIC = [
  ['RS256',   'rsa2048-private'],
  ['RS384',   'rsa2048-private'],
  ['RS512',   'rsa2048-private'],
  ['PS256',   'rsa2048-private'],
  ['PS384',   'rsa2048-private'],
  ['PS512',   'rsa2048-private'],
  ['ES256',   'p256-private'],
  ['ES384',   'p384-private'],
  ['ES512',   'p521-private'],
  ['Ed25519', 'ed25519-private'],
  ['Ed448',   'ed448-private'],
];

for (const [alg, keyName] of ASYMMETRIC) {
  const pem = readFileSync(join(KEYS, `${keyName}.pem`), 'utf8');
  const signed = sign(PAYLOAD, { algorithm: alg, privateKey: pem });
  writeFileSync(join(OUT, `${alg}.json`), JSON.stringify(signed, null, 2) + '\n');
  console.log('wrote', `${alg}.json`);
}

for (const alg of ['HS256', 'HS384', 'HS512']) {
  const secret = Buffer.from(HMAC_SECRET_HEX, 'hex');
  const signed = sign(PAYLOAD, { algorithm: alg, privateKey: secret });
  writeFileSync(join(OUT, `${alg}.json`), JSON.stringify(signed, null, 2) + '\n');
  console.log('wrote', `${alg}.json`);
}
