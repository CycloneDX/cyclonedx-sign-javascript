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
 * JSS asymmetric signing primitives.
 *
 * X.590 clause 6.2.1 defines the signature value as
 * `base64URL.encode(sign(algorithm, key, hash(jcs(<JSON Object>))))`.
 * The asymmetric primitive consumes the precomputed hash directly:
 *
 *   - EdDSA: Ed25519/Ed448 sign the hash bytes (Ed* internally hashes
 *     with SHA-512 as part of the curve operation, which is intrinsic
 *     to the algorithm and not "double hashing" in the JSS sense).
 *   - RSA PKCS#1 v1.5: a DigestInfo SEQUENCE wraps the supplied hash
 *     and is signed with PKCS#1 v1.5 padding. Built manually because
 *     Node's `crypto.sign('sha256', data, key)` always rehashes its
 *     input.
 *   - RSA-PSS: the EMSA-PSS encoded message is constructed manually
 *     from the supplied hash, then RSA private-keyed via
 *     privateEncrypt(RSA_NO_PADDING). Same reason as PKCS#1.
 *   - ECDSA (`ES256`/`ES384`/`ES512`): implemented via `@noble/curves`
 *     `p256`/`p384`/`p521` because `node:crypto` cannot consume a
 *     pre-hashed digest for ECDSA without an external dependency.
 *     Output is IEEE P-1363 (r || s) per JWA RFC 7518 § 3.4. Sign
 *     normalizes to low-S; verify accepts both forms for cross
 *     implementation interop.
 */

import {
  constants as cryptoConstants,
  createHash,
  createPublicKey,
  KeyObject,
  privateEncrypt,
  publicDecrypt,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';

import { p256, p384, p521 } from '@noble/curves/nist.js';
import { JssInputError } from '../errors.js';
import type { JssHashAlgorithm } from './hash.js';
import { JssHashAlgorithms, hashLength, isRegisteredHashAlgorithm } from './hash.js';

export type JssAlgorithm =
  | 'RS256' | 'RS384' | 'RS512'
  | 'PS256' | 'PS384' | 'PS512'
  | 'ES256' | 'ES384' | 'ES512'
  | 'Ed25519' | 'Ed448';

/**
 * Named runtime constants for every JSS algorithm. Callers who prefer
 * dot-access over raw string literals can write
 * `JssAlgorithms.Ed25519` instead of `'Ed25519'`. The values are the
 * exact X.590 / JWA wire identifiers; the type is `JssAlgorithm`, so
 * passing one of these into the sign / verify options is fully
 * type-safe. This object is also the single source of truth for the
 * registered-algorithm set the rest of this module dispatches on.
 */
export const JssAlgorithms = {
  RS256: 'RS256',
  RS384: 'RS384',
  RS512: 'RS512',
  PS256: 'PS256',
  PS384: 'PS384',
  PS512: 'PS512',
  ES256: 'ES256',
  ES384: 'ES384',
  ES512: 'ES512',
  Ed25519: 'Ed25519',
  Ed448: 'Ed448',
} as const satisfies Record<string, JssAlgorithm>;

const REGISTERED: ReadonlySet<JssAlgorithm> = new Set<JssAlgorithm>(
  Object.values(JssAlgorithms),
);

export function isRegisteredAlgorithm(name: string): name is JssAlgorithm {
  return REGISTERED.has(name as JssAlgorithm);
}

type AlgorithmFamily = 'eddsa' | 'rsa-pkcs1' | 'rsa-pss' | 'ecdsa';

/**
 * Map a registered JSS algorithm name to its primitive family. Single
 * source of truth for the sign/verify dispatch below.
 */
function familyOf(algorithm: JssAlgorithm): AlgorithmFamily {
  if (algorithm === JssAlgorithms.Ed25519 || algorithm === JssAlgorithms.Ed448) return 'eddsa';
  if (algorithm.startsWith('RS')) return 'rsa-pkcs1';
  if (algorithm.startsWith('PS')) return 'rsa-pss';
  return 'ecdsa';
}

/**
 * Sign a precomputed hash with the JSS algorithm.
 */
export function signHash(
  algorithm: string,
  hashAlgorithm: string,
  hash: Buffer,
  privateKey: KeyObject,
): Buffer {
  ensureRegistered(algorithm);
  ensureHashRegistered(hashAlgorithm);
  ensureHashLength(hashAlgorithm as JssHashAlgorithm, hash);
  const h = hashAlgorithm as JssHashAlgorithm;
  switch (familyOf(algorithm)) {
    case 'eddsa':     return signEdDsa(algorithm, hash, privateKey);
    case 'rsa-pkcs1': return signRsaPkcs1(h, hash, privateKey);
    case 'rsa-pss':   return signRsaPss(h, hash, privateKey);
    case 'ecdsa':     return signEcdsa(algorithm as EcdsaAlgorithm, hash, privateKey);
  }
}

/**
 * Verify a JSS signature against a precomputed hash.
 */
export function verifyHash(
  algorithm: string,
  hashAlgorithm: string,
  hash: Buffer,
  signature: Buffer,
  publicKey: KeyObject,
): boolean {
  ensureRegistered(algorithm);
  ensureHashRegistered(hashAlgorithm);
  ensureHashLength(hashAlgorithm as JssHashAlgorithm, hash);
  const h = hashAlgorithm as JssHashAlgorithm;
  switch (familyOf(algorithm)) {
    case 'eddsa':     return verifyEdDsa(algorithm, hash, signature, publicKey);
    case 'rsa-pkcs1': return verifyRsaPkcs1(h, hash, signature, publicKey);
    case 'rsa-pss':   return verifyRsaPss(h, hash, signature, publicKey);
    case 'ecdsa':     return verifyEcdsa(algorithm as EcdsaAlgorithm, hash, signature, publicKey);
  }
}

// -- EdDSA --------------------------------------------------------------------

function signEdDsa(algorithm: string, hash: Buffer, privateKey: KeyObject): Buffer {
  ensureKeyType(privateKey, algorithm.toLowerCase(), algorithm);
  return nodeSign(null, hash, privateKey);
}

function verifyEdDsa(
  algorithm: string,
  hash: Buffer,
  signature: Buffer,
  publicKey: KeyObject,
): boolean {
  ensureKeyType(publicKey, algorithm.toLowerCase(), algorithm);
  try {
    return nodeVerify(null, hash, publicKey, signature);
  } catch {
    return false;
  }
}

// -- RSA PKCS#1 v1.5 ----------------------------------------------------------

function signRsaPkcs1(
  hashAlgorithm: JssHashAlgorithm,
  hash: Buffer,
  privateKey: KeyObject,
): Buffer {
  ensureKeyType(privateKey, 'rsa', hashAlgorithm);
  const digestInfo = buildDigestInfo(hashAlgorithm, hash);
  return privateEncrypt(
    { key: privateKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
    digestInfo,
  );
}

function verifyRsaPkcs1(
  hashAlgorithm: JssHashAlgorithm,
  hash: Buffer,
  signature: Buffer,
  publicKey: KeyObject,
): boolean {
  ensureKeyType(publicKey, 'rsa', hashAlgorithm);
  try {
    const decoded = publicDecrypt(
      { key: publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
      signature,
    );
    const expected = buildDigestInfo(hashAlgorithm, hash);
    return constantTimeEqual(decoded, expected);
  } catch {
    return false;
  }
}

// PKCS#1 v1.5 DigestInfo: SEQUENCE { algorithmIdentifier, OCTET STRING(hash) }.
// Pre-baked DER prefixes per RFC 3447 Appendix B.1.
const DIGEST_INFO_PREFIX: Record<JssHashAlgorithm, Uint8Array> = {
  'sha-256': new Uint8Array([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
  ]),
  'sha-384': new Uint8Array([
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
  ]),
  'sha-512': new Uint8Array([
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
  ]),
};

function buildDigestInfo(hashAlgorithm: JssHashAlgorithm, hash: Buffer): Buffer {
  // eslint-disable-next-line security/detect-object-injection -- hashAlgorithm is a key of the static prefix table.
  const prefix = DIGEST_INFO_PREFIX[hashAlgorithm];
  return Buffer.concat([Buffer.from(prefix), hash]);
}

// -- RSA-PSS ------------------------------------------------------------------

function signRsaPss(
  hashAlgorithm: JssHashAlgorithm,
  hash: Buffer,
  privateKey: KeyObject,
): Buffer {
  ensureKeyType(privateKey, 'rsa', hashAlgorithm);
  const modulusBits = rsaModulusBits(privateKey);
  const em = pssEncode(hash, hashAlgorithm, modulusBits);
  return privateEncrypt(
    { key: privateKey, padding: cryptoConstants.RSA_NO_PADDING },
    em,
  );
}

function verifyRsaPss(
  hashAlgorithm: JssHashAlgorithm,
  hash: Buffer,
  signature: Buffer,
  publicKey: KeyObject,
): boolean {
  ensureKeyType(publicKey, 'rsa', hashAlgorithm);
  try {
    const modulusBits = rsaModulusBits(publicKey);
    const em = publicDecrypt(
      { key: publicKey, padding: cryptoConstants.RSA_NO_PADDING },
      signature,
    );
    return pssVerify(em, hash, hashAlgorithm, modulusBits);
  } catch {
    return false;
  }
}

/**
 * EMSA-PSS-ENCODE per RFC 8017 § 9.1.1. Salt length defaults to the
 * hash length (matches JWA RFC 7518 § 3.5 and the `dotnet-jss`
 * implementation default).
 */
function pssEncode(
  mHash: Buffer,
  hashAlgorithm: JssHashAlgorithm,
  modulusBits: number,
): Buffer {
  const hLen = hashLength(hashAlgorithm);
  const sLen = hLen;
  const emBits = modulusBits - 1;
  const emLen = Math.ceil(emBits / 8);

  if (emLen < hLen + sLen + 2) {
    throw new JssInputError('RSA modulus too small for PSS encoding');
  }

  const salt = randomBytes(sLen);
  const mPrime = Buffer.concat([
    Buffer.alloc(8, 0),
    mHash,
    salt,
  ]);
  const h = hashOf(hashAlgorithm, mPrime);

  const psLen = emLen - sLen - hLen - 2;
  const ps = Buffer.alloc(psLen, 0);
  const db = Buffer.concat([ps, Buffer.from([0x01]), salt]);

  const dbMask = mgf1(h, emLen - hLen - 1, hashAlgorithm);
  const maskedDb = xor(db, dbMask);

  // Set the leftmost 8*emLen - emBits bits of maskedDb to zero.
  const leftBits = 8 * emLen - emBits;
  if (leftBits > 0) {
    // eslint-disable-next-line security/detect-object-injection -- index 0 is always within bounds for a non-empty Buffer.
    maskedDb[0] = (maskedDb[0]! & (0xff >> leftBits));
  }

  return Buffer.concat([maskedDb, h, Buffer.from([0xbc])]);
}

function pssVerify(
  em: Buffer,
  mHash: Buffer,
  hashAlgorithm: JssHashAlgorithm,
  modulusBits: number,
): boolean {
  const hLen = hashLength(hashAlgorithm);
  const sLen = hLen;
  const emBits = modulusBits - 1;
  const emLen = Math.ceil(emBits / 8);

  // Strip a leading 0x00 byte if the modulus length is one greater than
  // the EM length (this happens when emBits is a multiple of 8 minus 1
  // and privateEncrypt's RSA_NO_PADDING returns a leading zero).
  if (em.length === emLen + 1 && em[0] === 0x00) em = em.subarray(1);
  if (em.length !== emLen) return false;
  if (em[em.length - 1] !== 0xbc) return false;
  if (emLen < hLen + sLen + 2) return false;

  const maskedDb = em.subarray(0, emLen - hLen - 1);
  const h = em.subarray(emLen - hLen - 1, emLen - 1);

  const leftBits = 8 * emLen - emBits;
  if (leftBits > 0) {
    // eslint-disable-next-line security/detect-object-injection -- index 0 is always valid for a non-empty Buffer.
    if ((maskedDb[0]! & ~(0xff >> leftBits)) !== 0) return false;
  }

  const dbMask = mgf1(h, emLen - hLen - 1, hashAlgorithm);
  const db = xor(maskedDb, dbMask);
  if (leftBits > 0) {
    // eslint-disable-next-line security/detect-object-injection -- index 0 is always valid for a non-empty Buffer.
    db[0] = (db[0]! & (0xff >> leftBits));
  }

  const psLen = emLen - sLen - hLen - 2;
  for (let i = 0; i < psLen; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop bounded by psLen.
    if (db[i] !== 0x00) return false;
  }
  if (db[psLen] !== 0x01) return false;

  const salt = db.subarray(psLen + 1);
  const mPrime = Buffer.concat([Buffer.alloc(8, 0), mHash, salt]);
  const hPrime = hashOf(hashAlgorithm, mPrime);
  return constantTimeEqual(h, hPrime);
}

function mgf1(seed: Buffer, length: number, hashAlgorithm: JssHashAlgorithm): Buffer {
  const hLen = hashLength(hashAlgorithm);
  const blocks: Buffer[] = [];
  for (let counter = 0, taken = 0; taken < length; counter += 1) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter, 0);
    blocks.push(hashOf(hashAlgorithm, Buffer.concat([seed, c])));
    taken += hLen;
  }
  return Buffer.concat(blocks).subarray(0, length);
}

function rsaModulusBits(key: KeyObject): number {
  const details = key.asymmetricKeyDetails;
  if (!details || typeof details.modulusLength !== 'number') {
    throw new JssInputError('RSA key did not expose modulusLength');
  }
  return details.modulusLength;
}

// -- ECDSA --------------------------------------------------------------------
//
// JSS § 6.2.1 defines value as `sign(algorithm, key, hash(jcs(...)))`.
// The asymmetric primitive consumes the precomputed digest directly:
// node:crypto's high-level sign API hashes its input internally, so we
// route ECDSA through `@noble/curves` which exposes a true pre-hashed
// signing path. Output is IEEE P-1363 (r||s) per JWA RFC 7518 § 3.4
// and matches dotnet-jss / BouncyCastle's `ECDsaSigner`.
//
// We sign with `lowS: true` (canonical, matches noble default) and
// verify with `lowS: false` so signatures from any conforming
// implementation (BouncyCastle, OpenSSL, others) are accepted. ECDSA
// signatures are not malleable in any way that affects the JSS
// envelope contract, so accepting both forms is interop-correct.

// noble's p256 / p384 / p521 share the same TypeScript shape, so a
// union of the three resolves to a single type. Use one as the
// representative; the runtime ECDSA_CURVES table still picks the
// right curve at call time.
type EcdsaCurve = typeof p256;
type EcdsaAlgorithm = typeof JssAlgorithms.ES256 | typeof JssAlgorithms.ES384 | typeof JssAlgorithms.ES512;

const ECDSA_CURVES: Record<EcdsaAlgorithm, EcdsaCurve> = {
  [JssAlgorithms.ES256]: p256,
  [JssAlgorithms.ES384]: p384,
  [JssAlgorithms.ES512]: p521,
};
const ECDSA_FIELD_BYTES: Record<EcdsaAlgorithm, number> = {
  [JssAlgorithms.ES256]: 32,
  [JssAlgorithms.ES384]: 48,
  [JssAlgorithms.ES512]: 66,
};
const ECDSA_CURVE_NAMES: Record<EcdsaAlgorithm, string> = {
  [JssAlgorithms.ES256]: 'P-256',
  [JssAlgorithms.ES384]: 'P-384',
  [JssAlgorithms.ES512]: 'P-521',
};

function signEcdsa(algorithm: EcdsaAlgorithm, hash: Buffer, privateKey: KeyObject): Buffer {
  // eslint-disable-next-line security/detect-object-injection -- algorithm narrowed to a literal union of three known keys
  const curve = ECDSA_CURVES[algorithm];
  const expectedField = ECDSA_FIELD_BYTES[algorithm];
  const dBytes = ecdsaPrivateScalar(privateKey, algorithm, expectedField);
  const sig = curve.sign(hash, dBytes, { prehash: false, format: 'compact' });
  // Defense-in-depth: confirm we got the expected field-size * 2.
  if (sig.length !== expectedField * 2) {
    throw new JssInputError(
      `Internal: ECDSA signature length mismatch for ${algorithm} (got ${sig.length}, want ${expectedField * 2})`,
    );
  }
  return Buffer.from(sig);
}

function verifyEcdsa(
  algorithm: EcdsaAlgorithm,
  hash: Buffer,
  signature: Buffer,
  publicKey: KeyObject,
): boolean {
  // eslint-disable-next-line security/detect-object-injection -- narrowed
  const curve = ECDSA_CURVES[algorithm];
  const expectedField = ECDSA_FIELD_BYTES[algorithm];
  // A well-formed IEEE P-1363 signature is exactly 2 * field bytes.
  // Reject other lengths up front so tampered envelopes do not trigger
  // noisy errors deep in @noble/curves.
  if (signature.length !== expectedField * 2) return false;
  const pubBytes = ecdsaPublicPointUncompressed(publicKey, algorithm, expectedField);
  try {
    return curve.verify(signature, hash, pubBytes, { prehash: false, lowS: false });
  } catch {
    return false;
  }
}

function ecdsaPrivateScalar(key: KeyObject, algorithm: EcdsaAlgorithm, expectedField: number): Buffer {
  ensureKeyType(key, 'ec', algorithm);
  const jwk = key.export({ format: 'jwk' }) as Record<string, string>;
  if (typeof jwk.d !== 'string') {
    throw new JssInputError(`Algorithm ${algorithm} requires a private EC key with scalar component`);
  }
  ensureCurve(jwk.crv, algorithm);
  const dBytes = base64UrlToBuffer(jwk.d);
  if (dBytes.length !== expectedField) {
    throw new JssInputError(
      `Algorithm ${algorithm} expects a ${expectedField}-byte private scalar; got ${dBytes.length}`,
    );
  }
  return dBytes;
}

function ecdsaPublicPointUncompressed(key: KeyObject, algorithm: EcdsaAlgorithm, expectedField: number): Buffer {
  // Accept either a public or a private KeyObject; for private we
  // export the public half via JWK (Node strips `d` automatically when
  // we ask for the public-key JWK shape).
  const pub = key.type === 'private'
    ? createPublicKey(key).export({ format: 'jwk' }) as Record<string, string>
    : key.export({ format: 'jwk' }) as Record<string, string>;
  if (pub.kty !== 'EC') {
    throw new JssInputError(`Algorithm ${algorithm} requires an EC public key; got kty=${String(pub.kty)}`);
  }
  ensureCurve(pub.crv, algorithm);
  const x = base64UrlToBuffer(pub.x ?? '');
  const y = base64UrlToBuffer(pub.y ?? '');
  if (x.length !== expectedField || y.length !== expectedField) {
    throw new JssInputError(
      `Algorithm ${algorithm} expects ${expectedField}-byte coordinates; got x=${x.length}, y=${y.length}`,
    );
  }
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

function ensureCurve(crv: string | undefined, algorithm: EcdsaAlgorithm): void {
  // eslint-disable-next-line security/detect-object-injection -- algorithm narrowed to EcdsaAlgorithm by the caller; ECDSA_CURVE_NAMES is keyed by exactly that union.
  const want = ECDSA_CURVE_NAMES[algorithm];
  if (crv !== want) {
    throw new JssInputError(
      `Algorithm ${algorithm} requires curve ${want}; got ${String(crv)}`,
    );
  }
}

function base64UrlToBuffer(s: string): Buffer {
  const pad = (4 - (s.length % 4)) % 4;
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad);
  return Buffer.from(b64, 'base64');
}

// -- low-level helpers --------------------------------------------------------

const NODE_HASH_NAMES: Record<JssHashAlgorithm, string> = {
  [JssHashAlgorithms.SHA_256]: 'sha256',
  [JssHashAlgorithms.SHA_384]: 'sha384',
  [JssHashAlgorithms.SHA_512]: 'sha512',
};

function hashOf(name: JssHashAlgorithm, data: Buffer): Buffer {
  // eslint-disable-next-line security/detect-object-injection -- `name` is a JssHashAlgorithm literal narrowed by the caller; NODE_HASH_NAMES is keyed by the same.
  return createHash(NODE_HASH_NAMES[name]).update(data).digest();
}

function xor(a: Buffer, b: Buffer): Buffer {
  if (a.length !== b.length) {
    throw new JssInputError('PSS xor inputs must have equal length');
  }
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop with matched-length buffers
    out[i] = a[i]! ^ b[i]!;
  }
  return out;
}

function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop with matched-length buffers
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

function ensureRegistered(algorithm: string): asserts algorithm is JssAlgorithm {
  if (!isRegisteredAlgorithm(algorithm)) {
    throw new JssInputError(`Unsupported JSS algorithm: ${algorithm}`);
  }
}

function ensureHashRegistered(name: string): void {
  if (!isRegisteredHashAlgorithm(name)) {
    throw new JssInputError(`Unsupported JSS hash algorithm: ${name}`);
  }
}

function ensureHashLength(name: JssHashAlgorithm, hash: Buffer): void {
  const want = hashLength(name);
  if (hash.length !== want) {
    throw new JssInputError(
      `Hash length mismatch for ${name}: expected ${want} bytes, got ${hash.length}`,
    );
  }
}

function ensureKeyType(key: KeyObject, expectedType: string, algorithm: string): void {
  const kt = key.asymmetricKeyType;
  if (expectedType === 'rsa') {
    if (kt !== 'rsa' && kt !== 'rsa-pss') {
      throw new JssInputError(
        `Algorithm ${algorithm} requires an RSA key; got ${String(kt)}`,
      );
    }
    return;
  }
  if (kt !== expectedType) {
    throw new JssInputError(
      `Algorithm ${algorithm} requires a ${expectedType} key; got ${String(kt)}`,
    );
  }
}

