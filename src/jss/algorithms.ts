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
 *   - ECDSA (`ES256`/`ES384`/`ES512`): NOT IMPLEMENTED. Pure
 *     `node:crypto` cannot consume a pre-hashed digest for ECDSA
 *     without an external dependency. This is documented in
 *     `docs/specs/jss-implementation-plan.md` § 8.18 and tracked as
 *     a roadmap item; calling sign/verify with these algorithms
 *     throws `JssNotImplementedError`.
 */

import {
  constants as cryptoConstants,
  createHash,
  KeyObject,
  privateDecrypt,
  privateEncrypt,
  publicDecrypt,
  publicEncrypt,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';

import { JssInputError, JssNotImplementedError } from '../errors.js';
import type { JssHashAlgorithm } from './hash.js';
import { hashLength, isRegisteredHashAlgorithm } from './hash.js';

export type JssAlgorithm =
  | 'RS256' | 'RS384' | 'RS512'
  | 'PS256' | 'PS384' | 'PS512'
  | 'ES256' | 'ES384' | 'ES512'
  | 'Ed25519' | 'Ed448';

const REGISTERED: ReadonlySet<JssAlgorithm> = new Set<JssAlgorithm>([
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'Ed448',
]);

const NOT_YET_IMPLEMENTED: ReadonlySet<JssAlgorithm> = new Set<JssAlgorithm>([
  'ES256', 'ES384', 'ES512',
]);

export function isRegisteredAlgorithm(name: string): name is JssAlgorithm {
  return REGISTERED.has(name as JssAlgorithm);
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
  ensureSupported(algorithm);
  ensureHashRegistered(hashAlgorithm);
  ensureHashLength(hashAlgorithm as JssHashAlgorithm, hash);

  if (algorithm === 'Ed25519' || algorithm === 'Ed448') {
    return signEdDsa(algorithm, hash, privateKey);
  }
  if (algorithm.startsWith('RS')) {
    return signRsaPkcs1(hashAlgorithm as JssHashAlgorithm, hash, privateKey);
  }
  if (algorithm.startsWith('PS')) {
    return signRsaPss(hashAlgorithm as JssHashAlgorithm, hash, privateKey);
  }
  /* c8 ignore next */
  throw new JssNotImplementedError(`JSS algorithm ${algorithm} not implemented`);
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
  ensureSupported(algorithm);
  ensureHashRegistered(hashAlgorithm);
  ensureHashLength(hashAlgorithm as JssHashAlgorithm, hash);

  if (algorithm === 'Ed25519' || algorithm === 'Ed448') {
    return verifyEdDsa(algorithm, hash, signature, publicKey);
  }
  if (algorithm.startsWith('RS')) {
    return verifyRsaPkcs1(hashAlgorithm as JssHashAlgorithm, hash, signature, publicKey);
  }
  if (algorithm.startsWith('PS')) {
    return verifyRsaPss(hashAlgorithm as JssHashAlgorithm, hash, signature, publicKey);
  }
  /* c8 ignore next */
  return false;
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

// -- low-level helpers --------------------------------------------------------

function hashOf(name: JssHashAlgorithm, data: Buffer): Buffer {
  // eslint-disable-next-line security/detect-object-injection -- `name` is a JssHashAlgorithm literal narrowed by the caller.
  return createHash({ 'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512' }[name])
    .update(data)
    .digest();
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

function ensureSupported(algorithm: JssAlgorithm): void {
  if (NOT_YET_IMPLEMENTED.has(algorithm)) {
    throw new JssNotImplementedError(
      `JSS algorithm ${algorithm} (ECDSA) is not yet implemented in this build. ` +
        `Pure node:crypto cannot consume a pre-hashed digest for ECDSA without ` +
        `double-hashing. Tracked in docs/specs/jss-implementation-plan.md.`,
    );
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

// keep these imports referenced even though we don't use them, so a future
// implementation that needs them does not need an additional import edit.
void privateDecrypt;
void publicEncrypt;
