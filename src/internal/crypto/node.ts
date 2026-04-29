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
 * Node `crypto` backend.
 *
 * Selected automatically when the package is consumed in a Node-like
 * runtime via `package.json` `"imports"`. Wraps `node:crypto.KeyObject`
 * and routes:
 *
 *   - JSF (message-mode) RSA / ECDSA / EdDSA / HMAC through
 *     `crypto.sign` / `crypto.verify` / `createHmac` / `timingSafeEqual`.
 *   - JSS (pre-hashed) RSA through manual EMSA-PSS / DigestInfo
 *     encoding plus `privateEncrypt(RSA_NO_PADDING)` /
 *     `publicDecrypt(RSA_NO_PADDING)`. Node has no high-level
 *     pre-hashed RSA primitive, so this is the only viable path.
 *   - JSS (pre-hashed) ECDSA through `@noble/curves`. Node's
 *     `crypto.sign` always re-hashes its input for ECDSA, so a curve
 *     library that accepts a digest directly is required.
 *
 * The handles wrap a Node `KeyObject` and cache the metadata the
 * format orchestrators care about so the public surface stays uniform
 * with the Web backend.
 */

import {
  constants as cryptoConstants,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  KeyObject,
  privateEncrypt,
  publicDecrypt,
  randomBytes as nodeRandomBytes,
  sign as nodeSign,
  timingSafeEqual,
  verify as nodeVerify,
  X509Certificate,
} from 'node:crypto';

import { p256, p384, p521 } from '@noble/curves/nist.js';

import type { JwkPublicKey, KeyInput } from '../../types.js';
import {
  buildDigestInfo,
  constantTimeEqual,
  hashLength,
  pkcs1V15Pad,
  pkcs1V15Unpad,
  pssEncode,
  pssVerify,
} from './shared.js';
import type {
  CryptoBackend,
  EcCurve,
  EdCurve,
  KeyKind,
  PrivateKeyHandle,
  PublicKeyHandle,
  Sha,
  SymmetricKeyHandle,
  VerifyResult,
} from './types.js';

// -- Hash name mapping --------------------------------------------------------

const NODE_HASH_NAMES: Record<Sha, string> = {
  'sha-256': 'sha256',
  'sha-384': 'sha384',
  'sha-512': 'sha512',
};

function nodeHashName(hash: Sha): string {
  // eslint-disable-next-line security/detect-object-injection -- `hash` narrowed to a Sha literal.
  return NODE_HASH_NAMES[hash];
}

// -- Curve helpers -----------------------------------------------------------

function toJwkCurve(node: string | undefined | null): string | null {
  if (!node) return null;
  switch (node) {
    case 'prime256v1':
    case 'P-256': return 'P-256';
    case 'secp384r1':
    case 'P-384': return 'P-384';
    case 'secp521r1':
    case 'P-521': return 'P-521';
    default: return node;
  }
}

const NOBLE_CURVES: Record<EcCurve, typeof p256> = {
  'P-256': p256,
  'P-384': p384,
  'P-521': p521,
};
const NOBLE_FIELD_BYTES: Record<EcCurve, number> = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
};

// -- Key handle classes ------------------------------------------------------

class NodePublicKey implements PublicKeyHandle {
  readonly kind: KeyKind;
  readonly curve: EcCurve | EdCurve | null;
  readonly rsaModulusBits: number | null;
  /** @internal */ readonly keyObject: KeyObject;

  constructor(keyObject: KeyObject) {
    this.keyObject = keyObject;
    const meta = describeKey(keyObject);
    this.kind = meta.kind;
    this.curve = meta.curve;
    this.rsaModulusBits = meta.rsaModulusBits;
  }

  async exportJwk(): Promise<JwkPublicKey> {
    return this.keyObject.export({ format: 'jwk' }) as unknown as JwkPublicKey;
  }

  async exportSpkiPem(): Promise<string> {
    if (this.kind === 'oct') {
      throw new Error('Cannot export symmetric key as SPKI PEM');
    }
    const pem = this.keyObject.export({ type: 'spki', format: 'pem' });
    return typeof pem === 'string' ? pem : pem.toString('utf8');
  }
}

class NodePrivateKey implements PrivateKeyHandle {
  readonly kind: KeyKind;
  readonly curve: EcCurve | EdCurve | null;
  readonly rsaModulusBits: number | null;
  /** @internal */ readonly keyObject: KeyObject;

  constructor(keyObject: KeyObject) {
    this.keyObject = keyObject;
    const meta = describeKey(keyObject);
    this.kind = meta.kind;
    this.curve = meta.curve;
    this.rsaModulusBits = meta.rsaModulusBits;
  }

  async publicHandle(): Promise<PublicKeyHandle> {
    if (this.keyObject.type === 'secret') {
      // For HMAC keys "public" is the same key; callers should not
      // call publicHandle() on symmetric keys.
      throw new Error('Symmetric keys do not have a separable public half');
    }
    return new NodePublicKey(createPublicKey(this.keyObject));
  }

  async exportPublicJwk(): Promise<JwkPublicKey> {
    const pub = await this.publicHandle();
    return pub.exportJwk();
  }
}

class NodeSymmetricKey implements SymmetricKeyHandle {
  readonly kind: 'oct' = 'oct' as const;
  readonly curve = null;
  readonly rsaModulusBits = null;
  /** @internal */ readonly keyObject: KeyObject;

  constructor(keyObject: KeyObject) {
    this.keyObject = keyObject;
  }
}

function describeKey(keyObject: KeyObject): {
  kind: KeyKind;
  curve: EcCurve | EdCurve | null;
  rsaModulusBits: number | null;
} {
  if (keyObject.type === 'secret') {
    return { kind: 'oct', curve: null, rsaModulusBits: null };
  }
  const akt = keyObject.asymmetricKeyType;
  if (akt === 'rsa' || akt === 'rsa-pss') {
    const bits = keyObject.asymmetricKeyDetails?.modulusLength ?? null;
    return { kind: 'rsa', curve: null, rsaModulusBits: bits };
  }
  if (akt === 'ec') {
    const curve = toJwkCurve(keyObject.asymmetricKeyDetails?.namedCurve ?? null);
    return { kind: 'ec', curve: (curve as EcCurve | null), rsaModulusBits: null };
  }
  if (akt === 'ed25519') return { kind: 'ed25519', curve: 'Ed25519', rsaModulusBits: null };
  if (akt === 'ed448') return { kind: 'ed448', curve: 'Ed448', rsaModulusBits: null };
  throw new Error(`Unsupported asymmetric key type: ${String(akt)}`);
}

// -- Key import dispatchers --------------------------------------------------

function isJwkInput(input: unknown): input is JwkPublicKey {
  return typeof input === 'object' && input !== null && 'kty' in input;
}

function isRawBytes(input: unknown): input is Buffer | Uint8Array {
  return Buffer.isBuffer(input) || input instanceof Uint8Array;
}

function nodeImportPrivate(input: KeyInput): KeyObject {
  if (input instanceof KeyObject) {
    if (input.type === 'private' || input.type === 'secret') return input;
    throw new Error('KeyObject must be a private or secret key');
  }
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('{')) {
      return createPrivateKey({ key: JSON.parse(trimmed) as Record<string, unknown>, format: 'jwk' });
    }
    return createPrivateKey({ key: trimmed, format: 'pem' });
  }
  if (isRawBytes(input)) {
    // Raw bytes are HMAC key material; PKCS#8 DER decoding is
    // ambiguous and goes through PEM or JWK explicitly.
    return createSecretKey(Buffer.isBuffer(input) ? input : Buffer.from(input));
  }
  if (isJwkInput(input)) {
    if (input.kty === 'oct') {
      if (!input.k) throw new Error('JWK oct missing k');
      return createSecretKey(Buffer.from(input.k, 'base64url'));
    }
    return createPrivateKey({ key: input as unknown as Record<string, unknown>, format: 'jwk' });
  }
  throw new Error('Unsupported private key input');
}

function nodeImportPublic(input: KeyInput): KeyObject {
  if (input instanceof KeyObject) {
    if (input.type === 'public') return input;
    if (input.type === 'private') return createPublicKey(input);
    return input;   // secret
  }
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('{')) {
      return createPublicKey({ key: JSON.parse(trimmed) as Record<string, unknown>, format: 'jwk' });
    }
    return createPublicKey({ key: trimmed, format: 'pem' });
  }
  if (isRawBytes(input)) {
    return createSecretKey(Buffer.isBuffer(input) ? input : Buffer.from(input));
  }
  if (isJwkInput(input)) {
    if (input.kty === 'oct') {
      if (!input.k) throw new Error('JWK oct missing k');
      return createSecretKey(Buffer.from(input.k, 'base64url'));
    }
    return createPublicKey({ key: input as unknown as Record<string, unknown>, format: 'jwk' });
  }
  throw new Error('Unsupported public key input');
}

// -- The backend implementation ----------------------------------------------

const digest = async (hash: Sha, data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(createHash(nodeHashName(hash)).update(data).digest());

const randomBytes = (n: number): Uint8Array =>
  new Uint8Array(nodeRandomBytes(n));

export const backend: CryptoBackend = {
  id: 'node',

  digest,
  randomBytes,

  async importPrivateKey(input: KeyInput): Promise<PrivateKeyHandle> {
    return new NodePrivateKey(nodeImportPrivate(input));
  },

  async importPublicKey(input: KeyInput): Promise<PublicKeyHandle> {
    return new NodePublicKey(nodeImportPublic(input));
  },

  async importHmacKey(input: KeyInput, _hash: Sha): Promise<SymmetricKeyHandle> {
    const ko = nodeImportPrivate(input);
    if (ko.type !== 'secret') {
      throw new Error('HMAC requires symmetric key material');
    }
    return new NodeSymmetricKey(ko);
  },

  async parseCertSpkiPublicKey(certDer: Uint8Array): Promise<PublicKeyHandle> {
    const cert = new X509Certificate(Buffer.from(certDer));
    return new NodePublicKey(cert.publicKey);
  },

  // -- JSF (message-mode) ----------------------------------------------------

  async signRsaPkcs1(hash, message, key) {
    const k = (key as NodePrivateKey).keyObject;
    return new Uint8Array(nodeSign(nodeHashName(hash), message, k));
  },
  async verifyRsaPkcs1(hash, message, signature, key) {
    const k = (key as NodePublicKey).keyObject;
    try { return nodeVerify(nodeHashName(hash), message, k, signature); }
    catch { return false; }
  },

  async signRsaPss(hash, message, saltLength, key) {
    const k = (key as NodePrivateKey).keyObject;
    return new Uint8Array(nodeSign(nodeHashName(hash), message, {
      key: k,
      padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
      saltLength,
    }));
  },
  async verifyRsaPss(hash, message, saltLength, signature, key) {
    const k = (key as NodePublicKey).keyObject;
    try {
      return nodeVerify(nodeHashName(hash), message, {
        key: k,
        padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
        saltLength,
      }, signature);
    } catch { return false; }
  },

  async signEcdsa(hash, message, key) {
    const k = (key as NodePrivateKey).keyObject;
    return new Uint8Array(nodeSign(nodeHashName(hash), message, {
      key: k,
      dsaEncoding: 'ieee-p1363',
    }));
  },
  async verifyEcdsa(hash, message, signature, key) {
    const k = (key as NodePublicKey).keyObject;
    try {
      return nodeVerify(nodeHashName(hash), message, {
        key: k,
        dsaEncoding: 'ieee-p1363',
      }, signature);
    } catch { return false; }
  },

  async signEddsa(message, key) {
    const k = (key as NodePrivateKey).keyObject;
    return new Uint8Array(nodeSign(null, message, k));
  },
  async verifyEddsa(message, signature, key) {
    const k = (key as NodePublicKey).keyObject;
    try { return nodeVerify(null, message, k, signature); }
    catch { return false; }
  },

  async hmacSign(hash, key, data) {
    const k = (key as NodeSymmetricKey).keyObject;
    return new Uint8Array(createHmac(nodeHashName(hash), k).update(data).digest());
  },
  async hmacVerify(hash, key, data, mac) {
    const k = (key as NodeSymmetricKey).keyObject;
    const computed = createHmac(nodeHashName(hash), k).update(data).digest();
    if (computed.length !== mac.length) return false;
    return timingSafeEqual(computed, Buffer.from(mac));
  },

  // -- JSS (pre-hashed RSA via raw RSA + manual padding) --------------------

  async signRsaPkcs1Prehashed(hash, digestBytes, key) {
    const k = (key as NodePrivateKey).keyObject;
    const digestInfo = buildDigestInfo(hash, digestBytes);
    // node:crypto can do PKCS#1 padding for us when given the
    // DigestInfo bytes via privateEncrypt(RSA_PKCS1_PADDING).
    return new Uint8Array(privateEncrypt(
      { key: k, padding: cryptoConstants.RSA_PKCS1_PADDING },
      Buffer.from(digestInfo),
    ));
  },
  async verifyRsaPkcs1Prehashed(hash, digestBytes, signature, key) {
    const k = (key as NodePublicKey).keyObject;
    try {
      const decoded = publicDecrypt(
        { key: k, padding: cryptoConstants.RSA_PKCS1_PADDING },
        Buffer.from(signature),
      );
      const expected = buildDigestInfo(hash, digestBytes);
      return constantTimeEqual(new Uint8Array(decoded), expected);
    } catch { return false; }
  },

  async signRsaPssPrehashed(hash, digestBytes, saltLength, key) {
    const k = (key as NodePrivateKey).keyObject;
    if (key.rsaModulusBits === null) throw new Error('RSA key did not expose modulusLength');
    const em = await pssEncode(digest, randomBytes, hash, digestBytes, saltLength, key.rsaModulusBits);
    return new Uint8Array(privateEncrypt(
      { key: k, padding: cryptoConstants.RSA_NO_PADDING },
      Buffer.from(em),
    ));
  },
  async verifyRsaPssPrehashed(hash, digestBytes, saltLength, signature, key) {
    const k = (key as NodePublicKey).keyObject;
    if (key.rsaModulusBits === null) return false;
    try {
      const em = publicDecrypt(
        { key: k, padding: cryptoConstants.RSA_NO_PADDING },
        Buffer.from(signature),
      );
      return await pssVerify(digest, hash, new Uint8Array(em), digestBytes, saltLength, key.rsaModulusBits);
    } catch { return false; }
  },

  // -- JSS (pre-hashed ECDSA via @noble/curves) -----------------------------

  async signEcdsaPrehashed(curve, digestBytes, key) {
    const np = (key as NodePrivateKey);
    if (np.kind !== 'ec' || np.curve !== curve) {
      throw new Error(`ECDSA key/curve mismatch: expected ${curve}, got ${np.curve}`);
    }
    const jwk = np.keyObject.export({ format: 'jwk' }) as Record<string, string>;
    if (typeof jwk.d !== 'string') {
      throw new Error('ECDSA pre-hashed sign requires private key with d');
    }
    // eslint-disable-next-line security/detect-object-injection -- curve narrowed to EcCurve.
    const noble = NOBLE_CURVES[curve];
    // eslint-disable-next-line security/detect-object-injection -- curve narrowed.
    const fieldBytes = NOBLE_FIELD_BYTES[curve];
    const dBytes = b64uToBytes(jwk.d);
    if (dBytes.length !== fieldBytes) {
      throw new Error(`ECDSA private scalar length mismatch for ${curve}`);
    }
    const sig = noble.sign(digestBytes, dBytes, { prehash: false, format: 'compact' });
    if (sig.length !== fieldBytes * 2) {
      throw new Error(`Internal: ECDSA signature length mismatch for ${curve}`);
    }
    return new Uint8Array(sig);
  },
  async verifyEcdsaPrehashed(curve, digestBytes, signature, key) {
    const np = (key as NodePublicKey);
    if (np.kind !== 'ec' || np.curve !== curve) return false;
    // eslint-disable-next-line security/detect-object-injection -- curve narrowed.
    const fieldBytes = NOBLE_FIELD_BYTES[curve];
    if (signature.length !== fieldBytes * 2) return false;
    // For private key objects we get the public half via createPublicKey.
    const pubObj = np.keyObject.type === 'private'
      ? createPublicKey(np.keyObject)
      : np.keyObject;
    const pubJwk = pubObj.export({ format: 'jwk' }) as Record<string, string>;
    if (pubJwk.kty !== 'EC' || pubJwk.crv !== curve) return false;
    const x = b64uToBytes(pubJwk.x ?? '');
    const y = b64uToBytes(pubJwk.y ?? '');
    if (x.length !== fieldBytes || y.length !== fieldBytes) return false;
    const pubBytes = new Uint8Array(1 + x.length + y.length);
    pubBytes[0] = 0x04;
    pubBytes.set(x, 1);
    pubBytes.set(y, 1 + x.length);
    // eslint-disable-next-line security/detect-object-injection -- curve narrowed.
    const noble = NOBLE_CURVES[curve];
    try {
      return noble.verify(signature, digestBytes, pubBytes, { prehash: false, lowS: false });
    } catch { return false; }
  },
};

function b64uToBytes(s: string): Uint8Array {
  const pad = (4 - (s.length % 4)) % 4;
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad);
  return new Uint8Array(Buffer.from(b64, 'base64'));
}
