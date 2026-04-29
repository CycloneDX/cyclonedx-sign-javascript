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
 * The algorithm consumes the precomputed hash directly:
 *
 *   - EdDSA: Ed25519/Ed448 sign the hash bytes (the algorithm
 *     internally re-hashes as part of the curve operation, which is
 *     intrinsic).
 *   - RSA PKCS#1 v1.5: a DigestInfo SEQUENCE wraps the supplied hash
 *     and is signed with PKCS#1 v1.5 padding.
 *   - RSA-PSS: the EMSA-PSS encoded message is constructed manually
 *     from the supplied hash, then RSA private-keyed.
 *   - ECDSA (`ES256`/`ES384`/`ES512`): IEEE P-1363 (r || s) per JWA
 *     RFC 7518 § 3.4. Sign normalizes to low-S; verify accepts both.
 *
 * All these operations are routed through the active crypto backend
 * (`#crypto-backend`). Node uses `privateEncrypt(RSA_NO_PADDING)` and
 * `@noble/curves`; Web uses pure-JS BigInt RSA and `@noble/curves`.
 * The PSS / DigestInfo encoding lives in `internal/crypto/shared.ts`
 * and is shared between the backends.
 */

import { backend } from '#crypto-backend';
import type {
  PrivateKeyHandle,
  PublicKeyHandle,
  EcCurve,
} from '../internal/crypto/types.js';
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

const ECDSA_FIELD_BYTES: Record<'ES256' | 'ES384' | 'ES512', number> = {
  ES256: 32,
  ES384: 48,
  ES512: 66,
};
const ECDSA_CURVES: Record<'ES256' | 'ES384' | 'ES512', EcCurve> = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
};

const PSS_SALT_LENGTHS: Record<JssHashAlgorithm, number> = {
  [JssHashAlgorithms.SHA_256]: 32,
  [JssHashAlgorithms.SHA_384]: 48,
  [JssHashAlgorithms.SHA_512]: 64,
};

/**
 * Sign a precomputed hash with the JSS algorithm.
 */
export async function signHash(
  algorithm: string,
  hashAlgorithm: string,
  hash: Uint8Array,
  privateKey: PrivateKeyHandle,
): Promise<Uint8Array> {
  ensureRegistered(algorithm);
  ensureHashRegistered(hashAlgorithm);
  ensureHashLength(hashAlgorithm as JssHashAlgorithm, hash);
  const h = hashAlgorithm as JssHashAlgorithm;
  switch (familyOf(algorithm)) {
    case 'eddsa': {
      ensureKeyType(privateKey, algorithm.toLowerCase(), algorithm);
      return backend.signEddsa(hash, privateKey);
    }
    case 'rsa-pkcs1': {
      ensureKeyType(privateKey, 'rsa', algorithm);
      return backend.signRsaPkcs1Prehashed(h, hash, privateKey);
    }
    case 'rsa-pss': {
      ensureKeyType(privateKey, 'rsa', algorithm);
      // eslint-disable-next-line security/detect-object-injection -- key narrowed via ensureHashRegistered.
      const saltLength = PSS_SALT_LENGTHS[h];
      return backend.signRsaPssPrehashed(h, hash, saltLength, privateKey);
    }
    case 'ecdsa': {
      ensureKeyType(privateKey, 'ec', algorithm);
       
      const curve = ECDSA_CURVES[algorithm as 'ES256' | 'ES384' | 'ES512'];
      ensureCurve(privateKey.curve, curve, algorithm);
      const sig = await backend.signEcdsaPrehashed(curve, hash, privateKey);
       
      const expected = ECDSA_FIELD_BYTES[algorithm as 'ES256' | 'ES384' | 'ES512'] * 2;
      if (sig.length !== expected) {
        throw new JssInputError(
          `Internal: ECDSA signature length mismatch for ${algorithm} (got ${sig.length}, want ${expected})`,
        );
      }
      return sig;
    }
  }
}

/**
 * Verify a JSS signature against a precomputed hash.
 */
export async function verifyHash(
  algorithm: string,
  hashAlgorithm: string,
  hash: Uint8Array,
  signature: Uint8Array,
  publicKey: PublicKeyHandle,
): Promise<boolean> {
  ensureRegistered(algorithm);
  ensureHashRegistered(hashAlgorithm);
  ensureHashLength(hashAlgorithm as JssHashAlgorithm, hash);
  const h = hashAlgorithm as JssHashAlgorithm;
  switch (familyOf(algorithm)) {
    case 'eddsa': {
      ensureKeyType(publicKey, algorithm.toLowerCase(), algorithm);
      return backend.verifyEddsa(hash, signature, publicKey);
    }
    case 'rsa-pkcs1': {
      ensureKeyType(publicKey, 'rsa', algorithm);
      return backend.verifyRsaPkcs1Prehashed(h, hash, signature, publicKey);
    }
    case 'rsa-pss': {
      ensureKeyType(publicKey, 'rsa', algorithm);
      // eslint-disable-next-line security/detect-object-injection -- h narrowed.
      const saltLength = PSS_SALT_LENGTHS[h];
      return backend.verifyRsaPssPrehashed(h, hash, saltLength, signature, publicKey);
    }
    case 'ecdsa': {
      ensureKeyType(publicKey, 'ec', algorithm);
       
      const curve = ECDSA_CURVES[algorithm as 'ES256' | 'ES384' | 'ES512'];
      ensureCurve(publicKey.curve, curve, algorithm);
       
      const expected = ECDSA_FIELD_BYTES[algorithm as 'ES256' | 'ES384' | 'ES512'] * 2;
      if (signature.length !== expected) return false;
      return backend.verifyEcdsaPrehashed(curve, hash, signature, publicKey);
    }
  }
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

function ensureHashLength(name: JssHashAlgorithm, hash: Uint8Array): void {
  const want = hashLength(name);
  if (hash.length !== want) {
    throw new JssInputError(
      `Hash length mismatch for ${name}: expected ${want} bytes, got ${hash.length}`,
    );
  }
}

function ensureKeyType(
  key: { kind: string },
  expected: string,
  algorithm: string,
): void {
  const kt = key.kind;
  if (expected === 'rsa') {
    if (kt !== 'rsa') {
      throw new JssInputError(
        `Algorithm ${algorithm} requires an RSA key; got ${String(kt)}`,
      );
    }
    return;
  }
  if (kt !== expected) {
    throw new JssInputError(
      `Algorithm ${algorithm} requires a ${expected} key; got ${String(kt)}`,
    );
  }
}

function ensureCurve(
  actual: string | null,
  expected: EcCurve,
  algorithm: string,
): void {
  if (actual !== expected) {
    throw new JssInputError(
      `Algorithm ${algorithm} requires curve ${expected}; got ${String(actual)}`,
    );
  }
}
