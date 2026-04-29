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
 * Runtime-neutral crypto backend contract.
 *
 * Two implementations of this interface ship side-by-side:
 *
 *   - `node.ts` wraps `node:crypto`.
 *   - `web.ts` wraps `crypto.subtle` and `@noble/curves`, with a
 *     pure-JS BigInt path for raw RSA (which WebCrypto does not
 *     expose).
 *
 * Selection happens via the `package.json` `"imports"` field — Node's
 * resolver picks the node build, bundlers pick the web build. The
 * rest of the library imports from `#crypto-backend` and never reaches
 * for `node:crypto` or `crypto.subtle` directly.
 *
 * Every method is async because WebCrypto cannot do synchronous key
 * import / sign / verify. The library's top-level sign() and verify()
 * are already async, so this aligns the internal contract with the
 * external one.
 */

import type { JwkPublicKey, KeyInput } from '../../types.js';

/** Hash algorithm names shared across JSF and JSS — the JSS / IANA wire form. */
export type Sha = 'sha-256' | 'sha-384' | 'sha-512';

/** Named NIST curves recognized by both formats. */
export type EcCurve = 'P-256' | 'P-384' | 'P-521';

/** Edwards curves used for EdDSA. */
export type EdCurve = 'Ed25519' | 'Ed448';

/**
 * Asymmetric key kinds the backends expose. `'oct'` is symmetric
 * material for HMAC.
 */
export type KeyKind = 'rsa' | 'ec' | 'ed25519' | 'ed448' | 'oct';

/**
 * Common metadata attached to every key handle so callers can dispatch
 * algorithm selection without backend-specific introspection.
 */
export interface KeyMetadata {
  readonly kind: KeyKind;
  readonly curve: EcCurve | EdCurve | null;
  /** RSA modulus length in bits. Populated only for `kind === 'rsa'`. */
  readonly rsaModulusBits: number | null;
}

/**
 * A backend-neutral handle for a public key. Holds whatever the
 * backend needs internally; consumers go through the methods.
 */
export interface PublicKeyHandle extends KeyMetadata {
  /** Lossless export to JWK in the JSF / JSS spec shape. */
  exportJwk(): Promise<JwkPublicKey>;
  /** Export the key as a PEM string with BEGIN/END headers (SPKI for asymmetric). */
  exportSpkiPem(): Promise<string>;
}

/**
 * A backend-neutral handle for a private key. `publicHandle()` derives
 * the public half lazily.
 */
export interface PrivateKeyHandle extends KeyMetadata {
  publicHandle(): Promise<PublicKeyHandle>;
  /**
   * Convenience: export only the public JWK, with private parameters
   * stripped. Equivalent to `(await this.publicHandle()).exportJwk()`.
   */
  exportPublicJwk(): Promise<JwkPublicKey>;
}

/** Symmetric key handle (HMAC). */
export interface SymmetricKeyHandle extends KeyMetadata {
  readonly kind: 'oct';
}

/**
 * Output sentinel: a backend may return an error code instead of a
 * boolean for verify() failures that look like programmer bugs (wrong
 * key shape) rather than tamper. Most callers treat this as `false`.
 */
export type VerifyResult = boolean;

/** The crypto backend contract. */
export interface CryptoBackend {
  /** Backend identifier — `'node'` or `'web'`. Useful for diagnostics. */
  readonly id: 'node' | 'web';

  // -- Hashing & random ----------------------------------------------------

  digest(hash: Sha, data: Uint8Array): Promise<Uint8Array>;
  randomBytes(length: number): Uint8Array;

  // -- Key import ----------------------------------------------------------

  importPrivateKey(input: KeyInput): Promise<PrivateKeyHandle>;
  importPublicKey(input: KeyInput): Promise<PublicKeyHandle>;
  importHmacKey(input: KeyInput, hash: Sha): Promise<SymmetricKeyHandle>;

  // -- X.509 certificate parsing -----------------------------------------

  parseCertSpkiPublicKey(certDer: Uint8Array): Promise<PublicKeyHandle>;

  // -- Message-mode sign / verify (JSF semantics) -------------------------
  //
  // The algorithm hashes its input internally per JWA / JSF.

  signRsaPkcs1(hash: Sha, message: Uint8Array, key: PrivateKeyHandle): Promise<Uint8Array>;
  verifyRsaPkcs1(hash: Sha, message: Uint8Array, signature: Uint8Array, key: PublicKeyHandle): Promise<VerifyResult>;

  signRsaPss(hash: Sha, message: Uint8Array, saltLength: number, key: PrivateKeyHandle): Promise<Uint8Array>;
  verifyRsaPss(hash: Sha, message: Uint8Array, saltLength: number, signature: Uint8Array, key: PublicKeyHandle): Promise<VerifyResult>;

  /** Returns IEEE P-1363 (r || s) regardless of backend. */
  signEcdsa(hash: Sha, message: Uint8Array, key: PrivateKeyHandle): Promise<Uint8Array>;
  verifyEcdsa(hash: Sha, message: Uint8Array, signature: Uint8Array, key: PublicKeyHandle): Promise<VerifyResult>;

  signEddsa(message: Uint8Array, key: PrivateKeyHandle): Promise<Uint8Array>;
  verifyEddsa(message: Uint8Array, signature: Uint8Array, key: PublicKeyHandle): Promise<VerifyResult>;

  hmacSign(hash: Sha, key: SymmetricKeyHandle, data: Uint8Array): Promise<Uint8Array>;
  /** Constant-time. */
  hmacVerify(hash: Sha, key: SymmetricKeyHandle, data: Uint8Array, mac: Uint8Array): Promise<VerifyResult>;

  // -- Pre-hashed sign / verify (JSS semantics) ---------------------------
  //
  // The algorithm consumes a digest produced by `hash`. RSA paths
  // perform manual EMSA-PSS / DigestInfo encoding; ECDSA delegates to
  // a curve library that accepts a digest directly.

  signRsaPkcs1Prehashed(hash: Sha, digest: Uint8Array, key: PrivateKeyHandle): Promise<Uint8Array>;
  verifyRsaPkcs1Prehashed(hash: Sha, digest: Uint8Array, signature: Uint8Array, key: PublicKeyHandle): Promise<VerifyResult>;

  signRsaPssPrehashed(hash: Sha, digest: Uint8Array, saltLength: number, key: PrivateKeyHandle): Promise<Uint8Array>;
  verifyRsaPssPrehashed(hash: Sha, digest: Uint8Array, saltLength: number, signature: Uint8Array, key: PublicKeyHandle): Promise<VerifyResult>;

  signEcdsaPrehashed(curve: EcCurve, digest: Uint8Array, key: PrivateKeyHandle): Promise<Uint8Array>;
  verifyEcdsaPrehashed(curve: EcCurve, digest: Uint8Array, signature: Uint8Array, key: PublicKeyHandle): Promise<VerifyResult>;
}
