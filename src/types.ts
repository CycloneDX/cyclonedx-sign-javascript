/**
 * Shared type definitions for the @cyclonedx/sign package.
 *
 * This module holds only the types that are neutral across JSF and JSS.
 * Format-specific types live in ./jsf/types.ts and ./jss/types.ts.
 *
 * The JSF-specific names that previously lived here (JsfAlgorithm,
 * JsfSigner, SignOptions, VerifyOptions, VerifyResult, JsfJwkKeyType,
 * JsfPublicKey) are re-exported at the bottom of this file so existing
 * consumers that import from `./types.js` continue to work unchanged.
 */

import type { KeyObject } from 'node:crypto';

/** JSON value types recognized by JCS, JSF, and JSS. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | JsonObject;

export interface JsonObject {
  [key: string]: JsonValue;
}

/** JWK key types recognized by both JSF and JSS signer envelopes. */
export type JwkKeyType = 'RSA' | 'EC' | 'OKP' | 'oct';

/**
 * JWK shape used by embedded publicKey fields. Both JSF and JSS use the
 * same JWK layout, so this type is shared.
 */
export interface JwkPublicKey {
  kty: JwkKeyType;
  // RSA
  n?: string;
  e?: string;
  // EC / OKP
  crv?: string;
  x?: string;
  y?: string;
  // HMAC (signing only; never embedded in a signed envelope because
  // symmetric keys are secret, but modeled for completeness).
  k?: string;
  [extra: string]: unknown;
}

/**
 * Accepted private-key and public-key inputs for signing and verifying.
 *
 * JWK objects are fully-described material. Strings accept PEM-encoded
 * PKCS#8 private keys, SPKI public keys, X.509 certificates, or JWK
 * JSON. Buffers are treated as raw symmetric key material. KeyObject
 * instances pass through untouched.
 *
 * For HMAC (HS256/384/512) pass either a Buffer of raw key bytes or a
 * JWK with kty='oct' and k set to the base64url-encoded key.
 */
export type KeyInput = JwkPublicKey | string | Buffer | Uint8Array | KeyObject;

/**
 * Signature format discriminator used by the top-level
 * sign / verify / signBom / verifyBom API.
 *
 *   'jsf' — JSON Signature Format. Used by CycloneDX 1.x.
 *   'jss' — JSON Signature Schema (X.590). Used by CycloneDX 2.x.
 */
export type SignatureFormat = 'jsf' | 'jss';

// -- Backward-compatibility re-exports ---------------------------------------
// These were previously defined in this file. They now live alongside the
// format they belong to, but the old import paths keep working.

export type { JsfAlgorithm, JsfSigner } from './jsf/types.js';
export type {
  JsfSignOptions as SignOptions,
  JsfVerifyOptions as VerifyOptions,
  JsfVerifyResult as VerifyResult,
} from './jsf/types.js';

/** @deprecated Use JwkKeyType. */
export type JsfJwkKeyType = JwkKeyType;

/** @deprecated Use JwkPublicKey. */
export type JsfPublicKey = JwkPublicKey;
