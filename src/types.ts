/**
 * Public type definitions for the JSF package.
 *
 * These types cover the JSF envelope, the supported algorithms per the
 * JSF 0.82 specification (and the CycloneDX jsf-0.82 subschema), and
 * the input shapes for sign and verify.
 */

import type { KeyObject } from 'node:crypto';

/** JSON value types recognized by JCS and JSF. */
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

/**
 * JSF algorithm names. These match the JSF 0.82 specification and the
 * CycloneDX jsf-0.82 subschema enum exactly.
 */
export type JsfAlgorithm =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'Ed25519'
  | 'Ed448'
  | 'HS256'
  | 'HS384'
  | 'HS512';

/** JWK shape subset used by JSF's publicKey element. */
export type JsfJwkKeyType = 'RSA' | 'EC' | 'OKP' | 'oct';

export interface JsfPublicKey {
  kty: JsfJwkKeyType;
  // RSA
  n?: string;
  e?: string;
  // EC / OKP
  crv?: string;
  x?: string;
  y?: string;
  // HMAC (used for signing only; NOT embedded in envelopes because
  // symmetric keys are secret — but we model the type for completeness)
  k?: string;
  [extra: string]: unknown;
}

/**
 * Shape of the JSF signer object as it appears inside an envelope.
 *
 * Per the JSF 0.82 schema a signer has algorithm and value as required,
 * plus optional keyId, publicKey, certificatePath, and excludes.
 */
export interface JsfSigner {
  algorithm: JsfAlgorithm | string;
  keyId?: string;
  publicKey?: JsfPublicKey;
  certificatePath?: string[];
  excludes?: string[];
  value: string;
}

/**
 * Accepted private-key inputs for signing.
 *
 * JWK objects are fully-described material. Strings accept PEM-encoded
 * PKCS#8 private keys, SPKI public keys, or JWK-JSON. Buffers are
 * treated as DER, and KeyObjects pass through untouched.
 *
 * For HMAC (HS256/384/512) pass either a Buffer of raw key bytes or
 * a JWK with kty='oct' and k set to the base64url-encoded key.
 */
export type KeyInput = JsfPublicKey | string | Buffer | Uint8Array | KeyObject;

export interface SignOptions {
  /** JSF algorithm identifier. */
  algorithm: JsfAlgorithm;

  /** The signing key. See KeyInput for accepted shapes. */
  privateKey: KeyInput;

  /**
   * Public key to embed in the signer.publicKey field. Pass `false`
   * to omit (for keyId-only or certificatePath-based signatures), or
   * `'auto'` to derive from the private key.
   *
   * For HMAC (HS*) algorithms the public key is always omitted, since
   * the signing key is the verifying key.
   */
  publicKey?: KeyInput | false | 'auto';

  /** Application-specific key identifier. Optional. */
  keyId?: string;

  /**
   * Ordered chain of base64-encoded DER X.509 certificates. The first
   * element must hold the signature certificate.
   */
  certificatePath?: string[];

  /**
   * Top-level property names to exclude from the signed canonical
   * form. Per JSF 0.82 the `excludes` property itself is always added
   * to the exclusion set automatically.
   */
  excludes?: string[];

  /**
   * Property name under which the signer object is attached. Defaults
   * to `"signature"`.
   */
  signatureProperty?: string;
}

export interface VerifyOptions {
  /**
   * Override the public key used for verification. When omitted the
   * key embedded in the signer is used; when both are absent the
   * verify fails with a descriptive error.
   *
   * HMAC verification always requires this because the symmetric key
   * is never embedded in the envelope.
   */
  publicKey?: KeyInput;

  /**
   * Property name under which to find the signer object. Defaults to
   * `"signature"`.
   */
  signatureProperty?: string;

  /**
   * Algorithms permitted for this verify call. If provided, a signer
   * whose algorithm is not on the list fails verification before any
   * cryptographic work runs.
   */
  allowedAlgorithms?: (JsfAlgorithm | string)[];

  /**
   * When true, the signer MUST carry an embedded publicKey. The caller
   * can use this to defend against a signer swapping in a different
   * key identifier after a trust decision was cached elsewhere.
   */
  requireEmbeddedPublicKey?: boolean;
}

export interface VerifyResult {
  /** True only when the signature verified and no constraint failed. */
  valid: boolean;

  /** Algorithm recorded in the signer (if recoverable). */
  algorithm?: JsfAlgorithm | string;

  /** Public key embedded in the signer (if any). */
  publicKey?: JsfPublicKey;

  /** keyId recorded in the signer (if any). */
  keyId?: string;

  /** X.509 chain recorded in the signer (if any). */
  certificatePath?: string[];

  /** Excludes recorded in the signer (if any). */
  excludes?: string[];

  /**
   * Human-readable reasons the verify failed. Empty when valid=true.
   */
  errors: string[];
}
