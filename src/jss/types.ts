/**
 * JSS (JSON Signature Schema, X.590) type placeholders.
 *
 * Status: INCOMPLETE STUB.
 *
 * These shapes are provisional. They exist so tool authors can start
 * wiring against the API surface today, but the fields, algorithm set,
 * and envelope layout will evolve as the X.590 specification and the
 * CycloneDX 2.x subschema stabilize. Expect breaking changes to the
 * JSS-specific types until this stub is replaced with a working
 * implementation.
 *
 * Where JSS and JSF share a concept (JWK shape, key input types, base
 * JSON value types) the types are imported from ../types.ts rather
 * than duplicated.
 */

import type { JwkPublicKey, KeyInput } from '../types.js';

/**
 * JSS algorithm identifier. Deliberately a plain string while the
 * X.590 algorithm registry is still in flux. When the spec is final
 * this will become a string literal union analogous to JsfAlgorithm.
 */
export type JssAlgorithm = string;

/**
 * Provisional JSS signer shape. The final X.590 layout may rename
 * fields or introduce a distinct envelope structure; treat this as a
 * placeholder for type checks only.
 */
export interface JssSigner {
  algorithm: JssAlgorithm;
  value: string;
  publicKey?: JwkPublicKey;
  keyId?: string;
  [extra: string]: unknown;
}

export interface JssSignOptions {
  algorithm: JssAlgorithm;
  privateKey: KeyInput;
  publicKey?: KeyInput | false | 'auto';
  keyId?: string;
  signatureProperty?: string;
  /** Additional fields may be added as the X.590 spec settles. */
  [extra: string]: unknown;
}

export interface JssVerifyOptions {
  publicKey?: KeyInput;
  signatureProperty?: string;
  allowedAlgorithms?: string[];
  [extra: string]: unknown;
}

export interface JssVerifyResult {
  valid: boolean;
  algorithm?: string;
  publicKey?: JwkPublicKey;
  keyId?: string;
  errors: string[];
}
