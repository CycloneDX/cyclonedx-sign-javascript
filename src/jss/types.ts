/**
 * JSS (JSON Signature Schema, X.590) type placeholders.
 *
 * Status: INCOMPLETE STUB.
 *
 * These shapes are provisional. They mirror the JSF unified API
 * surface so the call sites are stable for tool authors, but the
 * fields, algorithm set, and envelope layout will evolve as X.590 and
 * the CycloneDX 2.x subschema stabilize. Expect breaking changes to
 * the JSS-specific types until this stub is replaced with a working
 * implementation.
 *
 * Where JSS and JSF share a concept (JWK, key inputs, base JSON value
 * types, the verify policy/aggregation enum) the types are imported
 * from ../types.ts or ../core/types.ts rather than duplicated.
 */

import type { JsonValue, JwkPublicKey, KeyInput } from '../types.js';
import type {
  EnvelopeMode,
  Signer,
  VerifyPolicy,
} from '../core/types.js';

/**
 * JSS algorithm identifier. Deliberately a plain string while the
 * X.590 algorithm registry is still in flux. When the spec is final
 * this will become a string literal union analogous to JsfAlgorithm.
 */
export type JssAlgorithm = string;

/**
 * Provisional JSS signer shape. The X.590 wire layout may rename or
 * restructure fields; treat this as a placeholder for type checks.
 */
export interface JssSigner {
  algorithm: JssAlgorithm;
  value: string;
  publicKey?: JwkPublicKey;
  keyId?: string;
  [extra: string]: unknown;
}

export interface JssSignerInput {
  algorithm: JssAlgorithm;
  privateKey?: KeyInput;
  signer?: Signer;
  // eslint-disable-next-line @typescript-eslint/no-redundant-type-constituents -- 'auto' is a documented sentinel string.
  publicKey?: KeyInput | false | 'auto';
  keyId?: string;
  certificatePath?: string[];
  extensionValues?: Record<string, JsonValue>;
}

export interface JssSignOptions {
  signer?: JssSignerInput;
  signers?: JssSignerInput[];
  mode?: 'multi' | 'chain';
  excludes?: string[];
  extensions?: string[];
  signatureProperty?: string;
}

export interface JssVerifyOptions {
  publicKey?: KeyInput;
  publicKeys?: ReadonlyMap<number, KeyInput>;
  signatureProperty?: string;
  allowedAlgorithms?: string[];
  requireEmbeddedPublicKey?: boolean;
  policy?: VerifyPolicy;
  allowedExcludes?: readonly string[];
  allowedExtensions?: readonly string[];
}

export interface JssSignerVerifyResult {
  index: number;
  valid: boolean;
  algorithm: string;
  keyId?: string;
  publicKey?: JwkPublicKey;
  certificatePath?: string[];
  extensionValues?: Record<string, JsonValue>;
  errors: string[];
}

export interface JssVerifyResult {
  valid: boolean;
  mode: EnvelopeMode;
  signers: JssSignerVerifyResult[];
  excludes?: string[];
  extensions?: string[];
  errors: string[];
}
