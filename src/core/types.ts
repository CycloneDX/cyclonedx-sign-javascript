/**
 * Format-agnostic core types.
 *
 * These shapes describe envelope state in terms both JSF (today) and
 * JSS (when X.590 work begins) can present. The orchestrator and the
 * canonical-view builders speak only this vocabulary; format-specific
 * bindings translate to and from the on-the-wire object.
 */

import type { JsonObject, JsonValue, JwkPublicKey } from '../types.js';

/**
 * Logical container shape, regardless of format-specific property
 * names. The wire encoding is the binding's job; the orchestrator and
 * validation only need to know how many signers exist and how each
 * signer's canonical view should be built.
 */
export type EnvelopeMode = 'single' | 'multi' | 'chain';

/**
 * What a format reports about one signer in an envelope.
 *
 * `value` is absent on a not-yet-signed descriptor. `extensionValues`
 * carries the application-specific property values that live as
 * siblings of `algorithm` / `value` / etc. inside the signaturecore.
 * The keys MUST be a subset of the wrapper's declared `extensions`
 * list (validated up front).
 */
export interface SignerDescriptor {
  algorithm: string;
  keyId?: string;
  publicKey?: JwkPublicKey;
  certificatePath?: string[];
  value?: string;
  extensionValues?: Record<string, JsonValue>;
}

/**
 * Wrapper-level options shared across signers in `multi` or `chain`
 * mode. In `single` mode they live on the signaturecore itself; the
 * binding handles the placement difference.
 */
export interface EnvelopeOptions {
  /** Top-level payload property names to exclude from canonicalization. */
  excludes?: string[];
  /**
   * Names of application-specific extension properties carried inside
   * one or more signaturecore objects. The names list is signed (it
   * lives on the JSF signature object); the property values are signed
   * via their presence inside individual signaturecore objects. Names
   * must not duplicate and must not collide with JSF reserved words.
   */
  extensions?: string[];
}

/**
 * View of an existing envelope that the binding parsed off the wire.
 * Used by `verify` to inspect what is there before any cryptographic
 * work.
 */
export interface EnvelopeView {
  mode: EnvelopeMode;
  options: EnvelopeOptions;
  signers: SignerDescriptor[];
}

/**
 * Mutable working state used during sign and verify. `finalized[i]` is
 * true once `signers[i].value` has been computed; chain-mode
 * canonicalization for index k > i requires `finalized[i]` to be true.
 */
export interface WrapperState {
  mode: EnvelopeMode;
  options: EnvelopeOptions;
  signers: SignerDescriptor[];
  finalized: boolean[];
}

/**
 * Async signing primitive. The same interface a future HSM or KMS
 * adapter will satisfy. The orchestrator never calls `node:crypto`
 * directly; everything goes through this.
 */
export interface Signer {
  sign(canonicalBytes: Uint8Array): Promise<Uint8Array>;
}

/** Async verification primitive, paired with `Signer`. */
export interface Verifier {
  verify(canonicalBytes: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

/**
 * Per-signer cryptographic outcome from `verify`. Aggregated by the
 * orchestrator into the format-specific result type.
 */
export interface SignerVerifyOutcome {
  index: number;
  valid: boolean;
  algorithm: string;
  keyId?: string;
  publicKey?: JwkPublicKey;
  certificatePath?: string[];
  extensionValues?: Record<string, JsonValue>;
  errors: string[];
}

/**
 * `valid` aggregation policy across multiple signers.
 *
 *   'all'           — every signer must verify.
 *   'any'           — at least one must verify.
 *   { atLeast: n }  — at least n must verify.
 */
export type VerifyPolicy = 'all' | 'any' | { atLeast: number };

/**
 * Re-export `JsonObject` and `JsonValue` from the package-wide types
 * module as a convenience so consumers of `core/` do not have to
 * import from two places.
 */
export type { JsonObject, JsonValue } from '../types.js';
