/**
 * JSF-internal types used by the orchestrator, validation helpers,
 * and the binding implementation. Not exported through the package
 * public API; consumers see `JsfSigner`, `JsfSignOptions`, etc., from
 * `./types.ts`.
 */

import type { JsonObject, JsonValue, JwkPublicKey } from '../types.js';

/**
 * Logical container shape for a JSF envelope.
 *
 *   'single'  — bare signaturecore at payload[signatureProperty].
 *   'multi'   — multisignature wrapper: { signers: [signaturecore, ...] }.
 *   'chain'   — signaturechain wrapper: { chain:   [signaturecore, ...] }.
 */
export type JsfEnvelopeMode = 'single' | 'multi' | 'chain';

/** What JSF reports about one signer in an envelope. */
export interface JsfSignerDescriptor {
  algorithm: string;
  keyId?: string;
  publicKey?: JwkPublicKey;
  certificatePath?: string[];
  value?: string;
  /**
   * Application-specific extension property values declared via the
   * envelope's `extensions` list. Keys must be a subset of the
   * declared list (validated up front).
   */
  extensionValues?: Record<string, JsonValue>;
}

/**
 * Wrapper-level options shared across signers in multi or chain mode.
 * In single mode they sit on the signaturecore itself; the binding
 * handles the placement difference.
 */
export interface JsfEnvelopeOptions {
  excludes?: string[];
  extensions?: string[];
}

export interface JsfEnvelopeView {
  mode: JsfEnvelopeMode;
  options: JsfEnvelopeOptions;
  signers: JsfSignerDescriptor[];
}

/**
 * Mutable working state used during sign and verify. `finalized[i]`
 * is true once `signers[i].value` has been computed; chain-mode
 * canonical view for index k > i requires `finalized[i]` to be true.
 */
export interface JsfWrapperState {
  mode: JsfEnvelopeMode;
  options: JsfEnvelopeOptions;
  signers: JsfSignerDescriptor[];
  finalized: boolean[];
}

/**
 * Per-signer outcome accumulated by the JSF orchestrator. The public
 * `JsfSignerVerifyResult` in `./types.ts` is a richer shape derived
 * from this internal one.
 */
export interface JsfSignerVerifyOutcome {
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
 * Helper alias for callers building options bags around the binding
 * directly.
 */
export type { JsonObject, JsonValue, JwkPublicKey };
