/**
 * JSS-internal types used by the binding and the sign/verify
 * orchestration. Not exported through the public API; consumers see
 * `JssSigner`, `JssSignOptions`, etc., from `./types.ts`.
 *
 * Each format owns its own descriptor and state model. JSS does not
 * use the JSF shape because the on-the-wire fields differ enough
 * (PEM body vs JWK, hash_algorithm explicit, custom metadata
 * allowed) that sharing types creates more friction than reuse.
 */

import type { JsonObject, JsonValue, KeyInput, JwkPublicKey } from '../types.js';
import type { Signer } from '../core/signer.js';

/** Fields the JSS binding needs to construct a `Signer`. */
export interface JssSignerKeyInput {
  algorithm: string;
  privateKey?: KeyInput;
  /** Pre-built signer (HSM, KMS, remote). Wins over `privateKey`. */
  signer?: Signer;
  publicKey?: KeyInput | false | 'auto';
  extensionValues?: Record<string, JsonValue>;
}

/** Fields the JSS binding needs to construct a `Verifier`. */
export interface JssVerifierKeyInput {
  algorithm: string;
  hashAlgorithm?: string;
  publicKey?: KeyInput;
  embeddedPemBody?: string;
  embeddedCertChain?: string[];
  /**
   * JSS does not embed JWK on the wire (PEM bodies only). The field
   * is kept for API parity with the JSF verifier-key shape but JSS
   * never populates it.
   */
  embeddedPublicKey?: JwkPublicKey;
}

/**
 * What JSS reports about one signer in an envelope.
 *
 * `value` is absent on a not-yet-signed descriptor.
 *
 * `extensionValues` carries:
 *   - the per-signer hash algorithm name (sentinel `__jss_hash_algorithm__`),
 *   - the on-the-wire counter signature object if any (sentinel `__jss_countersignature__`),
 *   - key identification fields (`public_key` PEM body, `public_cert_chain`,
 *     `cert_url`, `thumbprint`),
 *   - and any application-defined metadata properties (X.590 § 6.3).
 *
 * The keys named with the leading-double-underscore sentinels never
 * appear on the wire; the binding reads them from the descriptor
 * before rendering the signaturecore.
 */
export interface JssSignerDescriptor {
  algorithm: string;
  value?: string;
  extensionValues?: Record<string, JsonValue>;
}

/** Logical container shape. JSS is always an array; single = length 1. */
export type JssEnvelopeMode = 'single' | 'multi';

export interface JssEnvelopeView {
  mode: JssEnvelopeMode;
  options: Record<string, never>;
  signers: JssSignerDescriptor[];
}

export interface JssWrapperState {
  mode: JssEnvelopeMode;
  options: Record<string, never>;
  signers: JssSignerDescriptor[];
  finalized: boolean[];
}

export type { JsonObject, JsonValue };
