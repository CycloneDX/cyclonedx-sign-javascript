/**
 * JSF-internal binding seam.
 *
 * The orchestrator (`./orchestrate.ts`) never speaks JSF wire-format
 * directly; it goes through this adapter. Internal to the JSF
 * subpackage; not exported through the public API.
 */

import type { JsonObject, JsonValue, JwkPublicKey, KeyInput } from '../types.js';
import type { Signer, Verifier } from '../core/signer.js';
import type {
  JsfEnvelopeOptions,
  JsfEnvelopeView,
  JsfSignerDescriptor,
  JsfWrapperState,
} from './internal-types.js';

/** Fields the binding needs to construct a `Signer`. */
export interface JsfSignerKeyInput {
  algorithm: string;
  privateKey?: KeyInput;
  /** Pre-built signer (HSM, KMS, remote). Wins over `privateKey`. */
  signer?: Signer;
  publicKey?: KeyInput | false | 'auto';
  keyId?: string;
  certificatePath?: string[];
  extensionValues?: Record<string, JsonValue>;
}

/** Fields the binding needs to construct a `Verifier`. */
export interface JsfVerifierKeyInput {
  algorithm: string;
  publicKey?: KeyInput;
  embeddedPublicKey?: JwkPublicKey;
  certificatePath?: string[];
}

/**
 * The orchestrator-level seam. The single concrete implementation is
 * `JsfBinding` in `./binding.ts`.
 */
export interface JsfBindingContract {
  detect(payload: JsonObject, signatureProperty: string): JsfEnvelopeView | null;
  buildCanonicalView(
    payload: JsonObject,
    state: JsfWrapperState,
    index: number,
    signatureProperty: string,
  ): JsonObject;
  emit(payload: JsonObject, state: JsfWrapperState, signatureProperty: string): JsonObject;
  toSigner(input: JsfSignerKeyInput): Signer;
  toVerifier(input: JsfVerifierKeyInput): Verifier;
  resolveEmbeddedPublicKey(input: JsfSignerKeyInput): JwkPublicKey | null;
  descriptorFromWire(core: JsonObject, options: JsfEnvelopeOptions): JsfSignerDescriptor;
}
