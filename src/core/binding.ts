/**
 * Format binding interface.
 *
 * Each signature format (JSF today, JSS later) implements this small
 * adapter so the orchestrator never speaks JSF or JSS directly. The
 * binding owns:
 *
 *   - parsing an existing wire envelope into the format-agnostic
 *     `EnvelopeView`,
 *   - building the per-signer canonical view exactly per the format's
 *     spec rules (the orchestrator calls JCS on whatever the binding
 *     returns),
 *   - emitting a completed `WrapperState` back into a wire envelope,
 *   - producing `Signer` / `Verifier` primitives for a given algorithm
 *     and key (so the orchestrator never imports `node:crypto`),
 *   - reporting format-specific reserved property names (used by the
 *     core's signature-object property validation).
 */

import type { JsonObject, JsonValue, JwkPublicKey } from '../types.js';
import type { KeyInput, SignatureFormat } from '../types.js';
import type {
  EnvelopeOptions,
  EnvelopeView,
  Signer,
  SignerDescriptor,
  Verifier,
  WrapperState,
} from './types.js';

/**
 * Fields the binding needs to construct a `Signer` for one signaturecore.
 */
export interface SignerKeyInput {
  algorithm: string;
  privateKey?: KeyInput;
  /**
   * If the caller supplied a pre-built `Signer` directly (HSM, KMS,
   * remote signer) the binding uses it as-is and ignores `privateKey`.
   */
  signer?: Signer;
  publicKey?: KeyInput | false | 'auto';
  keyId?: string;
  certificatePath?: string[];
  extensionValues?: Record<string, JsonValue>;
}

/**
 * Fields the binding needs to construct a `Verifier` for one
 * signaturecore that came off the wire.
 */
export interface VerifierKeyInput {
  algorithm: string;
  /** Override the embedded key. */
  publicKey?: KeyInput;
  /** Embedded JWK from the signer descriptor. */
  embeddedPublicKey?: JwkPublicKey;
  /** Embedded cert chain (leaf first) from the signer descriptor. */
  certificatePath?: string[];
}

export interface FormatBinding {
  readonly format: SignatureFormat;

  /**
   * Read the envelope wrapper (or bare signaturecore) at `payload[signatureProperty]`
   * and translate it to a format-agnostic `EnvelopeView`. Returns null
   * when the property is absent. Throws for malformed input.
   */
  detect(payload: JsonObject, signatureProperty: string): EnvelopeView | null;

  /**
   * Build the canonical view for signer at `index`, exactly per the
   * format's spec rules. The orchestrator hands the result straight
   * to JCS without modification.
   */
  buildCanonicalView(
    payload: JsonObject,
    state: WrapperState,
    index: number,
    signatureProperty: string,
  ): JsonObject;

  /**
   * Encode a completed `WrapperState` back into the payload. Returns a
   * fresh object; the input payload is not mutated.
   */
  emit(payload: JsonObject, state: WrapperState, signatureProperty: string): JsonObject;

  /**
   * Resolve a private key + algorithm into a `Signer`. The default
   * implementation uses `node:crypto` synchronously and resolves the
   * promise on the same tick. HSM/KMS adapters override by passing
   * their own `Signer` to the format-level sign function.
   */
  toSigner(input: SignerKeyInput): Signer;

  /** Resolve a public key + algorithm into a `Verifier`. */
  toVerifier(input: VerifierKeyInput): Verifier;

  /**
   * Derive the embedded `publicKey` value for the signaturecore from
   * the sign options. Returns null when the format chooses not to
   * embed (e.g., HMAC) or the caller asked for `publicKey: false`.
   */
  resolveEmbeddedPublicKey(
    input: SignerKeyInput,
  ): JwkPublicKey | null;

  /**
   * Promote a wire-level signaturecore property bag to a
   * `SignerDescriptor`. Used by `appendChainSigner` /
   * `appendMultiSigner` when reading existing signers off an envelope
   * before adding a new one.
   */
  descriptorFromWire(core: JsonObject, options: EnvelopeOptions): SignerDescriptor;
}
