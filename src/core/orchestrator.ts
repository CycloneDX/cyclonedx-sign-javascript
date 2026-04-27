/**
 * Format-agnostic sign and verify orchestration.
 *
 * This module knows nothing about JSF or JSS. It iterates the signer
 * array, asks the binding to build the per-signer canonical view,
 * canonicalizes via JCS, and dispatches to the binding-supplied
 * `Signer` / `Verifier` primitives. JSF-specific behaviour (the wrapper
 * shape, the bracket-and-comma rules of JSF §§ 8 / 9, the signaturecore
 * encoding) lives in the binding's `buildCanonicalView` and `emit`.
 *
 * The orchestrator is async because remote signers (HSM, KMS) are
 * async. The default in-process node-crypto signer resolves on the
 * same tick so synchronous sign/verify work without any extra cost.
 */

import { canonicalize } from '../jcs.js';
import { decodeBase64Url, encodeBase64Url } from '../base64url.js';
import type { JsonObject, JsonValue } from '../types.js';
import type {
  EnvelopeMode,
  EnvelopeOptions,
  SignerDescriptor,
  SignerVerifyOutcome,
  VerifyPolicy,
  WrapperState,
} from './types.js';
import type { FormatBinding, SignerKeyInput, VerifierKeyInput } from './binding.js';
import {
  checkAllowedExcludes,
  checkAllowedExtensions,
  checkSignatureCoreProperties,
  checkWrapperProperties,
  validateExtensionsInvariants,
  validateExcludesShape,
  validateStateAtSign,
} from './validation.js';

// -- Sign ---------------------------------------------------------------------

export interface OrchestratorSignInput {
  payload: JsonObject;
  inputs: SignerKeyInput[];
  mode: EnvelopeMode;
  options: EnvelopeOptions;
  binding: FormatBinding;
  signatureProperty: string;
  /**
   * When provided, used to construct the SignerInputError. Lets the
   * format-specific layer keep its own error class.
   */
  raiseInput: (message: string) => never;
}

/**
 * Build, sign, and emit an envelope.
 *
 * The caller's payload is never mutated. The output is a fresh object
 * with the signature property set.
 */
export async function signEnvelope(input: OrchestratorSignInput): Promise<JsonObject> {
  const { payload, inputs, mode, options, binding, signatureProperty, raiseInput } = input;

  // Convert SignerKeyInput[] into descriptors (without `value`) plus
  // the matching async Signer primitives. The binding owns the
  // mapping because resolveEmbeddedPublicKey and toSigner are
  // format-aware.
  const descriptors: SignerDescriptor[] = inputs.map((ski) => {
    const desc: SignerDescriptor = { algorithm: ski.algorithm };
    if (ski.keyId !== undefined) desc.keyId = ski.keyId;
    if (ski.certificatePath !== undefined) desc.certificatePath = [...ski.certificatePath];
    if (ski.extensionValues !== undefined) {
      desc.extensionValues = { ...ski.extensionValues };
    }
    const embedded = binding.resolveEmbeddedPublicKey(ski);
    if (embedded) desc.publicKey = embedded;
    return desc;
  });

  const state: WrapperState = {
    mode,
    options,
    signers: descriptors,
    finalized: descriptors.map(() => false),
  };

  validateStateAtSign(state, raiseInput);

  const signers = inputs.map((ski) => binding.toSigner(ski));

  for (let i = 0; i < state.signers.length; i++) {
    const view = binding.buildCanonicalView(payload, state, i, signatureProperty);
    const bytes = canonicalize(view);
    // eslint-disable-next-line security/detect-object-injection -- index from a counted loop over a typed array
    const sig = await signers[i]!.sign(bytes);
    // eslint-disable-next-line security/detect-object-injection -- index from a counted loop
    state.signers[i]!.value = encodeBase64Url(sig);
    // eslint-disable-next-line security/detect-object-injection -- index from a counted loop
    state.finalized[i] = true;
  }

  return binding.emit(payload, state, signatureProperty);
}

// -- Verify -------------------------------------------------------------------

export interface OrchestratorVerifyInput {
  payload: JsonObject;
  binding: FormatBinding;
  signatureProperty: string;
  publicKeys?: ReadonlyMap<number, VerifierKeyInput['publicKey']>;
  allowedAlgorithms?: readonly string[];
  requireEmbeddedPublicKey?: boolean;
  policy?: VerifyPolicy;
  allowedExcludes?: readonly string[];
  allowedExtensions?: readonly string[];
  raiseEnvelope: (message: string) => never;
  raiseVerify: (message: string) => never;
  /**
   * Format-specific raw-wrapper accessor for the JSF § 6 property
   * check. Returns the wrapper object as it appeared on the wire, or
   * null when the wire shape does not have a wrapper (single mode).
   */
  rawWrapper: () => Record<string, unknown> | null;
  /**
   * Format-specific raw signaturecore array accessor for the JSF § 6
   * property check. Returns the on-the-wire array of signaturecore
   * objects (length 1 for single mode).
   */
  rawSignatureCores: () => Record<string, unknown>[];
}

export interface OrchestratorVerifyResult {
  valid: boolean;
  mode: EnvelopeMode;
  signers: SignerVerifyOutcome[];
  excludes?: string[];
  extensions?: string[];
  envelopeErrors: string[];
}

export async function verifyEnvelope(
  input: OrchestratorVerifyInput,
): Promise<OrchestratorVerifyResult> {
  const {
    payload,
    binding,
    signatureProperty,
    publicKeys,
    allowedAlgorithms,
    requireEmbeddedPublicKey,
    policy = 'all',
    allowedExcludes,
    allowedExtensions,
    raiseEnvelope,
    raiseVerify,
    rawWrapper,
    rawSignatureCores,
  } = input;

  const view = binding.detect(payload, signatureProperty);
  if (view === null) {
    raiseEnvelope(`Payload has no "${signatureProperty}" property`);
  }
  // raiseEnvelope is typed as `(m) => never` so TS knows view is non-null below.
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- raiseEnvelope above never returns; satisfy strict null check.
  const v = view!;
  const state: WrapperState = {
    mode: v.mode,
    options: v.options,
    signers: v.signers,
    finalized: v.signers.map((s) => s.value !== undefined),
  };

  const envelopeErrors: string[] = [];

  // Always-on shape checks. JSF says "must" so structural failures here
  // are envelope-level errors that cause valid:false regardless of policy.
  try {
    validateExcludesShape(state.options.excludes, (m) => {
      throw new Error(m);
    });
    validateExtensionsInvariants(state.options, state.signers, (m) => {
      throw new Error(m);
    });
  } catch (e) {
    envelopeErrors.push((e as Error).message);
  }

  // Verifier-side acceptance allowlists.
  const exclErr = checkAllowedExcludes(state.options.excludes, allowedExcludes);
  if (exclErr) envelopeErrors.push(exclErr);
  const extErr = checkAllowedExtensions(state.options.extensions, allowedExtensions);
  if (extErr) envelopeErrors.push(extErr);

  // JSF § 6: "there must not be any not here defined properties
  // inside of the signature object". Always enforced; this is a
  // normative validator rule, not an opt-in.
  if (state.mode !== 'single') {
    const w = rawWrapper();
    if (w) {
      const arrayKey = state.mode === 'multi' ? 'signers' : 'chain';
      envelopeErrors.push(...checkWrapperProperties(w, arrayKey));
    }
  }
  const cores = rawSignatureCores();
  for (let i = 0; i < cores.length; i++) {
    // eslint-disable-next-line security/detect-object-injection -- index from a counted loop
    const core = cores[i];
    if (!core) continue;
    envelopeErrors.push(
      ...checkSignatureCoreProperties(
        core,
        state.options.extensions,
        state.mode === 'single',
        i,
      ),
    );
  }

  // Per-signer cryptographic verification. Even when envelopeErrors
  // already disqualifies the envelope we still run per-signer checks
  // and report results so callers can introspect.
  const outcomes: SignerVerifyOutcome[] = [];
  for (let i = 0; i < state.signers.length; i++) {
    // eslint-disable-next-line security/detect-object-injection -- index from a counted loop
    const desc = state.signers[i]!;
    const outcome: SignerVerifyOutcome = {
      index: i,
      valid: false,
      algorithm: desc.algorithm,
      errors: [],
    };
    if (desc.keyId !== undefined) outcome.keyId = desc.keyId;
    if (desc.publicKey !== undefined) outcome.publicKey = desc.publicKey;
    if (desc.certificatePath !== undefined) outcome.certificatePath = [...desc.certificatePath];
    if (desc.extensionValues !== undefined) {
      outcome.extensionValues = { ...desc.extensionValues } as Record<string, JsonValue>;
    }

    if (allowedAlgorithms && !allowedAlgorithms.includes(desc.algorithm)) {
      outcome.errors.push(`algorithm ${desc.algorithm} is not on the allow-list`);
      outcomes.push(outcome);
      continue;
    }
    if (requireEmbeddedPublicKey && !desc.publicKey) {
      outcome.errors.push('signer is missing an embedded publicKey');
      outcomes.push(outcome);
      continue;
    }

    if (desc.value === undefined || desc.value.length === 0) {
      outcome.errors.push('signer is missing value');
      outcomes.push(outcome);
      continue;
    }

    let signatureBytes: Uint8Array;
    try {
      signatureBytes = decodeBase64Url(desc.value);
    } catch (e) {
      outcome.errors.push(`malformed signature value: ${(e as Error).message}`);
      outcomes.push(outcome);
      continue;
    }

    const overrideKey = publicKeys ? publicKeys.get(i) : undefined;
    const verifierInput: VerifierKeyInput = { algorithm: desc.algorithm };
    if (overrideKey !== undefined) verifierInput.publicKey = overrideKey;
    if (desc.publicKey !== undefined) verifierInput.embeddedPublicKey = desc.publicKey;
    if (desc.certificatePath !== undefined)
      verifierInput.certificatePath = desc.certificatePath;

    let verifier;
    try {
      verifier = binding.toVerifier(verifierInput);
    } catch (e) {
      // No key available, or key/algorithm mismatch on construction.
      // Treat lack-of-key as a caller bug at the verify level.
      raiseVerify((e as Error).message);
    }

    // Build the canonical view as if signer i is the one being verified.
    // Strip its `value` so the canonical form matches what was signed.
    const tmpDesc: SignerDescriptor = { ...desc };
    delete tmpDesc.value;
    const stateForVerify: WrapperState = {
      ...state,
      signers: state.signers.map((s, idx) => (idx === i ? tmpDesc : s)),
      finalized: state.finalized.map((f, idx) => (idx === i ? false : f)),
    };
    const view2 = binding.buildCanonicalView(
      payload,
      stateForVerify,
      i,
      signatureProperty,
    );
    const bytes = canonicalize(view2);
    let ok = false;
    try {
      ok = await verifier!.verify(bytes, signatureBytes);
    } catch (e) {
      outcome.errors.push(`verifier threw: ${(e as Error).message}`);
    }
    if (!ok) {
      outcome.errors.push('signature did not verify');
    } else {
      outcome.valid = true;
    }
    outcomes.push(outcome);
  }

  const aggregateValid = envelopeErrors.length === 0 && applyPolicy(outcomes, policy);

  const out: OrchestratorVerifyResult = {
    valid: aggregateValid,
    mode: state.mode,
    signers: outcomes,
    envelopeErrors,
  };
  if (state.options.excludes) out.excludes = [...state.options.excludes];
  if (state.options.extensions) out.extensions = [...state.options.extensions];
  return out;
}

function applyPolicy(outcomes: SignerVerifyOutcome[], policy: VerifyPolicy): boolean {
  const ok = outcomes.filter((o) => o.valid).length;
  if (policy === 'all') return ok === outcomes.length;
  if (policy === 'any') return ok >= 1;
  return ok >= policy.atLeast;
}

// -- Append helpers (single binding-level operation) --------------------------

/**
 * Build a `WrapperState` for "append a new signer to an existing
 * envelope" flows. The orchestrator does the work; the binding
 * decides whether the envelope mode is acceptable for the operation
 * (e.g., only chain envelopes accept `appendChainSigner`).
 */
export function appendDescriptor(
  existing: WrapperState,
  newDescriptor: SignerDescriptor,
): WrapperState {
  return {
    mode: existing.mode,
    options: existing.options,
    signers: [...existing.signers, newDescriptor],
    finalized: [...existing.finalized, false],
  };
}
