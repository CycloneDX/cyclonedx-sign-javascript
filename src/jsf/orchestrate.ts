/**
 * JSF sign and verify orchestration.
 *
 * This module iterates the signer array, asks the binding to build
 * the per-signer canonical view, canonicalizes via JCS, and dispatches
 * to async `Signer` / `Verifier` primitives produced by the binding.
 * The orchestrator is async because remote signers (HSM, KMS) are
 * async; the in-process node-crypto path resolves on the same tick.
 */

import { canonicalize } from '../jcs.js';
import { decodeBase64Url, encodeBase64Url } from '../base64url.js';
import { applyPolicy } from '../core/policy.js';
import type { VerifyPolicy } from '../core/policy.js';
import type { JsonObject, JsonValue } from '../types.js';
import type {
  JsfEnvelopeMode,
  JsfEnvelopeOptions,
  JsfSignerDescriptor,
  JsfSignerVerifyOutcome,
  JsfWrapperState,
} from './internal-types.js';
import type {
  JsfBindingContract,
  JsfSignerKeyInput,
  JsfVerifierKeyInput,
} from './internal-binding.js';
import {
  checkAllowedExcludes,
  checkAllowedExtensions,
  checkSignatureCoreProperties,
  checkWrapperProperties,
  validateExtensionsInvariants,
  validateExcludesShape,
  validateStateAtSign,
} from './validation.js';

// -- Sign --------------------------------------------------------------------

export interface JsfOrchestratorSignInput {
  payload: JsonObject;
  inputs: JsfSignerKeyInput[];
  mode: JsfEnvelopeMode;
  options: JsfEnvelopeOptions;
  binding: JsfBindingContract;
  signatureProperty: string;
  raiseInput: (message: string) => never;
}

export async function signEnvelope(input: JsfOrchestratorSignInput): Promise<JsonObject> {
  const { payload, inputs, mode, options, binding, signatureProperty, raiseInput } = input;

  const descriptors: JsfSignerDescriptor[] = inputs.map((ski) => {
    const desc: JsfSignerDescriptor = { algorithm: ski.algorithm };
    if (ski.keyId !== undefined) desc.keyId = ski.keyId;
    if (ski.certificatePath !== undefined) desc.certificatePath = [...ski.certificatePath];
    if (ski.extensionValues !== undefined) {
      desc.extensionValues = { ...ski.extensionValues };
    }
    const embedded = binding.resolveEmbeddedPublicKey(ski);
    if (embedded) desc.publicKey = embedded;
    return desc;
  });

  const state: JsfWrapperState = {
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
    // eslint-disable-next-line security/detect-object-injection -- counted loop
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- index access bounded by a preceding length check or counted loop; the non-null assertion reflects that runtime invariant
    const sig = await signers[i]!.sign(bytes);
    // eslint-disable-next-line security/detect-object-injection -- counted loop
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- index access bounded by a preceding length check or counted loop; the non-null assertion reflects that runtime invariant
    state.signers[i]!.value = encodeBase64Url(sig);
    // eslint-disable-next-line security/detect-object-injection -- counted loop
    state.finalized[i] = true;
  }

  return binding.emit(payload, state, signatureProperty);
}

// -- Verify ------------------------------------------------------------------

export interface JsfOrchestratorVerifyInput {
  payload: JsonObject;
  binding: JsfBindingContract;
  signatureProperty: string;
  publicKeys?: ReadonlyMap<number, JsfVerifierKeyInput['publicKey']>;
  allowedAlgorithms?: readonly string[];
  requireEmbeddedPublicKey?: boolean;
  policy?: VerifyPolicy;
  allowedExcludes?: readonly string[];
  allowedExtensions?: readonly string[];
  raiseEnvelope: (message: string) => never;
  raiseVerify: (message: string) => never;
  rawWrapper: () => Record<string, unknown> | null;
  rawSignatureCores: () => Record<string, unknown>[];
}

export interface JsfOrchestratorVerifyResult {
  valid: boolean;
  mode: JsfEnvelopeMode;
  signers: JsfSignerVerifyOutcome[];
  excludes?: string[];
  extensions?: string[];
  envelopeErrors: string[];
}

export async function verifyEnvelope(
  input: JsfOrchestratorVerifyInput,
): Promise<JsfOrchestratorVerifyResult> {
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
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- raiseEnvelope above never returns
  const v = view!;
  const state: JsfWrapperState = {
    mode: v.mode,
    options: v.options,
    signers: v.signers,
    finalized: v.signers.map((s) => s.value !== undefined),
  };

  const envelopeErrors: string[] = [];

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

  const exclErr = checkAllowedExcludes(state.options.excludes, allowedExcludes);
  if (exclErr) envelopeErrors.push(exclErr);
  const extErr = checkAllowedExtensions(state.options.extensions, allowedExtensions);
  if (extErr) envelopeErrors.push(extErr);

  if (state.mode !== 'single') {
    const w = rawWrapper();
    if (w) {
      const arrayKey = state.mode === 'multi' ? 'signers' : 'chain';
      envelopeErrors.push(...checkWrapperProperties(w, arrayKey));
    }
  }
  const cores = rawSignatureCores();
  for (let i = 0; i < cores.length; i++) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop
    const core = cores[i];
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
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

  const outcomes: JsfSignerVerifyOutcome[] = [];
  for (let i = 0; i < state.signers.length; i++) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- index access bounded by a preceding length check or counted loop; the non-null assertion reflects that runtime invariant
    const desc = state.signers[i]!;
    const outcome: JsfSignerVerifyOutcome = {
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
    const verifierInput: JsfVerifierKeyInput = { algorithm: desc.algorithm };
    if (overrideKey !== undefined) verifierInput.publicKey = overrideKey;
    if (desc.publicKey !== undefined) verifierInput.embeddedPublicKey = desc.publicKey;
    if (desc.certificatePath !== undefined)
      verifierInput.certificatePath = desc.certificatePath;

    let verifier;
    try {
      verifier = binding.toVerifier(verifierInput);
    } catch (e) {
      raiseVerify((e as Error).message);
    }

    const tmpDesc: JsfSignerDescriptor = { ...desc };
    delete tmpDesc.value;
    const stateForVerify: JsfWrapperState = {
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
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- index access bounded by a preceding length check or counted loop; the non-null assertion reflects that runtime invariant
      ok = await verifier!.verify(bytes, signatureBytes);
    } catch (e) {
      outcome.errors.push(`verifier threw: ${(e as Error).message}`);
    }
    if (!ok) outcome.errors.push('signature did not verify');
    else outcome.valid = true;
    outcomes.push(outcome);
  }

  const aggregateValid =
    envelopeErrors.length === 0 && applyPolicy(outcomes.map((o) => o.valid), policy);

  const out: JsfOrchestratorVerifyResult = {
    valid: aggregateValid,
    mode: state.mode,
    signers: outcomes,
    envelopeErrors,
  };
  if (state.options.excludes) out.excludes = [...state.options.excludes];
  if (state.options.extensions) out.extensions = [...state.options.extensions];
  return out;
}

// -- Append helper ----------------------------------------------------------

export function appendDescriptor(
  existing: JsfWrapperState,
  newDescriptor: JsfSignerDescriptor,
): JsfWrapperState {
  return {
    mode: existing.mode,
    options: existing.options,
    signers: [...existing.signers, newDescriptor],
    finalized: [...existing.finalized, false],
  };
}
