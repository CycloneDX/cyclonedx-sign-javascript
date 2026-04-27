/**
 * Format-agnostic core barrel. Public API consumers should not import
 * from here; the JSF and JSS bindings re-export what callers actually
 * need. This barrel exists so internal modules have one well-known
 * import target.
 */

export type {
  EnvelopeMode,
  EnvelopeOptions,
  EnvelopeView,
  JsonObject,
  JsonValue,
  Signer,
  SignerDescriptor,
  SignerVerifyOutcome,
  Verifier,
  VerifyPolicy,
  WrapperState,
} from './types.js';

export type {
  FormatBinding,
  SignerKeyInput,
  VerifierKeyInput,
} from './binding.js';

export {
  signEnvelope,
  verifyEnvelope,
  appendDescriptor,
} from './orchestrator.js';

export type {
  OrchestratorSignInput,
  OrchestratorVerifyInput,
  OrchestratorVerifyResult,
} from './orchestrator.js';

export {
  validateExtensionsInvariants,
  validateExcludesShape,
  validateStateAtSign,
  checkAllowedExcludes,
  checkAllowedExtensions,
  checkWrapperProperties,
  checkSignatureCoreProperties,
} from './validation.js';

export {
  JSF_RESERVED_WORDS,
  JSF_SIGNATURECORE_FIELDS,
  JSF_WRAPPER_FIELDS_MULTI,
  JSF_WRAPPER_FIELDS_CHAIN,
  isJsfReservedWord,
  isJsfSignatureCoreField,
} from './jsf-reserved.js';

export type { JsfReservedWord } from './jsf-reserved.js';
