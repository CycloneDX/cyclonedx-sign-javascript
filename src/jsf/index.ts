/**
 * JSF public API barrel.
 *
 * Import this module via the ./jsf subpath when you want to target JSF
 * explicitly:
 *
 *     import { sign, verify } from '@cyclonedx/sign/jsf';
 *
 * The top-level API (@cyclonedx/sign) re-exports from this module and
 * adds a CycloneDX-major-aware sign / verify helper on top.
 */

export {
  sign,
  verify,
  appendChainSigner,
  appendMultiSigner,
  computeCanonicalInputs,
} from './sign.js';

export {
  getAlgorithmSpec,
  isRegisteredAlgorithm,
  isAsymmetricAlgorithm,
  signBytes,
  verifyBytes,
  JsfAlgorithms,
  JSF_ASYMMETRIC_ALGORITHMS,
} from './algorithms.js';

export type {
  AlgorithmSpec,
  RsaPkcs1Spec,
  RsaPssSpec,
  EcdsaSpec,
  EddsaSpec,
  HmacSpec,
  JsfAsymmetricAlgorithm,
} from './algorithms.js';

export { JSF_BINDING, JsfBinding } from './binding.js';

export type {
  JsfAlgorithm,
  JsfAppendOptions,
  JsfCanonicalInputState,
  JsfSigner,
  JsfSignerInput,
  JsfSignerVerifyResult,
  JsfSignOptions,
  JsfVerifyOptions,
  JsfVerifyResult,
} from './types.js';
