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

export { sign, verify, computeCanonicalInput } from './sign.js';

export {
  getAlgorithmSpec,
  isRegisteredAlgorithm,
  isAsymmetricAlgorithm,
  signBytes,
  verifyBytes,
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

export type {
  JsfAlgorithm,
  JsfSigner,
  JsfSignOptions,
  JsfVerifyOptions,
  JsfVerifyResult,
} from './types.js';
