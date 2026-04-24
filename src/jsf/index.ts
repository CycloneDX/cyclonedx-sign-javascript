/**
 * JSF public API barrel.
 *
 * Import this module via the ./jsf subpath when you want to target JSF
 * explicitly:
 *
 *     import { signJsf, verifyJsf } from '@cyclonedx/sign/jsf';
 *
 * The top-level API (@cyclonedx/sign) re-exports from this
 * module and adds format-aware routing and the signBom helper.
 *
 * For backward compatibility with @cyclonedx/jsf, `sign` and `verify`
 * are also exported from this module as aliases for signJsf / verifyJsf.
 */

export {
  signJsf,
  verifyJsf,
  computeJsfCanonicalInput,
  // Back-compat aliases for existing @cyclonedx/jsf consumers.
  signJsf as sign,
  verifyJsf as verify,
  computeJsfCanonicalInput as computeCanonicalInput,
} from './sign.js';

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
  // Back-compat names (these were the bare types on the old top level).
  JsfSignOptions as SignOptions,
  JsfVerifyOptions as VerifyOptions,
  JsfVerifyResult as VerifyResult,
} from './types.js';
