/**
 * JSS public API barrel (ITU-T X.590, 10/2023).
 *
 * Import this module via the ./jss subpath when you want to target
 * JSS explicitly:
 *
 *     import { sign, verify, countersign } from '@cyclonedx/sign/jss';
 *
 * The top-level API (@cyclonedx/sign) routes by `cyclonedxVersion`
 * (V2 -> JSS).
 */

export { sign, verify, countersign } from './sign.js';
export { JSS_BINDING, JssBinding } from './binding.js';
export {
  isRegisteredAlgorithm as isRegisteredJssAlgorithm,
  signHash as signJssHash,
  verifyHash as verifyJssHash,
} from './algorithms.js';
export { isRegisteredHashAlgorithm as isRegisteredJssHashAlgorithm, hashBytes as jssHashBytes } from './hash.js';
export {
  publicKeyFromPemBody,
  pemBodyFromPublicKey,
  privateKeyFromPem,
} from './pem.js';

export type {
  JssAlgorithm,
  JssHashAlgorithm,
  JssSigner,
  JssSignerInput,
  JssSignerVerifyResult,
  JssSignOptions,
  JssCountersignOptions,
  JssVerifyOptions,
  JssVerifyResult,
} from './types.js';
