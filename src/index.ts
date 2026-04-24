/**
 * Public API for the @cyclonedx/jsf package.
 *
 * Example:
 *
 *     import { sign, verify } from '@cyclonedx/jsf';
 *
 *     const signed = sign(
 *       { statement: 'hello world' },
 *       { algorithm: 'ES256', privateKey: ecPem }
 *     );
 *     const result = verify(signed);
 *     result.valid; // true
 *
 * JCS is also available for callers who need canonical bytes without
 * the JSF envelope (for example to pre-hash a payload in a two-phase
 * client-side signing flow):
 *
 *     import { canonicalize } from '@cyclonedx/jsf/jcs';
 *     const bytes = canonicalize({ a: 1, b: 2 });
 */

export { sign, verify, computeCanonicalInput } from './jsf.js';
export { canonicalize, canonicalizeToString } from './jcs.js';
export {
  decodeBase64Url,
  encodeBase64Url,
  encodeBase64UrlBigInteger,
} from './base64url.js';
export {
  exportPublicJwk,
  sanitizePublicJwk,
  toPrivateKey,
  toPublicKey,
} from './jwk.js';
export {
  getAlgorithmSpec,
  isRegisteredAlgorithm,
  isAsymmetricAlgorithm,
  signBytes,
  verifyBytes,
  JSF_ASYMMETRIC_ALGORITHMS,
} from './algorithms.js';

export {
  JsfError,
  JsfInputError,
  JcsError,
  JsfKeyError,
  JsfEnvelopeError,
  JsfSignError,
  JsfVerifyError,
} from './errors.js';

export type {
  JsonObject,
  JsonValue,
  JsfAlgorithm,
  JsfJwkKeyType,
  JsfPublicKey,
  JsfSigner,
  KeyInput,
  SignOptions,
  VerifyOptions,
  VerifyResult,
} from './types.js';

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
  NormalizedPrivateKey,
  NormalizedPublicKey,
} from './jwk.js';
