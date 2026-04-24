/**
 * Public API for the @cyclonedx/sign package.
 *
 * This library implements JSON Signature Format (JSF) and the JSON
 * Canonicalization Scheme (JCS, RFC 8785) today, and carries a stub
 * for JSON Signature Schema (JSS, X.590) so CycloneDX tool authors
 * can target both CycloneDX 1.x (JSF) and CycloneDX 2.x (JSS) through
 * a single dependency.
 *
 * The top-level sign / verify / signBom / verifyBom route to the
 * underlying format based on:
 *
 *   1. An explicit options.format ('jsf' or 'jss').
 *   2. For BOMs, the value of bom.specVersion.
 *   3. For verify, the shape of the envelope.
 *   4. Defaulting to JSF when no signal is available.
 *
 * Example: generic sign and verify
 *
 *     import { sign, verify } from '@cyclonedx/sign';
 *
 *     const signed = sign(
 *       { statement: 'hello world' },
 *       { algorithm: 'ES256', privateKey: ecPem }
 *     );
 *     const result = verify(signed);
 *     result.valid;   // true
 *     result.format;  // 'jsf'
 *
 * Example: the CycloneDX BOM helper
 *
 *     import { signBom, verifyBom } from '@cyclonedx/sign';
 *
 *     // For a CycloneDX 1.x BOM this routes to JSF automatically.
 *     const signedBom = signBom(bom, { algorithm: 'ES256', privateKey });
 *     const result = verifyBom(signedBom);
 *     result.valid;   // true
 *     result.format;  // 'jsf' or 'jss' depending on bom.specVersion
 *
 * Example: JCS canonical bytes without the envelope
 *
 *     import { canonicalize } from '@cyclonedx/sign/jcs';
 *     const bytes = canonicalize({ a: 1, b: 2 });
 */

// -- Top-level helper API ----------------------------------------------------

export {
  sign,
  verify,
  signBom,
  verifyBom,
  detectFormat,
  inferFormatFromBom,
} from './format-helper.js';

export type {
  SignOptions,
  VerifyOptions,
  VerifyResult,
} from './format-helper.js';

// -- Format namespaces -------------------------------------------------------
// `jsf` and `jss` are namespace re-exports. Use when you want the
// format-specific call sites without the helper in the middle:
//
//     import { jsf } from '@cyclonedx/sign';
//     jsf.signJsf(payload, options);

export * as jsf from './jsf/index.js';
export * as jss from './jss/index.js';

// Format-specific functions are also exported flat for convenience.
export { signJsf, verifyJsf, computeJsfCanonicalInput } from './jsf/index.js';
export { signJss, verifyJss } from './jss/index.js';

// -- Back-compat with the previous @cyclonedx/jsf top level ------------------
// Callers who were importing computeCanonicalInput from the old package
// still get it here.

export { computeJsfCanonicalInput as computeCanonicalInput } from './jsf/index.js';

// -- Shared utilities --------------------------------------------------------

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

// -- JSF algorithm registry (re-exported for back compat) --------------------

export {
  getAlgorithmSpec,
  isRegisteredAlgorithm,
  isAsymmetricAlgorithm,
  signBytes,
  verifyBytes,
  JSF_ASYMMETRIC_ALGORITHMS,
} from './jsf/algorithms.js';

export type {
  AlgorithmSpec,
  RsaPkcs1Spec,
  RsaPssSpec,
  EcdsaSpec,
  EddsaSpec,
  HmacSpec,
  JsfAsymmetricAlgorithm,
} from './jsf/algorithms.js';

// -- Errors ------------------------------------------------------------------

export {
  SignatureError,
  JcsError,
  JsfError,
  JsfInputError,
  JsfKeyError,
  JsfEnvelopeError,
  JsfSignError,
  JsfVerifyError,
  JssError,
  JssNotImplementedError,
  JssInputError,
  JssEnvelopeError,
} from './errors.js';

// -- Shared types ------------------------------------------------------------

export type {
  JsonObject,
  JsonValue,
  JwkKeyType,
  JwkPublicKey,
  KeyInput,
  SignatureFormat,
  // Back-compat type names from @cyclonedx/jsf.
  JsfJwkKeyType,
  JsfPublicKey,
} from './types.js';

// -- JSF types ---------------------------------------------------------------

export type {
  JsfAlgorithm,
  JsfSigner,
  JsfSignOptions,
  JsfVerifyOptions,
  JsfVerifyResult,
} from './jsf/types.js';

// -- JSS types ---------------------------------------------------------------

export type {
  JssAlgorithm,
  JssSigner,
  JssSignOptions,
  JssVerifyOptions,
  JssVerifyResult,
} from './jss/types.js';

// -- JWK normalization types -------------------------------------------------

export type {
  NormalizedPrivateKey,
  NormalizedPublicKey,
} from './jwk.js';
