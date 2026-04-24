/**
 * Public API for the @cyclonedx/sign package.
 *
 * This library implements JSON Signature Format (JSF) and the JSON
 * Canonicalization Scheme (JCS, RFC 8785) today, and carries a stub
 * for JSON Signature Schema (JSS, X.590) so CycloneDX tool authors
 * can target both CycloneDX 1.x (JSF) and CycloneDX 2.x (JSS) through
 * a single dependency.
 *
 * The top-level sign() and verify() dispatch to the right format based
 * on the CycloneDxMajor enum passed in options.cyclonedxVersion:
 *
 *   CycloneDxMajor.V1 -> JSF
 *   CycloneDxMajor.V2 -> JSS
 *
 * Defaulting to V1 when cyclonedxVersion is omitted.
 *
 * The subject passed to sign() / verify() can be the whole BOM or any
 * JSON object inside it. The library does not inspect BOM structure;
 * the caller is responsible for handing in the exact object they want
 * signed or verified.
 *
 * Example: sign a whole BOM
 *
 *     import { sign, CycloneDxMajor } from '@cyclonedx/sign';
 *
 *     const signedBom = sign(bom, {
 *       cyclonedxVersion: CycloneDxMajor.V1,
 *       algorithm: 'ES256',
 *       privateKey: ecPem,
 *     });
 *
 * Example: sign a sub-object (declarations block) in place
 *
 *     bom.declarations = sign(bom.declarations, {
 *       cyclonedxVersion: CycloneDxMajor.V1,
 *       algorithm: 'ES256',
 *       privateKey,
 *     });
 *
 * Example: verify
 *
 *     const result = verify(signedBom, { cyclonedxVersion: CycloneDxMajor.V1 });
 *     result.valid;              // true
 *     result.cyclonedxVersion;   // CycloneDxMajor.V1
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
  detectFormat,
  cyclonedxFormat,
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
//     jsf.sign(payload, options);
//
// Or import directly from the subpath:
//
//     import { sign, verify } from '@cyclonedx/sign/jsf';

export * as jsf from './jsf/index.js';
export * as jss from './jss/index.js';

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

export { CycloneDxMajor } from './types.js';

export type {
  JsonObject,
  JsonValue,
  JwkKeyType,
  JwkPublicKey,
  KeyInput,
  SignatureFormat,
} from './types.js';

// -- JWK normalization types -------------------------------------------------

export type {
  NormalizedPrivateKey,
  NormalizedPublicKey,
} from './jwk.js';
