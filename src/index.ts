/**
 * Public API for the @cyclonedx/sign package.
 *
 * This library implements JSON Signature Format (JSF, 0.82),
 * JSON Signature Schema (JSS, X.590, stub), and the JSON
 * Canonicalization Scheme (JCS, RFC 8785) used by both, so CycloneDX
 * tool authors can target both CycloneDX 1.x (JSF) and CycloneDX 2.x
 * (JSS) through a single dependency.
 *
 * The top-level `sign()` and `verify()` are async and dispatch to
 * the right format based on the `CycloneDxMajor` enum passed in
 * options.cyclonedxVersion:
 *
 *   CycloneDxMajor.V1 -> JSF
 *   CycloneDxMajor.V2 -> JSS
 *
 * Defaults to V1 when omitted.
 *
 * The subject passed to sign() / verify() can be the whole BOM or any
 * JSON object inside it. The library does not inspect BOM structure;
 * callers pick what to sign by passing the exact object.
 *
 * Example: sign a whole BOM
 *
 *     import { sign, CycloneDxMajor } from '@cyclonedx/sign';
 *
 *     const signedBom = await sign(bom, {
 *       cyclonedxVersion: CycloneDxMajor.V1,
 *       signer: { algorithm: 'ES256', privateKey: ecPem },
 *     });
 *
 * Example: multi-signer (JSF Multiple Signatures)
 *
 *     const signed = await sign(payload, {
 *       signers: [
 *         { algorithm: 'ES256', privateKey: keyA },
 *         { algorithm: 'RS256', privateKey: keyB },
 *       ],
 *       mode: 'multi',
 *     });
 *
 * Example: chain (JSF Signature Chains, used for counter-signatures)
 *
 *     const initial = await sign(payload, {
 *       signers: [{ algorithm: 'ES256', privateKey: keyA }],
 *       mode: 'chain',
 *     });
 *     const countersigned = await appendChainSigner(initial, {
 *       algorithm: 'RS256',
 *       privateKey: keyB,
 *     });
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

export * as jsf from './jsf/index.js';
export * as jss from './jss/index.js';

// -- JSF helpers re-exported at the top level --------------------------------

export {
  appendChainSigner,
  appendMultiSigner,
  computeCanonicalInputs,
} from './jsf/sign.js';

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
  JsfMultiSignerInputError,
  JsfChainOrderError,
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

// -- Format-agnostic core (advanced) ----------------------------------------

export type {
  EnvelopeMode,
  EnvelopeOptions,
  EnvelopeView,
  Signer,
  SignerDescriptor,
  SignerVerifyOutcome,
  Verifier,
  VerifyPolicy,
  WrapperState,
} from './core/types.js';

export type {
  FormatBinding,
  SignerKeyInput,
  VerifierKeyInput,
} from './core/binding.js';

export {
  JSF_RESERVED_WORDS,
  JSF_SIGNATURECORE_FIELDS,
  isJsfReservedWord,
  isJsfSignatureCoreField,
} from './core/jsf-reserved.js';
