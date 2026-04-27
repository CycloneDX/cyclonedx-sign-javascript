/*!
This file is part of CycloneDX Signing Library for Javascript.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
Copyright (c) OWASP Foundation. All Rights Reserved.
*/

/**
 * Public API for the @cyclonedx/sign package.
 *
 * This library implements JSON Signature Format (JSF, 0.82),
 * JSON Signature Scheme (JSS, X.590, stub), and the JSON
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

// -- JSS counter sign helper re-exported at the top level --------------------

export { countersign as countersignJss } from './jss/sign.js';

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

// -- Format-agnostic core (the plug-in surface) -----------------------------
//
// The Signer / Verifier interfaces and the verify-policy aggregator are
// the only cross-format primitives. HSM, KMS, and remote-signer adapter
// packages target these. Format-specific shapes (envelope modes, signer
// descriptors, wrapper state, validation) live next to the format that
// owns them: see `@cyclonedx/sign/jsf` and `@cyclonedx/sign/jss`.

export type { Signer, Verifier, VerifyPolicy } from './core/index.js';
export { applyPolicy } from './core/index.js';

// -- JSF-specific helpers (advanced) ----------------------------------------

export {
  JSF_RESERVED_WORDS,
  JSF_SIGNATURECORE_FIELDS,
  isJsfReservedWord,
  isJsfSignatureCoreField,
} from './jsf/reserved.js';
