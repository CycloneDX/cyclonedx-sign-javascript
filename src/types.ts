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
 * Shared type definitions for the @cyclonedx/sign package.
 *
 * This module holds only the types that are neutral across JSF and JSS.
 * Format-specific types live in ./jsf/types.ts and ./jss/types.ts.
 */

import type { KeyObject } from 'node:crypto';

/** JSON value types recognized by JCS, JSF, and JSS. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | JsonObject;

// eslint-disable-next-line @typescript-eslint/consistent-indexed-object-style -- Kept as an interface because JsonValue and JsonObject are mutually recursive; type aliases cannot express that directly.
export interface JsonObject {
  [key: string]: JsonValue;
}

/** JWK key types recognized by both JSF and JSS signer envelopes. */
export type JwkKeyType = 'RSA' | 'EC' | 'OKP' | 'oct';

/**
 * JWK shape used by embedded publicKey fields. Both JSF and JSS use the
 * same JWK layout, so this type is shared.
 */
export interface JwkPublicKey {
  kty: JwkKeyType;
  // RSA
  n?: string;
  e?: string;
  // EC / OKP
  crv?: string;
  x?: string;
  y?: string;
  // HMAC (signing only; never embedded in a signed envelope because
  // symmetric keys are secret, but modeled for completeness).
  k?: string;
  [extra: string]: unknown;
}

/**
 * Accepted private-key and public-key inputs for signing and verifying.
 *
 * JWK objects are fully-described material. Strings accept PEM-encoded
 * PKCS#8 private keys, SPKI public keys, X.509 certificates, or JWK
 * JSON. Buffers are treated as raw symmetric key material. KeyObject
 * instances pass through untouched.
 *
 * For HMAC (HS256/384/512) pass either a Buffer of raw key bytes or a
 * JWK with kty='oct' and k set to the base64url-encoded key.
 */
export type KeyInput = JwkPublicKey | string | Buffer | Uint8Array | KeyObject;

/**
 * CycloneDX major version. This is the primary discriminator exposed by
 * the top-level sign() and verify() functions. The library maps the
 * major version onto the right JSON signing format:
 *
 *   V1 -> JSF (JSON Signature Format, 0.82)
 *   V2 -> JSS (JSON Signature Schema, X.590)
 *
 * Using the CycloneDX major version rather than the underlying format
 * name lets tool authors think in terms of their specification target
 * and avoids leaking signing-format vocabulary into the call site.
 */
export enum CycloneDxMajor {
  // eslint-disable-next-line no-unused-vars -- enum members are consumed at call sites (for example sign(..., { cyclonedxVersion: CycloneDxMajor.V1 })) but the rule does not see cross-file usage.
  V1 = 1,
  // eslint-disable-next-line no-unused-vars -- enum members are consumed at call sites but the rule does not see cross-file usage.
  V2 = 2,
}

/**
 * Signature format discriminator. This is an internal concept that
 * still surfaces through the detectFormat() utility and the ./jsf and
 * ./jss subpath imports. Most callers should prefer CycloneDxMajor on
 * the top-level API.
 */
export type SignatureFormat = 'jsf' | 'jss';
