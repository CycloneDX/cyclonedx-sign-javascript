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
 * JWK import and export helpers.
 *
 * JSF embeds verifying keys as JWK objects (RFC 7517). This module
 * delegates the actual import / export work to the active crypto
 * backend (`#crypto-backend`). Callers can supply:
 *
 *   - PEM strings (PKCS#8 private, SPKI public, X.509 certificate)
 *   - JWK objects (with private parameters for sign-side, without for
 *     verify-side)
 *   - Raw `Uint8Array` for HMAC keys
 *   - Backend-native handles (Node `KeyObject` or Web `CryptoKey`,
 *     each accepted only by its corresponding backend)
 *
 * The module also exposes `sanitizePublicJwk()` which strips a JWK to
 * the subset JSF recognizes (and explicitly removes private fields
 * like `d`, `p`, `q` so a sign-side JWK never leaks through to the
 * embedded `publicKey` slot).
 */

import { backend } from '#crypto-backend';
import type { PrivateKeyHandle, PublicKeyHandle } from './internal/crypto/types.js';
import type { JwkPublicKey, KeyInput } from './types.js';
import { JsfKeyError } from './errors.js';

/** Public re-export so callers can hold the same type the library uses internally. */
export type NormalizedPrivateKey = PrivateKeyHandle;
export type NormalizedPublicKey = PublicKeyHandle;

/**
 * Convert a KeyInput to a private key handle. The handle exposes the
 * key's metadata (kind, curve, RSA modulus bits) and is consumed by
 * the format orchestrators directly.
 */
export async function toPrivateKey(input: KeyInput): Promise<PrivateKeyHandle> {
  try {
    return await backend.importPrivateKey(input);
  } catch (err) {
    throw new JsfKeyError(`Unsupported private key input: ${(err as Error).message}`);
  }
}

/**
 * Convert a KeyInput to a public key handle. Private-key inputs are
 * converted to their public half automatically.
 */
export async function toPublicKey(input: KeyInput): Promise<PublicKeyHandle> {
  try {
    return await backend.importPublicKey(input);
  } catch (err) {
    throw new JsfKeyError(`Unsupported public key input: ${(err as Error).message}`);
  }
}

/**
 * Derive the publicKey JWK to embed in a JSF signer from any accepted
 * private or public key input.
 */
export async function exportPublicJwk(input: KeyInput): Promise<JwkPublicKey> {
  const handle = await toPublicKey(input);
  if (handle.kind === 'oct') {
    throw new JsfKeyError('HMAC keys must not be embedded in a JSF envelope');
  }
  const raw = await handle.exportJwk();
  return sanitizePublicJwk(raw);
}

/**
 * Strip a JWK to the fields JSF actually defines for each kty, and
 * remove every private parameter. Downstream consumers can still
 * round-trip a sanitized JWK through any importer because all
 * required public fields remain present.
 */
export function sanitizePublicJwk(raw: Record<string, unknown>): JwkPublicKey {
  const kty = raw.kty;
  if (kty === 'RSA') {
    requireFields(raw, ['n', 'e'], 'RSA');
    return { kty: 'RSA', n: String(raw.n), e: String(raw.e) };
  }
  if (kty === 'EC') {
    requireFields(raw, ['crv', 'x', 'y'], 'EC');
    return { kty: 'EC', crv: String(raw.crv), x: String(raw.x), y: String(raw.y) };
  }
  if (kty === 'OKP') {
    requireFields(raw, ['crv', 'x'], 'OKP');
    return { kty: 'OKP', crv: String(raw.crv), x: String(raw.x) };
  }
  if (kty === 'oct') {
    // JSF permits HMAC envelopes only for completeness — callers
    // sending oct keys have already deliberately asked for it.
    requireFields(raw, ['k'], 'oct');
    return { kty: 'oct', k: String(raw.k) };
  }
  throw new JsfKeyError(`Unsupported JWK kty: ${String(kty)}`);
}

function requireFields(raw: Record<string, unknown>, fields: string[], kty: string): void {
  for (const field of fields) {
    // eslint-disable-next-line security/detect-object-injection -- `field` is a caller-supplied constant list of JWK member names (for example ['n', 'e']).
    if (raw[field] === undefined || raw[field] === null || raw[field] === '') {
      throw new JsfKeyError(`JWK ${kty} missing required field ${field}`);
    }
  }
}
