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
 * PEM body codec for JSS public_key fields.
 *
 * Per ITU-T X.590 clause 6.2.1, the `public_key` property "contains a
 * privacy enhanced mail (PEM) encoded public key without the header
 * and footer". The wire value is therefore the base64 of a DER-encoded
 * SubjectPublicKeyInfo (SPKI), with the BEGIN/END markers stripped
 * and any whitespace removed.
 *
 * This module wraps the active crypto backend's key import / export
 * paths so the JSS binding can convert between the wire form and a
 * runtime-neutral key handle.
 */

import { backend } from '#crypto-backend';
import type { PrivateKeyHandle, PublicKeyHandle } from '../internal/crypto/types.js';
import { JssInputError, JssEnvelopeError } from '../errors.js';
import type { KeyInput } from '../types.js';

const PEM_PUBLIC_HEADER = '-----BEGIN PUBLIC KEY-----';
const PEM_PUBLIC_FOOTER = '-----END PUBLIC KEY-----';

/**
 * Wrap a PEM body (just the base64 content) in PEM headers and parse
 * as a public key handle.
 *
 * Accepts the body with or without padding (`=`). Whitespace inside
 * the body is stripped before re-emission.
 */
export async function publicKeyFromPemBody(body: string): Promise<PublicKeyHandle> {
  if (typeof body !== 'string' || body.length === 0) {
    throw new JssInputError('public_key body must be a non-empty string');
  }
  const cleaned = body.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]+=*$/.test(cleaned)) {
    throw new JssEnvelopeError('public_key body is not valid base64');
  }
  // Add padding if absent.
  const pad = cleaned.length % 4 === 0 ? '' : '='.repeat(4 - (cleaned.length % 4));
  const wrapped = wrap(`${cleaned}${pad}`, PEM_PUBLIC_HEADER, PEM_PUBLIC_FOOTER);
  try {
    return await backend.importPublicKey(wrapped);
  } catch (err) {
    throw new JssEnvelopeError(`public_key body did not parse as PEM SPKI: ${(err as Error).message}`);
  }
}

/**
 * Inverse of `publicKeyFromPemBody`: export a public key handle as a
 * base64 string with the BEGIN/END headers stripped. Trailing `=`
 * padding is removed to match the spec's Appendix II.1 example
 * verbatim ("MCowBQYDK2VwAyEAubMon...ZkU" without trailing `=`).
 * Both forms parse correctly per `publicKeyFromPemBody`.
 */
export async function pemBodyFromPublicKey(key: PublicKeyHandle): Promise<string> {
  const pem = await key.exportSpkiPem();
  return stripPemHeaders(pem).replace(/=+$/, '');
}

/**
 * Normalize any accepted private-key input form into a backend
 * `PrivateKeyHandle`. Single source of truth for JSS sign-side key
 * normalization; consumed by `src/jss/sign.ts` and `src/jss/binding.ts`.
 */
export async function toPrivateKey(input: KeyInput): Promise<PrivateKeyHandle> {
  try {
    return await backend.importPrivateKey(input);
  } catch (err) {
    throw new JssInputError(`Unsupported private key input for JSS: ${(err as Error).message}`);
  }
}

/**
 * Normalize any accepted public-key input form into a backend
 * `PublicKeyHandle`. Private-key inputs are converted to their public
 * half. Single source of truth shared by `src/jss/sign.ts` and
 * `src/jss/binding.ts`.
 */
export async function toPublicKey(input: KeyInput): Promise<PublicKeyHandle> {
  try {
    return await backend.importPublicKey(input);
  } catch (err) {
    throw new JssInputError(`Unsupported public key input for JSS: ${(err as Error).message}`);
  }
}

function wrap(body: string, header: string, footer: string): string {
  // Re-emit the body with 64-character lines, matching the canonical
  // PEM layout. Most parsers are lenient about line length but a
  // strict layout makes round-tripping deterministic.
  const lines: string[] = [header];
  for (let i = 0; i < body.length; i += 64) {
    lines.push(body.slice(i, i + 64));
  }
  lines.push(footer);
  lines.push('');
  return lines.join('\n');
}

function stripPemHeaders(pem: string): string {
  return pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
}
