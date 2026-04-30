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
 * base64url codec per RFC 7515 Appendix C.
 *
 * Unlike standard base64, base64url uses `-` and `_` in place of `+`
 * and `/` and omits `=` padding. All JSF signature values and JWK
 * coordinates use this encoding.
 *
 * Implemented against `btoa` / `atob` rather than Node's `Buffer`.
 * Both are exposed as globals on every runtime this package targets:
 * Node 20+, browsers, Deno, Cloudflare Workers, etc. An earlier
 * version of this module called `Buffer.from(...).toString('base64')`,
 * which threw `ReferenceError: Buffer is not defined` the moment the
 * Web bundle reached `value`-encoding inside the JSF sign pipeline.
 */

/**
 * Encode a byte sequence as base64url. Accepts any `Uint8Array`-shaped
 * input, including `Buffer` (which extends Uint8Array) for backward
 * compatibility with Node-side callers.
 */
export function encodeBase64Url(input: Uint8Array): string {
  // String.fromCharCode applied byte-by-byte builds a binary string
  // that btoa understands. Spread (`...input`) would blow the call
  // stack on very large inputs; a counted loop stays safe.
  let bin = '';
  for (let i = 0; i < input.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop bounded by length.
    bin += String.fromCharCode(input[i]!);
  }
  return btoa(bin)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function decodeBase64Url(input: string): Uint8Array {
  if (typeof input !== 'string') {
    throw new TypeError('base64url input must be a string');
  }
  // Reject characters outside the alphabet. A defensive parser avoids
  // silently accepting standard-base64 with `+`/`/` which would mask
  // signer bugs.
  if (!/^[A-Za-z0-9_-]*$/.test(input)) {
    throw new Error('Invalid base64url: contains characters outside the alphabet');
  }
  const padLength = (4 - (input.length % 4)) % 4;
  const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padLength);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop bounded by length.
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/**
 * Encode a non-negative big-endian byte array with leading zeros
 * stripped. Useful for RSA modulus/exponent conversion where JWK
 * rejects unneeded leading zero octets.
 */
export function encodeBase64UrlBigInteger(bytes: Uint8Array): string {
  let start = 0;
  // eslint-disable-next-line security/detect-object-injection -- `start` is a loop-bounded numeric index.
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start += 1;
  }
  return encodeBase64Url(bytes.subarray(start));
}
