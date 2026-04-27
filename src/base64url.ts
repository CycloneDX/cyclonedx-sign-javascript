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
 */

export function encodeBase64Url(input: Uint8Array | Buffer): string {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf
    .toString('base64')
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
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

/**
 * Encode a non-negative big-endian byte array with leading zeros
 * stripped. Useful for RSA modulus/exponent conversion where JWK
 * rejects unneeded leading zero octets.
 */
export function encodeBase64UrlBigInteger(bytes: Uint8Array | Buffer): string {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  let start = 0;
  // eslint-disable-next-line security/detect-object-injection -- `start` is a loop-bounded numeric index into a Buffer we just materialized.
  while (start < buf.length - 1 && buf[start] === 0) {
    start += 1;
  }
  return encodeBase64Url(buf.subarray(start));
}
