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
 * Hash algorithm registry for JSS.
 *
 * X.590 clause 6.2.1 defines `hash_algorithm` as a case-sensitive
 * ASCII string from the IANA registry, with `sha-256` and `sha-512`
 * called out explicitly. We ship `sha-256`, `sha-384`, and `sha-512`
 * which is the JWA-aligned subset used by every JSS algorithm in
 * clause 6.2.2 table 1 (RS*, PS*, ES*; Ed* internally hash again so
 * any of these three is acceptable for the pre-hash step).
 *
 * The hash names are spelled in the spec's exact lowercase-with-hyphen
 * form and the registry comparison is case-sensitive (X.590 clause
 * 6.2.1).
 */

import { createHash } from 'node:crypto';
import { JssInputError } from '../errors.js';

export type JssHashAlgorithm = 'sha-256' | 'sha-384' | 'sha-512';

/**
 * Named runtime constants for the JSS hash algorithms. Callers who
 * prefer dot-access over the hyphenated wire string can write
 * `JssHashAlgorithms.SHA_256` instead of `'sha-256'`. The values are
 * the exact X.590 / IANA wire identifiers (lower-case, hyphenated)
 * and the type is `JssHashAlgorithm`.
 */
export const JssHashAlgorithms = {
  SHA_256: 'sha-256',
  SHA_384: 'sha-384',
  SHA_512: 'sha-512',
} as const satisfies Record<string, JssHashAlgorithm>;

const HASH_NAMES = {
  [JssHashAlgorithms.SHA_256]: 'sha256',
  [JssHashAlgorithms.SHA_384]: 'sha384',
  [JssHashAlgorithms.SHA_512]: 'sha512',
} as const satisfies Record<JssHashAlgorithm, string>;

const HASH_LENGTHS: Record<JssHashAlgorithm, number> = {
  [JssHashAlgorithms.SHA_256]: 32,
  [JssHashAlgorithms.SHA_384]: 48,
  [JssHashAlgorithms.SHA_512]: 64,
};

export function isRegisteredHashAlgorithm(name: string): name is JssHashAlgorithm {
  return Object.prototype.hasOwnProperty.call(HASH_NAMES, name);
}

export function hashLength(name: JssHashAlgorithm): number {
  // eslint-disable-next-line security/detect-object-injection -- `name` was just narrowed to a key of HASH_LENGTHS.
  return HASH_LENGTHS[name];
}

export function hashBytes(name: string, data: Uint8Array): Buffer {
  if (!isRegisteredHashAlgorithm(name)) {
    throw new JssInputError(`Unsupported JSS hash algorithm: ${name}`);
  }
  // eslint-disable-next-line security/detect-object-injection -- `name` was narrowed to JssHashAlgorithm, a known key.
  const nodeName = HASH_NAMES[name];
  return createHash(nodeName).update(data).digest();
}
