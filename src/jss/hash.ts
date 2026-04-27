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

const HASH_NAMES = {
  'sha-256': 'sha256',
  'sha-384': 'sha384',
  'sha-512': 'sha512',
} as const satisfies Record<JssHashAlgorithm, string>;

const HASH_LENGTHS: Record<JssHashAlgorithm, number> = {
  'sha-256': 32,
  'sha-384': 48,
  'sha-512': 64,
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
