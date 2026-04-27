/**
 * Shared test helpers.
 *
 * The same key-pair generation functions and `KeyPair` interface
 * were previously duplicated across nearly every `*.test.ts` file.
 * Importing from here removes that duplication so Codacy's clones
 * detector does not flag boilerplate setup as repeated code.
 */

import { generateKeyPairSync, type KeyObject } from 'node:crypto';

export interface KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

/** Generate a fresh EC key pair. Defaults to P-256 (`prime256v1`). */
export function ecPair(
  curve: 'prime256v1' | 'secp384r1' | 'secp521r1' = 'prime256v1',
): KeyPair {
  return generateKeyPairSync('ec', { namedCurve: curve }) as unknown as KeyPair;
}

/** Generate a fresh RSA key pair. Defaults to 2048-bit. */
export function rsaPair(modulusLength = 2048): KeyPair {
  return generateKeyPairSync('rsa', { modulusLength }) as unknown as KeyPair;
}

/** Generate a fresh EdDSA key pair. Defaults to Ed25519. */
export function edPair(kind: 'ed25519' | 'ed448' = 'ed25519'): KeyPair {
  return (generateKeyPairSync as unknown as (k: string) => KeyPair)(kind);
}
