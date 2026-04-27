/**
 * Shared test helpers.
 *
 * The same key-pair generation functions and `KeyPair` interface
 * were previously duplicated across nearly every `*.test.ts` file.
 * Importing from here removes that duplication so Codacy's clones
 * detector does not flag boilerplate setup as repeated code.
 */
import { generateKeyPairSync } from 'node:crypto';
/** Generate a fresh EC key pair. Defaults to P-256 (`prime256v1`). */
export function ecPair(curve = 'prime256v1') {
    return generateKeyPairSync('ec', { namedCurve: curve });
}
/** Generate a fresh RSA key pair. Defaults to 2048-bit. */
export function rsaPair(modulusLength = 2048) {
    return generateKeyPairSync('rsa', { modulusLength });
}
/** Generate a fresh EdDSA key pair. Defaults to Ed25519. */
export function edPair(kind = 'ed25519') {
    return generateKeyPairSync(kind);
}
