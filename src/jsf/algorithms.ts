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
 * JSF algorithm registry and cryptographic primitives.
 *
 * This module owns every JSF cryptographic dispatch decision. The JSF
 * orchestrator never reaches into a host crypto API directly; it asks
 * this module to sign / verify canonical bytes given a spec and a key
 * handle. The actual primitive lives in the active backend (Node or
 * Web), which `signBytes` / `verifyBytes` route through.
 *
 * Per the JSF 0.82 specification and the CycloneDX jsf-0.82 subschema:
 *   RS256/384/512 — RSA PKCS#1 v1.5 with SHA-256/384/512
 *   PS256/384/512 — RSA-PSS with SHA-256/384/512, MGF1 on the same
 *                   digest, salt length equal to the digest length
 *   ES256/384/512 — ECDSA on P-256/P-384/P-521 with SHA-256/384/512.
 *                   Signature encoded as R||S, each element padded to
 *                   the fixed curve size (IEEE P1363 form — NOT DER).
 *   Ed25519/Ed448 — EdDSA as defined in RFC 8032.
 *   HS256/384/512 — HMAC with SHA-256/384/512.
 */

import { backend } from '#crypto-backend';
import type {
  PrivateKeyHandle,
  PublicKeyHandle,
  Sha,
  SymmetricKeyHandle,
  EcCurve,
} from '../internal/crypto/types.js';

import type { JsfAlgorithm } from './types.js';
import { JsfSignError, JsfInputError } from '../errors.js';

export interface RsaPkcs1Spec {
  family: 'rsa-pkcs1';
  digest: Sha;
  expectedKeyType: 'rsa';
}

export interface RsaPssSpec {
  family: 'rsa-pss';
  digest: Sha;
  saltLength: number;
  expectedKeyType: 'rsa' | 'rsa-pss';
}

export interface EcdsaSpec {
  family: 'ecdsa';
  digest: Sha;
  expectedKeyType: 'ec';
  expectedCurve: EcCurve;
  coordinateBytes: number;
}

export interface EddsaSpec {
  family: 'eddsa';
  expectedKeyType: 'ed25519' | 'ed448';
}

export interface HmacSpec {
  family: 'hmac';
  digest: Sha;
  expectedKeyType: 'oct';
}

export type AlgorithmSpec = RsaPkcs1Spec | RsaPssSpec | EcdsaSpec | EddsaSpec | HmacSpec;

const SPECS: Record<JsfAlgorithm, AlgorithmSpec> = {
  RS256: { family: 'rsa-pkcs1', digest: 'sha-256', expectedKeyType: 'rsa' },
  RS384: { family: 'rsa-pkcs1', digest: 'sha-384', expectedKeyType: 'rsa' },
  RS512: { family: 'rsa-pkcs1', digest: 'sha-512', expectedKeyType: 'rsa' },
  PS256: { family: 'rsa-pss', digest: 'sha-256', saltLength: 32, expectedKeyType: 'rsa' },
  PS384: { family: 'rsa-pss', digest: 'sha-384', saltLength: 48, expectedKeyType: 'rsa' },
  PS512: { family: 'rsa-pss', digest: 'sha-512', saltLength: 64, expectedKeyType: 'rsa' },
  ES256: { family: 'ecdsa', digest: 'sha-256', expectedKeyType: 'ec', expectedCurve: 'P-256', coordinateBytes: 32 },
  ES384: { family: 'ecdsa', digest: 'sha-384', expectedKeyType: 'ec', expectedCurve: 'P-384', coordinateBytes: 48 },
  ES512: { family: 'ecdsa', digest: 'sha-512', expectedKeyType: 'ec', expectedCurve: 'P-521', coordinateBytes: 66 },
  Ed25519: { family: 'eddsa', expectedKeyType: 'ed25519' },
  Ed448: { family: 'eddsa', expectedKeyType: 'ed448' },
  HS256: { family: 'hmac', digest: 'sha-256', expectedKeyType: 'oct' },
  HS384: { family: 'hmac', digest: 'sha-384', expectedKeyType: 'oct' },
  HS512: { family: 'hmac', digest: 'sha-512', expectedKeyType: 'oct' },
};

export function getAlgorithmSpec(algorithm: string): AlgorithmSpec {
   
  const spec = SPECS[algorithm as JsfAlgorithm];
   
  if (!spec) {
    throw new JsfInputError(`Unknown JSF algorithm: ${algorithm}`);
  }
  return spec;
}

/**
 * True if the given string is a registered JSF algorithm identifier.
 * The JSF spec also permits URI-encoded proprietary algorithms, but
 * this package does not own those; callers must use a custom provider.
 */
export function isRegisteredAlgorithm(algorithm: string): algorithm is JsfAlgorithm {
  return algorithm in SPECS;
}

/**
 * Named runtime constants for every JSF algorithm. Callers who prefer
 * dot-access over raw string literals can write
 * `JsfAlgorithms.ES256` instead of `'ES256'`. The values are the
 * exact JWA / JSF wire identifiers; the type is `JsfAlgorithm`, so
 * passing one of these into the sign / verify options is fully
 * type-safe.
 */
export const JsfAlgorithms = {
  RS256: 'RS256',
  RS384: 'RS384',
  RS512: 'RS512',
  PS256: 'PS256',
  PS384: 'PS384',
  PS512: 'PS512',
  ES256: 'ES256',
  ES384: 'ES384',
  ES512: 'ES512',
  Ed25519: 'Ed25519',
  Ed448: 'Ed448',
  HS256: 'HS256',
  HS384: 'HS384',
  HS512: 'HS512',
} as const satisfies Record<string, JsfAlgorithm>;

/**
 * The JSF asymmetric algorithms suitable for signatory use in
 * CycloneDX declarations.affirmation.signatories[].signature and for
 * the enveloping declarations.signature and top level document
 * signature. HMAC algorithms (HS256/384/512) are deliberately excluded
 * because symmetric keys are not appropriate for signatory attribution
 * or for tamper evident envelopes where the verifier is distinct from
 * the signer.
 */
export const JSF_ASYMMETRIC_ALGORITHMS = [
  JsfAlgorithms.RS256, JsfAlgorithms.RS384, JsfAlgorithms.RS512,
  JsfAlgorithms.PS256, JsfAlgorithms.PS384, JsfAlgorithms.PS512,
  JsfAlgorithms.ES256, JsfAlgorithms.ES384, JsfAlgorithms.ES512,
  JsfAlgorithms.Ed25519, JsfAlgorithms.Ed448,
] as const satisfies readonly JsfAlgorithm[];

export type JsfAsymmetricAlgorithm = typeof JSF_ASYMMETRIC_ALGORITHMS[number];

/**
 * True if the given string is a JSF asymmetric algorithm identifier
 * (excludes HMAC). Use this to validate user supplied algorithm
 * selections in signatory and envelope flows.
 */
export function isAsymmetricAlgorithm(algorithm: string): algorithm is JsfAsymmetricAlgorithm {
  return (JSF_ASYMMETRIC_ALGORITHMS as readonly string[]).includes(algorithm);
}

/**
 * Sign the canonical bytes with the given algorithm and key handle.
 *
 * Returns the signature as raw bytes — the JSF orchestrator is
 * responsible for base64url-encoding the result before embedding
 * it in the envelope.
 */
export async function signBytes(
  spec: AlgorithmSpec,
  data: Uint8Array,
  key: PrivateKeyHandle | SymmetricKeyHandle,
): Promise<Uint8Array> {
  assertKeyMatches(spec, key, 'sign');
  try {
    switch (spec.family) {
      case 'rsa-pkcs1':
        return await backend.signRsaPkcs1(spec.digest, data, key as PrivateKeyHandle);
      case 'rsa-pss':
        return await backend.signRsaPss(spec.digest, data, spec.saltLength, key as PrivateKeyHandle);
      case 'ecdsa':
        return await backend.signEcdsa(spec.digest, data, key as PrivateKeyHandle);
      case 'eddsa':
        return await backend.signEddsa(data, key as PrivateKeyHandle);
      case 'hmac':
        return await backend.hmacSign(spec.digest, key as SymmetricKeyHandle, data);
    }
  } catch (err) {
    throw new JsfSignError(`Signing with ${spec.family} failed: ${(err as Error).message}`, err);
  }
}

/**
 * Verify a signature against canonical bytes. Returns a boolean rather
 * than throwing; only input errors (wrong key shape for the algorithm)
 * surface as exceptions because those indicate caller bugs rather than
 * signature tampering.
 */
export async function verifyBytes(
  spec: AlgorithmSpec,
  data: Uint8Array,
  signature: Uint8Array,
  key: PublicKeyHandle | SymmetricKeyHandle,
): Promise<boolean> {
  assertKeyMatches(spec, key, 'verify');
  try {
    switch (spec.family) {
      case 'rsa-pkcs1':
        return await backend.verifyRsaPkcs1(spec.digest, data, signature, key as PublicKeyHandle);
      case 'rsa-pss':
        return await backend.verifyRsaPss(spec.digest, data, spec.saltLength, signature, key as PublicKeyHandle);
      case 'ecdsa':
        // A well-formed IEEE P1363 signature is exactly 2 * coordinateBytes.
        // Reject oddball lengths up front to keep tampered envelopes from
        // triggering noisy errors downstream.
        if (signature.length !== spec.coordinateBytes * 2) return false;
        return await backend.verifyEcdsa(spec.digest, data, signature, key as PublicKeyHandle);
      case 'eddsa':
        return await backend.verifyEddsa(data, signature, key as PublicKeyHandle);
      case 'hmac':
        return await backend.hmacVerify(spec.digest, key as SymmetricKeyHandle, data, signature);
    }
  } catch {
    return false;
  }
}

function assertKeyMatches(
  spec: AlgorithmSpec,
  key: { kind: string; curve: string | null },
  operation: 'sign' | 'verify',
): void {
  const kt = key.kind;
  switch (spec.family) {
    case 'rsa-pkcs1':
    case 'rsa-pss':
      if (kt !== 'rsa') {
        throw new JsfInputError(`Algorithm requires an RSA key for ${operation}; got ${String(kt)}`);
      }
      break;
    case 'ecdsa':
      if (kt !== 'ec') {
        throw new JsfInputError(`Algorithm requires an EC key for ${operation}; got ${String(kt)}`);
      }
      if (key.curve !== spec.expectedCurve) {
        throw new JsfInputError(
          `Algorithm requires EC curve ${spec.expectedCurve} for ${operation}; got ${String(key.curve)}`,
        );
      }
      break;
    case 'eddsa':
      if (kt !== spec.expectedKeyType) {
        throw new JsfInputError(
          `Algorithm requires an ${spec.expectedKeyType} key for ${operation}; got ${String(kt)}`,
        );
      }
      break;
    case 'hmac':
      if (kt !== 'oct') {
        throw new JsfInputError(`Algorithm requires a symmetric key for ${operation}; got ${String(kt)}`);
      }
      break;
  }
}
