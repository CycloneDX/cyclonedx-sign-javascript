/**
 * JSF algorithm registry and cryptographic primitives.
 *
 * This module owns every call into `node:crypto` for JSF. The JSF
 * orchestrator never touches Node's sign/verify directly — it asks this
 * module to sign/verify canonical bytes given a spec and a key object.
 * That keeps algorithm knowledge in exactly one place and gives callers
 * a single seam if they later want to retarget to WebCrypto or a
 * hardware token.
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

import {
  constants as cryptoConstants,
  createHmac,
  sign as nodeSign,
  timingSafeEqual,
  verify as nodeVerify,
  type KeyObject,
} from 'node:crypto';

import type { JsfAlgorithm } from './types.js';
import { JsfSignError, JsfInputError } from '../errors.js';

export interface RsaPkcs1Spec {
  family: 'rsa-pkcs1';
  digest: 'sha256' | 'sha384' | 'sha512';
  expectedKeyType: 'rsa';
}

export interface RsaPssSpec {
  family: 'rsa-pss';
  digest: 'sha256' | 'sha384' | 'sha512';
  saltLength: number;
  expectedKeyType: 'rsa' | 'rsa-pss';
}

export interface EcdsaSpec {
  family: 'ecdsa';
  digest: 'sha256' | 'sha384' | 'sha512';
  expectedKeyType: 'ec';
  expectedCurve: 'P-256' | 'P-384' | 'P-521';
  coordinateBytes: number;
}

export interface EddsaSpec {
  family: 'eddsa';
  expectedKeyType: 'ed25519' | 'ed448';
}

export interface HmacSpec {
  family: 'hmac';
  digest: 'sha256' | 'sha384' | 'sha512';
  expectedKeyType: 'oct';
}

export type AlgorithmSpec = RsaPkcs1Spec | RsaPssSpec | EcdsaSpec | EddsaSpec | HmacSpec;

const SPECS: Record<JsfAlgorithm, AlgorithmSpec> = {
  RS256: { family: 'rsa-pkcs1', digest: 'sha256', expectedKeyType: 'rsa' },
  RS384: { family: 'rsa-pkcs1', digest: 'sha384', expectedKeyType: 'rsa' },
  RS512: { family: 'rsa-pkcs1', digest: 'sha512', expectedKeyType: 'rsa' },
  PS256: { family: 'rsa-pss', digest: 'sha256', saltLength: 32, expectedKeyType: 'rsa' },
  PS384: { family: 'rsa-pss', digest: 'sha384', saltLength: 48, expectedKeyType: 'rsa' },
  PS512: { family: 'rsa-pss', digest: 'sha512', saltLength: 64, expectedKeyType: 'rsa' },
  ES256: { family: 'ecdsa', digest: 'sha256', expectedKeyType: 'ec', expectedCurve: 'P-256', coordinateBytes: 32 },
  ES384: { family: 'ecdsa', digest: 'sha384', expectedKeyType: 'ec', expectedCurve: 'P-384', coordinateBytes: 48 },
  ES512: { family: 'ecdsa', digest: 'sha512', expectedKeyType: 'ec', expectedCurve: 'P-521', coordinateBytes: 66 },
  Ed25519: { family: 'eddsa', expectedKeyType: 'ed25519' },
  Ed448: { family: 'eddsa', expectedKeyType: 'ed448' },
  HS256: { family: 'hmac', digest: 'sha256', expectedKeyType: 'oct' },
  HS384: { family: 'hmac', digest: 'sha384', expectedKeyType: 'oct' },
  HS512: { family: 'hmac', digest: 'sha512', expectedKeyType: 'oct' },
};

export function getAlgorithmSpec(algorithm: string): AlgorithmSpec {
  // eslint-disable-next-line security/detect-object-injection -- `algorithm` is validated below via the hasOwn check on the SPECS table.
  const spec = SPECS[algorithm as JsfAlgorithm];
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- The cast above lies to TypeScript; at runtime `algorithm` may be any string, so this guard covers the spec-missing case.
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
 * Sign the canonical bytes with the given algorithm and key.
 *
 * Returns the signature as raw bytes — the JSF orchestrator is
 * responsible for base64url-encoding the result before embedding
 * it in the envelope.
 */
export function signBytes(
  spec: AlgorithmSpec,
  data: Uint8Array,
  keyObject: KeyObject,
  keyCurve: string | null,
): Buffer {
  assertKeyMatches(spec, keyObject, keyCurve, 'sign');
  try {
    switch (spec.family) {
      case 'rsa-pkcs1':
        return nodeSign(spec.digest, data, keyObject);
      case 'rsa-pss':
        return nodeSign(spec.digest, data, {
          key: keyObject,
          padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength: spec.saltLength,
        });
      case 'ecdsa':
        return nodeSign(spec.digest, data, { key: keyObject, dsaEncoding: 'ieee-p1363' });
      case 'eddsa':
        return nodeSign(null, data, keyObject);
      case 'hmac':
        return createHmac(spec.digest, keyObject).update(data).digest();
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
export function verifyBytes(
  spec: AlgorithmSpec,
  data: Uint8Array,
  signature: Uint8Array,
  keyObject: KeyObject,
  keyCurve: string | null,
): boolean {
  assertKeyMatches(spec, keyObject, keyCurve, 'verify');
  try {
    switch (spec.family) {
      case 'rsa-pkcs1':
        return nodeVerify(spec.digest, data, keyObject, signature);
      case 'rsa-pss':
        return nodeVerify(spec.digest, data, {
          key: keyObject,
          padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength: spec.saltLength,
        }, signature);
      case 'ecdsa':
        // A well-formed IEEE P1363 signature is exactly 2 * coordinateBytes.
        // Reject oddball lengths up front to keep tampered envelopes from
        // triggering noisy Node errors downstream.
        if (signature.length !== spec.coordinateBytes * 2) {
          return false;
        }
        return nodeVerify(spec.digest, data, { key: keyObject, dsaEncoding: 'ieee-p1363' }, signature);
      case 'eddsa':
        return nodeVerify(null, data, keyObject, signature);
      case 'hmac': {
        const mac = createHmac(spec.digest, keyObject).update(data).digest();
        if (mac.length !== signature.length) return false;
        return timingSafeEqual(mac, signature);
      }
    }
  } catch {
    // A Node-level exception on verify almost always means the
    // signature was malformed for the algorithm. Surface as a clean
    // failure rather than a thrown error.
    return false;
  }
}

function assertKeyMatches(
  spec: AlgorithmSpec,
  keyObject: KeyObject,
  keyCurve: string | null,
  operation: 'sign' | 'verify',
): void {
  const kt = keyObject.type === 'secret' ? 'oct' : keyObject.asymmetricKeyType;
  switch (spec.family) {
    case 'rsa-pkcs1':
    case 'rsa-pss':
      if (kt !== 'rsa' && kt !== 'rsa-pss') {
        throw new JsfInputError(`Algorithm requires an RSA key for ${operation}; got ${String(kt)}`);
      }
      break;
    case 'ecdsa':
      if (kt !== 'ec') {
        throw new JsfInputError(`Algorithm requires an EC key for ${operation}; got ${String(kt)}`);
      }
      if (keyCurve !== spec.expectedCurve) {
        throw new JsfInputError(
          `Algorithm requires EC curve ${spec.expectedCurve} for ${operation}; got ${String(keyCurve)}`,
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
