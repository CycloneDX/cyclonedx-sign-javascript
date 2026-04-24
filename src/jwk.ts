/**
 * JWK import and export helpers.
 *
 * JSF embeds verifying keys as JWK objects (RFC 7517). Node's own
 * KeyObject can export to JWK and import from JWK for RSA/EC/OKP/oct,
 * but the input shapes we accept from application callers are messier
 * than Node's strict JWK parser tolerates. This module normalizes:
 *
 *   - PEM strings (PKCS#1, PKCS#8, SPKI, X.509)
 *   - Raw DER buffers (inferred as SPKI for public, PKCS#8 for private)
 *   - Pre-parsed JWK objects
 *   - Node KeyObject instances, which pass straight through
 *
 * It also canonicalizes the JWK shape to the subset JSF recognizes:
 *   RSA:  { kty: 'RSA', n, e }
 *   EC:   { kty: 'EC', crv, x, y }
 *   OKP:  { kty: 'OKP', crv, x }
 *   oct:  { kty: 'oct', k }
 *
 * Extraneous JWK fields (alg, use, key_ops, etc.) are stripped from
 * exports so the embedded publicKey never leaks policy beyond what
 * the JSF signer intentionally published.
 */

import { createPrivateKey, createPublicKey, createSecretKey, KeyObject } from 'node:crypto';
import type { JwkPublicKey, KeyInput } from './types.js';
import { JsfKeyError } from './errors.js';

export interface NormalizedPrivateKey {
  /** The Node KeyObject ready for signing. */
  keyObject: KeyObject;
  /** The key type as reported by Node (rsa | ec | ed25519 | ed448 | oct). */
  asymmetricKeyType: string;
  /** Curve name for ec/ed keys ('P-256', 'P-384', 'P-521', 'Ed25519', 'Ed448'). null otherwise. */
  curve: string | null;
}

export type NormalizedPublicKey = NormalizedPrivateKey;

/**
 * Convert a KeyInput to a Node private KeyObject, along with some
 * metadata handy for the signing layer.
 */
export function toPrivateKey(input: KeyInput): NormalizedPrivateKey {
  if (input instanceof KeyObject) {
    if (input.type === 'secret') {
      return {
        keyObject: input,
        asymmetricKeyType: 'oct',
        curve: null,
      };
    }
    if (input.type !== 'private') {
      throw new JsfKeyError('KeyObject must be a private key for signing');
    }
    return describeAsymmetric(input);
  }

  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('{')) {
      return toPrivateKey(parseJwk(trimmed));
    }
    const keyObject = createPrivateKey({ key: trimmed, format: 'pem' });
    return describeAsymmetric(keyObject);
  }

  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    // Buffers are only ever HMAC key material. Asymmetric key imports
    // go through PEM or JWK because DER detection is ambiguous.
    const secret = createSecretKey(Buffer.isBuffer(input) ? input : Buffer.from(input));
    return { keyObject: secret, asymmetricKeyType: 'oct', curve: null };
  }

  // Must be a JWK-like object
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Earlier branches narrowed the input, but this is a runtime guard that protects against JS callers that bypass the declared KeyInput type.
  if (typeof input === 'object' && input !== null && 'kty' in input) {
    const jwk = input;
    if (jwk.kty === 'oct') {
      if (!jwk.k) {
        throw new JsfKeyError('JWK oct requires a k property');
      }
      const secret = createSecretKey(Buffer.from(jwk.k, 'base64url'));
      return { keyObject: secret, asymmetricKeyType: 'oct', curve: null };
    }
    // createPrivateKey with format:'jwk' needs the JWK to have the
    // private parameters (d, p, q, dp, dq, qi for RSA; d for EC/OKP).
    const keyObject = createPrivateKey({ key: jwk as unknown as Record<string, unknown>, format: 'jwk' });
    return describeAsymmetric(keyObject);
  }

  throw new JsfKeyError('Unsupported private key input');
}

/**
 * Convert a KeyInput to a Node public KeyObject. Accepts JWK, PEM
 * (SPKI or X.509), Node KeyObject (public or private — the public half
 * is extracted from a private key), or HMAC bytes for symmetric alg.
 */
export function toPublicKey(input: KeyInput): NormalizedPublicKey {
  if (input instanceof KeyObject) {
    if (input.type === 'secret') {
      return { keyObject: input, asymmetricKeyType: 'oct', curve: null };
    }
    if (input.type === 'private') {
      const pub = createPublicKey(input);
      return describeAsymmetric(pub);
    }
    return describeAsymmetric(input);
  }

  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('{')) {
      return toPublicKey(parseJwk(trimmed));
    }
    const keyObject = createPublicKey({ key: trimmed, format: 'pem' });
    return describeAsymmetric(keyObject);
  }

  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    const secret = createSecretKey(Buffer.isBuffer(input) ? input : Buffer.from(input));
    return { keyObject: secret, asymmetricKeyType: 'oct', curve: null };
  }

  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers that bypass the declared KeyInput type.
  if (typeof input === 'object' && input !== null && 'kty' in input) {
    const jwk = input;
    if (jwk.kty === 'oct') {
      if (!jwk.k) {
        throw new JsfKeyError('JWK oct requires a k property');
      }
      const secret = createSecretKey(Buffer.from(jwk.k, 'base64url'));
      return { keyObject: secret, asymmetricKeyType: 'oct', curve: null };
    }
    const keyObject = createPublicKey({ key: jwk as unknown as Record<string, unknown>, format: 'jwk' });
    return describeAsymmetric(keyObject);
  }

  throw new JsfKeyError('Unsupported public key input');
}

/**
 * Derive the publicKey JWK to embed in a JSF signer from any accepted
 * private or public key input.
 */
export function exportPublicJwk(input: KeyInput): JwkPublicKey {
  const { keyObject, asymmetricKeyType } = toPublicKey(input);
  if (asymmetricKeyType === 'oct') {
    throw new JsfKeyError('HMAC keys must not be embedded in a JSF envelope');
  }
  const rawJwk = keyObject.export({ format: 'jwk' }) as Record<string, unknown>;
  return sanitizePublicJwk(rawJwk);
}

/**
 * Strip JWK to the fields JSF actually defines for each kty.
 * Downstream consumers can still round-trip a sanitized JWK through
 * Node because all required fields remain present.
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

function describeAsymmetric(keyObject: KeyObject): NormalizedPrivateKey {
  const asymmetricKeyType = keyObject.asymmetricKeyType;
  if (!asymmetricKeyType) {
    throw new JsfKeyError('KeyObject does not expose an asymmetric key type');
  }
  let curve: string | null = null;
  if (asymmetricKeyType === 'ec') {
    // Node exposes the named curve on the key details.
    const details = keyObject.asymmetricKeyDetails;
    const node = details?.namedCurve;
    curve = nodeCurveToJwk(node ?? null);
  } else if (asymmetricKeyType === 'ed25519') {
    curve = 'Ed25519';
  } else if (asymmetricKeyType === 'ed448') {
    curve = 'Ed448';
  }
  return { keyObject, asymmetricKeyType, curve };
}

function nodeCurveToJwk(node: string | null): string | null {
  if (!node) return null;
  switch (node) {
    case 'prime256v1':
    case 'P-256':
      return 'P-256';
    case 'secp384r1':
    case 'P-384':
      return 'P-384';
    case 'secp521r1':
    case 'P-521':
      return 'P-521';
    default:
      return node;
  }
}

function parseJwk(text: string): JwkPublicKey {
  try {
    return JSON.parse(text) as JwkPublicKey;
  } catch (err) {
    throw new JsfKeyError(`Invalid JWK JSON: ${(err as Error).message}`);
  }
}
