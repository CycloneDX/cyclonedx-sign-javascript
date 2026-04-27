/**
 * PEM body codec for JSS public_key fields.
 *
 * Per ITU-T X.590 clause 6.2.1, the `public_key` property "contains a
 * privacy enhanced mail (PEM) encoded public key without the header
 * and footer". The wire value is therefore the base64 of a DER-encoded
 * SubjectPublicKeyInfo (SPKI), with the BEGIN/END markers stripped
 * and any whitespace removed.
 *
 * This module wraps Node `crypto`'s key import/export so the JSS
 * binding can convert between the wire form and a usable KeyObject.
 */

import { createPublicKey, createPrivateKey, KeyObject } from 'node:crypto';
import { JssInputError, JssEnvelopeError } from '../errors.js';
import type { KeyInput } from '../types.js';

const PEM_PUBLIC_HEADER = '-----BEGIN PUBLIC KEY-----';
const PEM_PUBLIC_FOOTER = '-----END PUBLIC KEY-----';
const PEM_PRIVATE_HEADER_PKCS8 = '-----BEGIN PRIVATE KEY-----';
const PEM_PRIVATE_FOOTER_PKCS8 = '-----END PRIVATE KEY-----';

/**
 * Wrap a PEM body (just the base64 content) in PEM headers and parse
 * as a public KeyObject.
 *
 * Accepts the body with or without padding (`=`). Whitespace inside
 * the body is stripped before re-emission.
 */
export function publicKeyFromPemBody(body: string): KeyObject {
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
    return createPublicKey({ key: wrapped, format: 'pem' });
  } catch (err) {
    throw new JssEnvelopeError(`public_key body did not parse as PEM SPKI: ${(err as Error).message}`);
  }
}

/**
 * Inverse of `publicKeyFromPemBody`: export a public KeyObject as a
 * base64 string with the BEGIN/END headers stripped. Trailing `=`
 * padding is removed to match the spec's Appendix II.1 example
 * verbatim ("MCowBQYDK2VwAyEAubMon...ZkU" without trailing `=`).
 * Both forms parse correctly per `publicKeyFromPemBody`.
 */
export function pemBodyFromPublicKey(key: KeyObject): string {
  const pem = key.export({ type: 'spki', format: 'pem' });
  const text = typeof pem === 'string' ? pem : pem.toString('utf8');
  return stripPemHeaders(text).replace(/=+$/, '');
}

/**
 * Parse a PEM-formatted private key (PKCS#8) string. JSS does not
 * define an on-the-wire private-key serialization (private keys never
 * appear on the wire) so this helper is for caller-supplied PEM
 * strings and the Appendix II reference key. PEM body without headers
 * also accepted, in which case PKCS#8 wrapping is added.
 */
export function privateKeyFromPem(input: string): KeyObject {
  if (typeof input !== 'string' || input.length === 0) {
    throw new JssInputError('private key PEM must be a non-empty string');
  }
  const trimmed = input.trim();
  if (trimmed.startsWith(PEM_PRIVATE_HEADER_PKCS8) || trimmed.startsWith('-----BEGIN ')) {
    try {
      return createPrivateKey({ key: trimmed, format: 'pem' });
    } catch (err) {
      throw new JssInputError(`private key did not parse as PEM: ${(err as Error).message}`);
    }
  }
  // Treat as PKCS#8 body without headers.
  const cleaned = trimmed.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]+=*$/.test(cleaned)) {
    throw new JssInputError('private key body is not valid base64');
  }
  const pad = cleaned.length % 4 === 0 ? '' : '='.repeat(4 - (cleaned.length % 4));
  const wrapped = wrap(`${cleaned}${pad}`, PEM_PRIVATE_HEADER_PKCS8, PEM_PRIVATE_FOOTER_PKCS8);
  try {
    return createPrivateKey({ key: wrapped, format: 'pem' });
  } catch (err) {
    throw new JssInputError(`private key body did not parse as PKCS#8 PEM: ${(err as Error).message}`);
  }
}

/**
 * Normalize any accepted private-key input form into a node `KeyObject`:
 *
 *   - `KeyObject` instances pass through.
 *   - PEM strings (with headers, or PKCS#8 body without headers) parse
 *     via `privateKeyFromPem`.
 *   - `Buffer` / `Uint8Array` values are treated as raw PKCS#8 DER.
 *   - JWK objects (with a `kty` field) parse via `createPrivateKey`.
 *
 * Single source of truth for JSS sign-side key normalization; consumed
 * by `src/jss/sign.ts` and `src/jss/binding.ts`.
 */
export function toPrivateKey(input: KeyInput): KeyObject {
  if (input instanceof KeyObject) return input;
  if (typeof input === 'string') return privateKeyFromPem(input);
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    return createPrivateKey({ key: Buffer.from(input), format: 'der', type: 'pkcs8' });
  }
  if (typeof input === 'object' && 'kty' in (input as Record<string, unknown>)) {
    return createPrivateKey({ key: input as unknown as Record<string, unknown>, format: 'jwk' });
  }
  throw new JssInputError('Unsupported private key input for JSS');
}

/**
 * Normalize any accepted public-key input form into a node
 * `KeyObject`. `KeyObject` private keys are converted to their public
 * half. PEM strings with headers parse directly; bare base64 bodies
 * are routed through `publicKeyFromPemBody`. `Buffer` / `Uint8Array`
 * values are treated as DER SPKI; JWK objects (with `kty`) parse
 * directly. Single source of truth shared by `src/jss/sign.ts` and
 * `src/jss/binding.ts`.
 */
export function toPublicKey(input: KeyInput): KeyObject {
  if (input instanceof KeyObject) {
    return input.type === 'private' ? createPublicKey(input) : input;
  }
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('-----BEGIN ')) {
      return createPublicKey({ key: trimmed, format: 'pem' });
    }
    return publicKeyFromPemBody(trimmed);
  }
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    return createPublicKey({ key: Buffer.from(input), format: 'der', type: 'spki' });
  }
  if (typeof input === 'object' && 'kty' in (input as Record<string, unknown>)) {
    return createPublicKey({ key: input as unknown as Record<string, unknown>, format: 'jwk' });
  }
  throw new JssInputError('Unsupported public key input for JSS');
}

function wrap(body: string, header: string, footer: string): string {
  // Re-emit the body with 64-character lines, matching the canonical
  // PEM layout. Node's PEM parser is lenient about line length but a
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
