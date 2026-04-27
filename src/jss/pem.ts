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
