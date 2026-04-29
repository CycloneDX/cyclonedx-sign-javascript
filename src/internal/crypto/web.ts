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
 * Web `crypto.subtle` backend.
 *
 * Selected automatically when the package is consumed via a bundler
 * targeting a browser, Deno, Cloudflare Workers, or any other runtime
 * that exposes the standard `crypto.subtle` API. Routes:
 *
 *   - JSF (message-mode) RSA / ECDSA / EdDSA / HMAC through
 *     `crypto.subtle.sign` / `verify`. Ed25519 uses native Subtle in
 *     modern browsers (Chrome 113+, Firefox 130+, Safari 17+); Ed448
 *     has no Subtle support anywhere and routes through
 *     `@noble/curves`.
 *   - JSS (pre-hashed) RSA through pure-JS BigInt modular
 *     exponentiation. WebCrypto exposes no raw RSA primitive, so the
 *     EMSA-PSS / DigestInfo encoding plus modPow-against-the-private-
 *     params is the only viable path.
 *   - JSS (pre-hashed) ECDSA through `@noble/curves`. Subtle's ECDSA
 *     always re-hashes its input.
 *
 * Key import accepts JWK, PEM (PKCS#8 or SPKI), or raw bytes (HMAC).
 * PKCS#1 and SEC1 PEM forms are not supported on this backend; users
 * should convert to PKCS#8 (`openssl pkcs8 -topk8 ...`) or supply a
 * JWK.
 */

import { p256, p384, p521 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';

// Type-only imports — erased at compile time so the web bundle has no
// runtime dependency on node:crypto. The `webcrypto` namespace in
// @types/node mirrors the global Web Crypto API surface, so these
// names line up structurally with `globalThis.crypto.subtle`.
import type { webcrypto as wc } from 'node:crypto';
type Crypto = wc.Crypto;
type SubtleCrypto = wc.SubtleCrypto;
type CryptoKey = wc.CryptoKey;
type JsonWebKey = wc.JsonWebKey;
type KeyUsage = wc.KeyUsage;
type AlgorithmIdentifier = wc.AlgorithmIdentifier;
type RsaHashedImportParams = wc.RsaHashedImportParams;
type EcKeyImportParams = wc.EcKeyImportParams;
type HmacImportParams = wc.HmacImportParams;

import type { JwkPublicKey, KeyInput } from '../../types.js';
import {
  buildDigestInfo,
  constantTimeEqual,
  hashLength,
  pkcs1V15Pad,
  pkcs1V15Unpad,
  pssEncode,
  pssVerify,
} from './shared.js';
import {
  bytesToBigInt,
  decodeJwkBigInt,
  modulusBits as bigintModulusBits,
  rsaPrivate,
  rsaPublic,
} from './bigint-rsa.js';
import type {
  CryptoBackend,
  EcCurve,
  EdCurve,
  KeyKind,
  PrivateKeyHandle,
  PublicKeyHandle,
  Sha,
  SymmetricKeyHandle,
  VerifyResult,
} from './types.js';

// -- Subtle helpers ----------------------------------------------------------

const SUBTLE_HASH_NAMES: Record<Sha, string> = {
  'sha-256': 'SHA-256',
  'sha-384': 'SHA-384',
  'sha-512': 'SHA-512',
};
function subtleHashName(hash: Sha): string {
  // eslint-disable-next-line security/detect-object-injection -- `hash` narrowed to Sha.
  return SUBTLE_HASH_NAMES[hash];
}

const SUBTLE_CURVE_NAMES: Record<EcCurve, string> = {
  'P-256': 'P-256',
  'P-384': 'P-384',
  'P-521': 'P-521',
};

const NOBLE_CURVES: Record<EcCurve, typeof p256> = {
  'P-256': p256,
  'P-384': p384,
  'P-521': p521,
};
const NOBLE_FIELD_BYTES: Record<EcCurve, number> = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
};

function getSubtle(): SubtleCrypto {
  // globalThis.crypto.subtle is the standard surface across browsers,
  // Node 20+, Deno, and modern Workers runtimes.
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || !c.subtle) {
    throw new Error('Web crypto backend selected but globalThis.crypto.subtle is unavailable');
  }
  return c.subtle;
}

function getRandom(): (b: Uint8Array) => Uint8Array {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error('Web crypto backend selected but globalThis.crypto.getRandomValues is unavailable');
  }
  return (b) => c.getRandomValues(b);
}

// -- Key handle classes ------------------------------------------------------

/**
 * Internal: per-algorithm CryptoKey cache so repeated sign/verify
 * calls on the same logical key reuse one Subtle import.
 */
type SubtleAlgo = AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams;

class WebPublicKey implements PublicKeyHandle {
  readonly kind: KeyKind;
  readonly curve: EcCurve | EdCurve | null;
  readonly rsaModulusBits: number | null;
  /** @internal */ readonly jwk: JwkPublicKey;
  /** @internal */ readonly cache = new Map<string, CryptoKey>();

  constructor(jwk: JwkPublicKey) {
    this.jwk = jwk;
    const meta = describeJwk(jwk);
    this.kind = meta.kind;
    this.curve = meta.curve;
    this.rsaModulusBits = meta.rsaModulusBits;
  }

  async exportJwk(): Promise<JwkPublicKey> {
    return sanitizePublicJwk(this.jwk);
  }

  async exportSpkiPem(): Promise<string> {
    if (this.kind === 'oct') throw new Error('Cannot export symmetric key as SPKI PEM');
    // Ed25519 / Ed448 may not be importable via Subtle on the runtime,
    // and Ed448 never is. Build the SPKI manually from the JWK's
    // public point in those cases.
    if (this.kind === 'ed25519' || this.kind === 'ed448') {
      return wrapPem(buildEdwardsSpki(this.kind, b64uToBytes(String(this.jwk.x))), 'PUBLIC KEY');
    }
    const subtleAlgo = subtleAlgoForExport(this.kind, this.curve);
    const key = await getSubtle().importKey('jwk', this.jwk as unknown as JsonWebKey, subtleAlgo, true, []);
    const der = await getSubtle().exportKey('spki', key);
    return wrapPem(new Uint8Array(der), 'PUBLIC KEY');
  }

  /** @internal */
  async getCryptoKey(algo: SubtleAlgo, usages: KeyUsage[]): Promise<CryptoKey> {
    const cacheKey = JSON.stringify(algo) + '|' + usages.join(',');
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;
    const k = await getSubtle().importKey('jwk', this.jwk as unknown as JsonWebKey, algo, false, usages);
    this.cache.set(cacheKey, k);
    return k;
  }
}

class WebPrivateKey implements PrivateKeyHandle {
  readonly kind: KeyKind;
  readonly curve: EcCurve | EdCurve | null;
  readonly rsaModulusBits: number | null;
  /** @internal */ readonly jwk: JwkPublicKey;     // includes private params
  /** @internal */ readonly cache = new Map<string, CryptoKey>();

  constructor(jwk: JwkPublicKey) {
    this.jwk = jwk;
    const meta = describeJwk(jwk);
    this.kind = meta.kind;
    this.curve = meta.curve;
    this.rsaModulusBits = meta.rsaModulusBits;
  }

  async publicHandle(): Promise<PublicKeyHandle> {
    return new WebPublicKey(sanitizePublicJwk(this.jwk));
  }

  async exportPublicJwk(): Promise<JwkPublicKey> {
    return sanitizePublicJwk(this.jwk);
  }

  /** @internal */
  async getCryptoKey(algo: SubtleAlgo, usages: KeyUsage[]): Promise<CryptoKey> {
    const cacheKey = JSON.stringify(algo) + '|' + usages.join(',');
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;
    const k = await getSubtle().importKey('jwk', this.jwk as unknown as JsonWebKey, algo, false, usages);
    this.cache.set(cacheKey, k);
    return k;
  }
}

class WebSymmetricKey implements SymmetricKeyHandle {
  readonly kind: 'oct' = 'oct' as const;
  readonly curve = null;
  readonly rsaModulusBits = null;
  /** @internal */ readonly bytes: Uint8Array;
  /** @internal */ readonly cache = new Map<string, CryptoKey>();

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /** @internal */
  async getHmacKey(hash: Sha, usages: KeyUsage[]): Promise<CryptoKey> {
    const cacheKey = hash + '|' + usages.join(',');
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;
    const k = await getSubtle().importKey(
      'raw',
      this.bytes,
      { name: 'HMAC', hash: subtleHashName(hash) },
      false,
      usages,
    );
    this.cache.set(cacheKey, k);
    return k;
  }
}

function describeJwk(jwk: JwkPublicKey): {
  kind: KeyKind;
  curve: EcCurve | EdCurve | null;
  rsaModulusBits: number | null;
} {
  if (jwk.kty === 'RSA') {
    if (!jwk.n) throw new Error('RSA JWK missing n');
    const n = decodeJwkBigInt(jwk.n);
    return { kind: 'rsa', curve: null, rsaModulusBits: bigintModulusBits(n) };
  }
  if (jwk.kty === 'EC') {
    const crv = (jwk.crv ?? '') as EcCurve;
    if (crv !== 'P-256' && crv !== 'P-384' && crv !== 'P-521') {
      throw new Error(`Unsupported EC curve: ${String(jwk.crv)}`);
    }
    return { kind: 'ec', curve: crv, rsaModulusBits: null };
  }
  if (jwk.kty === 'OKP') {
    if (jwk.crv === 'Ed25519') return { kind: 'ed25519', curve: 'Ed25519', rsaModulusBits: null };
    if (jwk.crv === 'Ed448') return { kind: 'ed448', curve: 'Ed448', rsaModulusBits: null };
    throw new Error(`Unsupported OKP curve: ${String(jwk.crv)}`);
  }
  if (jwk.kty === 'oct') {
    return { kind: 'oct', curve: null, rsaModulusBits: null };
  }
  throw new Error(`Unsupported JWK kty: ${String(jwk.kty)}`);
}

function sanitizePublicJwk(raw: JwkPublicKey): JwkPublicKey {
  // Strip private and metadata fields, leaving only the wire shape.
  if (raw.kty === 'RSA') return { kty: 'RSA', n: String(raw.n), e: String(raw.e) };
  if (raw.kty === 'EC') return { kty: 'EC', crv: String(raw.crv), x: String(raw.x), y: String(raw.y) };
  if (raw.kty === 'OKP') return { kty: 'OKP', crv: String(raw.crv), x: String(raw.x) };
  if (raw.kty === 'oct') return { kty: 'oct', k: String(raw.k) };
  throw new Error(`Unsupported JWK kty: ${String(raw.kty)}`);
}

function subtleAlgoForExport(kind: KeyKind, curve: EcCurve | EdCurve | null): SubtleAlgo {
  // Used only to produce a CryptoKey we can then exportKey('spki') on.
  // The hash is irrelevant for SPKI export so we pick a stable default.
  if (kind === 'rsa') return { name: 'RSA-PSS', hash: 'SHA-256' };
  if (kind === 'ec') return { name: 'ECDSA', namedCurve: SUBTLE_CURVE_NAMES[(curve as EcCurve)] };
  if (kind === 'ed25519') return { name: 'Ed25519' } as AlgorithmIdentifier;
  if (kind === 'ed448') throw new Error('Ed448 has no Subtle support; cannot export via Subtle');
  throw new Error(`No Subtle algorithm mapping for ${kind}`);
}

// -- PEM / DER helpers -------------------------------------------------------

const PEM_HEADER_RE = /-----BEGIN ([^-]+)-----/;

function parsePem(pem: string): { label: string; der: Uint8Array } {
  const m = PEM_HEADER_RE.exec(pem);
  if (!m) throw new Error('Not a PEM-encoded value');
  const label = m[1]!;
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
  const padded = body + '='.repeat((4 - (body.length % 4)) % 4);
  const binary = atob(padded);
  const der = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    der[i] = binary.charCodeAt(i);
  }
  return { label, der };
}

function wrapPem(der: Uint8Array, label: string): string {
  let binary = '';
  for (let i = 0; i < der.length; i += 1) binary += String.fromCharCode(der[i]!);
  const b64 = btoa(binary);
  const lines = [`-----BEGIN ${label}-----`];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  lines.push(`-----END ${label}-----`);
  lines.push('');
  return lines.join('\n');
}

/**
 * Detect the algorithm of an SPKI or PKCS#8 DER blob by walking just
 * far enough into the SEQUENCE to find the algorithm OID. Returns one
 * of `'rsa'`, `'ec'`, `'ed25519'`, `'ed448'`, plus the named curve OID
 * for EC keys.
 */
function detectDerAlgorithm(der: Uint8Array, isPrivate: boolean): {
  kind: KeyKind;
  curve: EcCurve | EdCurve | null;
} {
  // Both SPKI and PKCS#8 start with SEQUENCE { ... }. PKCS#8 has a
  // version INTEGER 0 first, then the AlgorithmIdentifier SEQUENCE.
  // SPKI starts with the AlgorithmIdentifier SEQUENCE directly.
  let p = 0;
  if (der[p] !== 0x30) throw new Error('DER: expected outer SEQUENCE');
  p += 1;
  p = skipDerLength(der, p);
  if (isPrivate) {
    if (der[p] !== 0x02) throw new Error('PKCS#8: expected version INTEGER');
    p += 1;
    const verLen = der[p]!;
    p += 1 + verLen;
  }
  if (der[p] !== 0x30) throw new Error('DER: expected AlgorithmIdentifier SEQUENCE');
  p += 1;
  p = skipDerLength(der, p);
  // Now we're at the algorithm OID.
  if (der[p] !== 0x06) throw new Error('DER: expected algorithm OID');
  p += 1;
  const oidLen = der[p]!;
  p += 1;
  const oid = der.subarray(p, p + oidLen);
  p += oidLen;
  // RSA: 1.2.840.113549.1.1.1 (PKCS#1 rsaEncryption) — DER: 2A864886F70D010101
  // RSA-PSS: 1.2.840.113549.1.1.10 — DER: 2A864886F70D01010A
  // EC: 1.2.840.10045.2.1 — DER: 2A8648CE3D0201
  // Ed25519: 1.3.101.112 — DER: 2B6570
  // Ed448: 1.3.101.113 — DER: 2B6571
  if (oidEquals(oid, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) ||
      oidEquals(oid, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a])) {
    return { kind: 'rsa', curve: null };
  }
  if (oidEquals(oid, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])) {
    // EC: parameters may be a named curve OID (0x06) or an explicit
    // ECParameters SEQUENCE (0x30). When explicit, signal the caller
    // (importEcPublicFromSpki) to derive the curve from the public
    // point byte length instead.
    if (der[p] === 0x30) {
      return { kind: 'ec', curve: null };
    }
    if (der[p] !== 0x06) throw new Error('DER: EC missing curve OID');
    p += 1;
    const curveLen = der[p]!;
    p += 1;
    const curveOid = der.subarray(p, p + curveLen);
    // P-256: 1.2.840.10045.3.1.7 — DER: 2A8648CE3D030107
    // P-384: 1.3.132.0.34 — DER: 2B81040022
    // P-521: 1.3.132.0.35 — DER: 2B81040023
    if (oidEquals(curveOid, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])) return { kind: 'ec', curve: 'P-256' };
    if (oidEquals(curveOid, [0x2b, 0x81, 0x04, 0x00, 0x22])) return { kind: 'ec', curve: 'P-384' };
    if (oidEquals(curveOid, [0x2b, 0x81, 0x04, 0x00, 0x23])) return { kind: 'ec', curve: 'P-521' };
    throw new Error('Unsupported EC curve OID');
  }
  if (oidEquals(oid, [0x2b, 0x65, 0x70])) return { kind: 'ed25519', curve: 'Ed25519' };
  if (oidEquals(oid, [0x2b, 0x65, 0x71])) return { kind: 'ed448', curve: 'Ed448' };
  throw new Error('Unsupported key algorithm OID');
}

function skipDerLength(der: Uint8Array, p: number): number {
  const first = der[p]!;
  if (first < 0x80) return p + 1;
  const numLen = first & 0x7f;
  return p + 1 + numLen;
}

function oidEquals(a: Uint8Array, b: number[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop bounded by length.
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// -- Key import dispatchers --------------------------------------------------

async function importJwkPrivateAsHandle(jwk: JwkPublicKey): Promise<PrivateKeyHandle> {
  if (jwk.kty === 'oct') {
    throw new Error('Use importHmacKey for symmetric material');
  }
  return new WebPrivateKey(jwk);
}

async function importJwkPublicAsHandle(jwk: JwkPublicKey): Promise<PublicKeyHandle> {
  if (jwk.kty === 'oct') {
    throw new Error('oct keys are symmetric, not public');
  }
  return new WebPublicKey(jwk);
}

async function importPemPrivate(pem: string): Promise<PrivateKeyHandle> {
  const { label, der } = parsePem(pem);
  if (label !== 'PRIVATE KEY') {
    throw new Error(
      `Web backend only accepts PKCS#8 private keys (-----BEGIN PRIVATE KEY-----); got "${label}". ` +
        'Convert with: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pkcs8.pem',
    );
  }
  const algo = detectDerAlgorithm(der, true);
  // Ed448 has no Subtle support anywhere, so handle it before asking
  // for a Subtle algorithm identifier.
  if (algo.kind === 'ed448') {
    return importEd448PrivateFromPkcs8(der);
  }
  // EC PKCS#8 with explicit parameters (curve === null) cannot be
  // imported via Subtle when given a namedCurve algorithm; walk the
  // ECPrivateKey wrapper to extract the scalar and public point and
  // build a clean JWK that Subtle accepts.
  if (algo.kind === 'ec' && algo.curve === null) {
    return importEcPrivateFromExplicitPkcs8(der);
  }
  const subtleAlgo = subtleImportAlgo(algo.kind, algo.curve);
  const usages: KeyUsage[] = ['sign'];
  const ck = await getSubtle().importKey('pkcs8', der, subtleAlgo, true, usages);
  const jwk = await getSubtle().exportKey('jwk', ck) as unknown as JwkPublicKey;
  return new WebPrivateKey(jwk);
}

/**
 * Walk a PKCS#8 wrapper whose AlgorithmIdentifier carries explicit EC
 * parameters and recover a clean JWK with `crv`, `d`, `x`, `y`. The
 * inner privateKey OCTET STRING contains an ECPrivateKey:
 *
 *   ECPrivateKey ::= SEQUENCE {
 *     version INTEGER,
 *     privateKey OCTET STRING,
 *     parameters [0] EXPLICIT ECParameters OPTIONAL,
 *     publicKey  [1] EXPLICIT BIT STRING OPTIONAL
 *   }
 *
 * The curve is inferred from the public-key BIT STRING's byte length
 * (same heuristic as importEcPublicFromSpki).
 */
function importEcPrivateFromExplicitPkcs8(der: Uint8Array): PrivateKeyHandle {
  const ecPrivate = unwrapPkcs8PrivateKey(der);
  const { dBytes, point } = parseEcPrivateKey(ecPrivate);
  return new WebPrivateKey(buildEcPrivateJwk(dBytes, point));
}

/** Walk a PKCS#8 wrapper and return the inner privateKey OCTET STRING bytes. */
function unwrapPkcs8PrivateKey(der: Uint8Array): Uint8Array {
  const top = readSeq(der, 0);
  let p = top.body;
  if (der[p] !== 0x02) throw new Error('PKCS#8: expected version INTEGER');
  const ver = readDerLength(der, p + 1);
  p = ver.contentStart + ver.length;
  if (der[p] !== 0x30) throw new Error('PKCS#8: expected AlgorithmIdentifier');
  const alg = readDerLength(der, p + 1);
  p = alg.contentStart + alg.length;
  if (der[p] !== 0x04) throw new Error('PKCS#8: expected privateKey OCTET STRING');
  const inner = readDerLength(der, p + 1);
  return der.subarray(inner.contentStart, inner.contentStart + inner.length);
}

/** Parse an ECPrivateKey SEQUENCE and return the scalar plus the embedded public point. */
function parseEcPrivateKey(ecPrivate: Uint8Array): { dBytes: Uint8Array; point: Uint8Array } {
  const top = readSeq(ecPrivate, 0);
  let q = top.body;
  if (ecPrivate[q] !== 0x02) throw new Error('ECPrivateKey: expected version INTEGER');
  const ver = readDerLength(ecPrivate, q + 1);
  q = ver.contentStart + ver.length;
  if (ecPrivate[q] !== 0x04) throw new Error('ECPrivateKey: expected privateKey OCTET STRING');
  const dLen = readDerLength(ecPrivate, q + 1);
  const dBytes = ecPrivate.subarray(dLen.contentStart, dLen.contentStart + dLen.length);
  q = dLen.contentStart + dLen.length;

  // Walk optional [0] parameters and the [1] EXPLICIT publicKey BIT STRING.
  while (q < top.end) {
    const tag = ecPrivate[q]!;
    const lenInfo = readDerLength(ecPrivate, q + 1);
    if (tag === 0xa1) {
      return { dBytes, point: extractEcPointFromTagged(ecPrivate, lenInfo.contentStart) };
    }
    q = lenInfo.contentStart + lenInfo.length;
  }
  throw new Error('ECPrivateKey: missing publicKey field — cannot recover x, y');
}

/** Extract the uncompressed EC point from a `[1] EXPLICIT BIT STRING` content area. */
function extractEcPointFromTagged(buf: Uint8Array, taggedContentStart: number): Uint8Array {
  if (buf[taggedContentStart] !== 0x03) {
    throw new Error('ECPrivateKey: expected publicKey BIT STRING');
  }
  const bitLen = readDerLength(buf, taggedContentStart + 1);
  // First byte after the length is the unused-bits count (always 0).
  const point = buf.subarray(bitLen.contentStart + 1, bitLen.contentStart + bitLen.length);
  if (point[0] !== 0x04) {
    throw new Error('ECPrivateKey: only uncompressed points are supported');
  }
  return point;
}

const EC_FIELD_TO_CURVE: Record<number, EcCurve> = {
  32: 'P-256',
  48: 'P-384',
  66: 'P-521',
};

/** Map the EC point's coordinate length to its named curve. */
function curveFromFieldBytes(fieldBytes: number): EcCurve {
  // eslint-disable-next-line security/detect-object-injection -- fieldBytes is a derived integer; the table is a closed set of allowed widths.
  const curve = EC_FIELD_TO_CURVE[fieldBytes];
  if (!curve) throw new Error(`EC SPKI: unrecognized field size ${fieldBytes}`);
  return curve;
}

/** Build a private EC JWK (with `d`) from a private scalar plus the uncompressed public point. */
function buildEcPrivateJwk(dBytes: Uint8Array, point: Uint8Array): JwkPublicKey {
  const fieldBytes = (point.length - 1) / 2;
  const curve = curveFromFieldBytes(fieldBytes);
  const x = point.subarray(1, 1 + fieldBytes);
  const y = point.subarray(1 + fieldBytes);
  const dPadded = padLeftToLength(dBytes, fieldBytes);
  return {
    kty: 'EC',
    crv: curve,
    x: bytesToB64u(x),
    y: bytesToB64u(y),
    d: bytesToB64u(dPadded),
  };
}

/** Left-pad a byte string with zeros to reach the requested width. No-op if already wide enough. */
function padLeftToLength(bytes: Uint8Array, width: number): Uint8Array {
  if (bytes.length === width) return bytes;
  const out = new Uint8Array(width);
  out.set(bytes, width - bytes.length);
  return out;
}

async function importPemPublic(pem: string): Promise<PublicKeyHandle> {
  const { label, der } = parsePem(pem);
  if (label !== 'PUBLIC KEY') {
    throw new Error(
      `Web backend only accepts SPKI public keys (-----BEGIN PUBLIC KEY-----); got "${label}".`,
    );
  }
  const algo = detectDerAlgorithm(der, false);
  // Ed448 has no Subtle support; bypass importKey entirely.
  if (algo.kind === 'ed448') {
    return importEd448PublicFromSpki(der);
  }
  // EC SPKIs may carry explicit curve parameters (dotnet-jss emits
  // these by default). Subtle rejects explicit params when given a
  // namedCurve algorithm, so for EC we always extract the public
  // point and reconstruct a clean JWK that Subtle accepts.
  if (algo.kind === 'ec') {
    return importEcPublicFromSpki(der, algo.curve as EcCurve);
  }
  const subtleAlgo = subtleImportAlgo(algo.kind, algo.curve);
  const usages: KeyUsage[] = ['verify'];
  const ck = await getSubtle().importKey('spki', der, subtleAlgo, true, usages);
  const jwk = await getSubtle().exportKey('jwk', ck) as unknown as JwkPublicKey;
  return new WebPublicKey(jwk);
}

function subtleImportAlgo(kind: KeyKind, curve: EcCurve | EdCurve | null): SubtleAlgo {
  if (kind === 'rsa') return { name: 'RSA-PSS', hash: 'SHA-256' };
  if (kind === 'ec') return { name: 'ECDSA', namedCurve: SUBTLE_CURVE_NAMES[(curve as EcCurve)] };
  if (kind === 'ed25519') return { name: 'Ed25519' } as AlgorithmIdentifier;
  throw new Error(`No Subtle algorithm for kind=${kind}`);
}

/**
 * Ed448 fallback: WebCrypto has no Ed448 support, so we walk the PKCS#8
 * structure to extract the 57-byte private seed and synthesize a JWK.
 */
function importEd448PrivateFromPkcs8(der: Uint8Array): PrivateKeyHandle {
  // PKCS#8 OneAsymmetricKey ::= SEQUENCE {
  //   version Version, privateKeyAlgorithm AlgorithmIdentifier,
  //   privateKey OCTET STRING (containing CurvePrivateKey ::= OCTET STRING),
  //   ... }
  // The Ed448 private key is 57 bytes nested inside two OCTET STRING wrappers.
  const seed = extractInnermostOctetString(der);
  if (seed.length !== 57) {
    throw new Error(`Ed448 private key seed: expected 57 bytes, got ${seed.length}`);
  }
  const pubBytes = ed448.getPublicKey(seed);
  const jwk: JwkPublicKey = {
    kty: 'OKP',
    crv: 'Ed448',
    x: bytesToB64u(pubBytes),
    d: bytesToB64u(seed),
  };
  return new WebPrivateKey(jwk);
}

/**
 * Extract an EC public point from any SPKI form (named curve OR
 * explicit parameters) and produce a JWK directly. The curve is
 * inferred from the byte length of the encoded point, since each NIST
 * curve has a unique field size:
 *
 *   - P-256: 1 + 32 + 32 = 65 bytes
 *   - P-384: 1 + 48 + 48 = 97 bytes
 *   - P-521: 1 + 66 + 66 = 133 bytes
 *
 * `expectedCurve` may be `null` when the SPKI used explicit
 * parameters and the caller deferred curve identification to here.
 */
function importEcPublicFromSpki(der: Uint8Array, expectedCurve: EcCurve | null): PublicKeyHandle {
  const point = extractFirstBitString(der);
  if (point.length === 0 || point[0] !== 0x04) {
    throw new Error('EC SPKI: only uncompressed public points are supported');
  }
  const fieldBytes = (point.length - 1) / 2;
  let curve: EcCurve;
  if (fieldBytes === 32) curve = 'P-256';
  else if (fieldBytes === 48) curve = 'P-384';
  else if (fieldBytes === 66) curve = 'P-521';
  else throw new Error(`EC SPKI: unrecognized field size ${fieldBytes}`);
  if (expectedCurve !== null && expectedCurve !== curve) {
    throw new Error(`EC SPKI curve mismatch: expected ${expectedCurve}, derived ${curve}`);
  }
  const x = point.subarray(1, 1 + fieldBytes);
  const y = point.subarray(1 + fieldBytes);
  const jwk: JwkPublicKey = {
    kty: 'EC',
    crv: curve,
    x: bytesToB64u(x),
    y: bytesToB64u(y),
  };
  return new WebPublicKey(jwk);
}

/**
 * Build a minimal SPKI DER for an Edwards-curve public key. The OID
 * differs by curve (Ed25519 = 1.3.101.112, Ed448 = 1.3.101.113); the
 * BIT STRING wrapper carries the raw public point.
 */
function buildEdwardsSpki(kind: 'ed25519' | 'ed448', pubBytes: Uint8Array): Uint8Array {
  // SubjectPublicKeyInfo ::= SEQUENCE {
  //   AlgorithmIdentifier ::= SEQUENCE { OID }
  //   subjectPublicKey BIT STRING
  // }
  const oid = kind === 'ed25519'
    ? new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x70])
    : new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x71]);
  const algIdSeq = derSequence(oid);
  // BIT STRING with 0x00 unused-bits prefix.
  const bitString = new Uint8Array(1 + pubBytes.length);
  bitString[0] = 0x00;
  bitString.set(pubBytes, 1);
  const bitStringTagged = derTag(0x03, bitString);
  return derSequence(concat(algIdSeq, bitStringTagged));
}

function derTag(tag: number, content: Uint8Array): Uint8Array {
  const lenBytes = derLength(content.length);
  const out = new Uint8Array(1 + lenBytes.length + content.length);
  out[0] = tag;
  out.set(lenBytes, 1);
  out.set(content, 1 + lenBytes.length);
  return out;
}

function derSequence(content: Uint8Array): Uint8Array {
  return derTag(0x30, content);
}

function derLength(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  if (n < 0x100) return new Uint8Array([0x81, n]);
  if (n < 0x10000) return new Uint8Array([0x82, (n >> 8) & 0xff, n & 0xff]);
  throw new Error('DER length too large');
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function importEd448PublicFromSpki(der: Uint8Array): PublicKeyHandle {
  // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING (publicKey) }
  // After the algorithm OID, find the BIT STRING and strip its leading
  // 0x00 unused-bits byte.
  const bs = extractFirstBitString(der);
  if (bs.length !== 57) {
    throw new Error(`Ed448 public key: expected 57 bytes, got ${bs.length}`);
  }
  const jwk: JwkPublicKey = {
    kty: 'OKP',
    crv: 'Ed448',
    x: bytesToB64u(bs),
  };
  return new WebPublicKey(jwk);
}

/** Find the deepest OCTET STRING and return its contents. */
function extractInnermostOctetString(der: Uint8Array): Uint8Array {
  let i = 0;
  let last: Uint8Array | null = null;
  // Walk top-level SEQUENCE children.
  const top = readSeq(der, 0);
  let p = top.body;
  while (p < top.end) {
    const tag = der[p]!;
    p += 1;
    const len = readDerLength(der, p);
    p = len.contentStart;
    const content = der.subarray(p, p + len.length);
    if (tag === 0x04) {
      // OCTET STRING — Ed448 PKCS#8 nests another OCTET STRING here.
      if (content[0] === 0x04) {
        const inner = readDerLength(content, 1);
        last = content.subarray(inner.contentStart, inner.contentStart + inner.length);
      } else {
        last = content;
      }
    }
    p += len.length;
  }
  if (!last) throw new Error('DER: no OCTET STRING found');
  return last;
}

/** Find the first BIT STRING and return its contents (without unused-bits byte). */
function extractFirstBitString(der: Uint8Array): Uint8Array {
  const top = readSeq(der, 0);
  let p = top.body;
  while (p < top.end) {
    const tag = der[p]!;
    p += 1;
    const len = readDerLength(der, p);
    p = len.contentStart;
    if (tag === 0x03) {
      // BIT STRING: first byte is unused-bits count (always 0 here).
      return der.subarray(p + 1, p + len.length);
    }
    p += len.length;
  }
  throw new Error('DER: no BIT STRING found');
}

function readSeq(der: Uint8Array, offset: number): { body: number; end: number } {
  if (der[offset] !== 0x30) throw new Error('DER: expected SEQUENCE');
  const len = readDerLength(der, offset + 1);
  return { body: len.contentStart, end: len.contentStart + len.length };
}

function readDerLength(der: Uint8Array, p: number): { contentStart: number; length: number } {
  const first = der[p]!;
  if (first < 0x80) return { contentStart: p + 1, length: first };
  const numLen = first & 0x7f;
  let length = 0;
  for (let i = 0; i < numLen; i += 1) {
    length = (length << 8) | der[p + 1 + i]!;
  }
  return { contentStart: p + 1 + numLen, length };
}

function bytesToB64u(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uToBytes(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function isJwkInput(input: unknown): input is JwkPublicKey {
  return typeof input === 'object' && input !== null && 'kty' in input;
}

// -- The backend implementation ----------------------------------------------

const digest = async (hash: Sha, data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await getSubtle().digest(subtleHashName(hash), data));

const randomBytes = (n: number): Uint8Array => {
  const out = new Uint8Array(n);
  return getRandom()(out);
};

export const backend: CryptoBackend = {
  id: 'web',

  digest,
  randomBytes,

  async importPrivateKey(input: KeyInput): Promise<PrivateKeyHandle> {
    if (typeof input === 'string') {
      const trimmed = input.trim();
      if (trimmed.startsWith('{')) {
        return importJwkPrivateAsHandle(JSON.parse(trimmed) as JwkPublicKey);
      }
      return importPemPrivate(trimmed);
    }
    if (input instanceof Uint8Array) {
      // Raw bytes: treat as HMAC material; importPrivateKey is the
      // wrong door for asymmetric DER (use PEM or JWK).
      throw new Error('Raw byte input is for HMAC; pass a JWK or PEM for asymmetric keys');
    }
    if (isJwkInput(input)) {
      return importJwkPrivateAsHandle(input);
    }
    // Reject CryptoKey directly (callers must pre-import via Subtle and export to JWK).
    throw new Error('Unsupported private key input on web backend');
  },

  async importPublicKey(input: KeyInput): Promise<PublicKeyHandle> {
    if (typeof input === 'string') {
      const trimmed = input.trim();
      if (trimmed.startsWith('{')) {
        return importJwkPublicAsHandle(JSON.parse(trimmed) as JwkPublicKey);
      }
      return importPemPublic(trimmed);
    }
    if (input instanceof Uint8Array) {
      throw new Error('Raw byte input is for HMAC; pass a JWK or PEM for asymmetric keys');
    }
    if (isJwkInput(input)) {
      return importJwkPublicAsHandle(input);
    }
    throw new Error('Unsupported public key input on web backend');
  },

  async importHmacKey(input: KeyInput, _hash: Sha): Promise<SymmetricKeyHandle> {
    if (input instanceof Uint8Array) return new WebSymmetricKey(input);
    if (isJwkInput(input) && input.kty === 'oct') {
      if (!input.k) throw new Error('JWK oct missing k');
      return new WebSymmetricKey(b64uToBytes(input.k));
    }
    throw new Error('HMAC import requires raw bytes or JWK oct');
  },

  async parseCertSpkiPublicKey(certDer: Uint8Array): Promise<PublicKeyHandle> {
    // X.509: TBSCertificate.subjectPublicKeyInfo. Walk to it.
    const spki = extractSpkiFromX509(certDer);
    return importPemPublic(wrapPem(spki, 'PUBLIC KEY'));
  },

  // -- JSF (message-mode) ----------------------------------------------------

  async signRsaPkcs1(hash, message, key) {
    const ck = await (key as WebPrivateKey).getCryptoKey(
      { name: 'RSASSA-PKCS1-v1_5', hash: subtleHashName(hash) }, ['sign']);
    return new Uint8Array(await getSubtle().sign({ name: 'RSASSA-PKCS1-v1_5' }, ck, message));
  },
  async verifyRsaPkcs1(hash, message, signature, key) {
    const ck = await (key as WebPublicKey).getCryptoKey(
      { name: 'RSASSA-PKCS1-v1_5', hash: subtleHashName(hash) }, ['verify']);
    return getSubtle().verify({ name: 'RSASSA-PKCS1-v1_5' }, ck, signature, message);
  },

  async signRsaPss(hash, message, saltLength, key) {
    const ck = await (key as WebPrivateKey).getCryptoKey(
      { name: 'RSA-PSS', hash: subtleHashName(hash) }, ['sign']);
    return new Uint8Array(await getSubtle().sign({ name: 'RSA-PSS', saltLength }, ck, message));
  },
  async verifyRsaPss(hash, message, saltLength, signature, key) {
    const ck = await (key as WebPublicKey).getCryptoKey(
      { name: 'RSA-PSS', hash: subtleHashName(hash) }, ['verify']);
    return getSubtle().verify({ name: 'RSA-PSS', saltLength }, ck, signature, message);
  },

  async signEcdsa(hash, message, key) {
    const wp = key as WebPrivateKey;
    const ck = await wp.getCryptoKey(
      { name: 'ECDSA', namedCurve: SUBTLE_CURVE_NAMES[(wp.curve as EcCurve)] }, ['sign']);
    // Subtle returns IEEE P-1363 by default for ECDSA.
    return new Uint8Array(await getSubtle().sign({ name: 'ECDSA', hash: subtleHashName(hash) }, ck, message));
  },
  async verifyEcdsa(hash, message, signature, key) {
    const wp = key as WebPublicKey;
    const ck = await wp.getCryptoKey(
      { name: 'ECDSA', namedCurve: SUBTLE_CURVE_NAMES[(wp.curve as EcCurve)] }, ['verify']);
    return getSubtle().verify({ name: 'ECDSA', hash: subtleHashName(hash) }, ck, signature, message);
  },

  async signEddsa(message, key) {
    const wp = key as WebPrivateKey;
    if (wp.kind === 'ed448') {
      const seed = b64uToBytes(String(wp.jwk.d));
      return new Uint8Array(ed448.sign(message, seed));
    }
    // Ed25519: prefer Subtle when available; fall back to noble.
    try {
      const ck = await wp.getCryptoKey({ name: 'Ed25519' } as AlgorithmIdentifier, ['sign']);
      return new Uint8Array(await getSubtle().sign({ name: 'Ed25519' } as AlgorithmIdentifier, ck, message));
    } catch {
      const seed = b64uToBytes(String(wp.jwk.d));
      return new Uint8Array(ed25519.sign(message, seed));
    }
  },
  async verifyEddsa(message, signature, key) {
    const wp = key as WebPublicKey;
    if (wp.kind === 'ed448') {
      const x = b64uToBytes(String(wp.jwk.x));
      try { return ed448.verify(signature, message, x); } catch { return false; }
    }
    try {
      const ck = await wp.getCryptoKey({ name: 'Ed25519' } as AlgorithmIdentifier, ['verify']);
      return getSubtle().verify({ name: 'Ed25519' } as AlgorithmIdentifier, ck, signature, message);
    } catch {
      const x = b64uToBytes(String(wp.jwk.x));
      try { return ed25519.verify(signature, message, x); } catch { return false; }
    }
  },

  async hmacSign(hash, key, data) {
    const ck = await (key as WebSymmetricKey).getHmacKey(hash, ['sign']);
    return new Uint8Array(await getSubtle().sign({ name: 'HMAC' }, ck, data));
  },
  async hmacVerify(hash, key, data, mac) {
    const ck = await (key as WebSymmetricKey).getHmacKey(hash, ['verify']);
    // Subtle's HMAC verify is constant-time per spec.
    return getSubtle().verify({ name: 'HMAC' }, ck, mac, data);
  },

  // -- JSS (pre-hashed RSA via JS BigInt) -----------------------------------

  async signRsaPkcs1Prehashed(hash, digestBytes, key) {
    const params = rsaPrivateParamsFromJwk((key as WebPrivateKey).jwk);
    const modBytes = Math.ceil(bigintModulusBits(params.n) / 8);
    const digestInfo = buildDigestInfo(hash, digestBytes);
    const em = pkcs1V15Pad(digestInfo, modBytes);
    return rsaPrivate(em, params);
  },
  async verifyRsaPkcs1Prehashed(hash, digestBytes, signature, key) {
    const params = rsaPublicParamsFromJwk((key as WebPublicKey).jwk);
    const modBytes = Math.ceil(bigintModulusBits(params.n) / 8);
    try {
      const em = rsaPublic(signature, params);
      const digestInfo = pkcs1V15Unpad(em, modBytes);
      if (!digestInfo) return false;
      const expected = buildDigestInfo(hash, digestBytes);
      return constantTimeEqual(digestInfo, expected);
    } catch { return false; }
  },

  async signRsaPssPrehashed(hash, digestBytes, saltLength, key) {
    const wp = key as WebPrivateKey;
    if (wp.rsaModulusBits === null) throw new Error('RSA key did not expose modulus length');
    const params = rsaPrivateParamsFromJwk(wp.jwk);
    const em = await pssEncode(digest, randomBytes, hash, digestBytes, saltLength, wp.rsaModulusBits);
    return rsaPrivate(em, params);
  },
  async verifyRsaPssPrehashed(hash, digestBytes, saltLength, signature, key) {
    const wp = key as WebPublicKey;
    if (wp.rsaModulusBits === null) return false;
    const params = rsaPublicParamsFromJwk(wp.jwk);
    try {
      const em = rsaPublic(signature, params);
      return await pssVerify(digest, hash, em, digestBytes, saltLength, wp.rsaModulusBits);
    } catch { return false; }
  },

  // -- JSS (pre-hashed ECDSA via @noble/curves) -----------------------------

  async signEcdsaPrehashed(curve, digestBytes, key) {
    const wp = key as WebPrivateKey;
    if (wp.kind !== 'ec' || wp.curve !== curve) {
      throw new Error(`ECDSA key/curve mismatch: expected ${curve}, got ${wp.curve}`);
    }
    if (typeof wp.jwk.d !== 'string') {
      throw new Error('ECDSA pre-hashed sign requires private key with d');
    }
    // eslint-disable-next-line security/detect-object-injection -- curve narrowed.
    const noble = NOBLE_CURVES[curve];
    // eslint-disable-next-line security/detect-object-injection -- curve narrowed.
    const fieldBytes = NOBLE_FIELD_BYTES[curve];
    const dBytes = b64uToBytes(wp.jwk.d);
    if (dBytes.length !== fieldBytes) {
      throw new Error(`ECDSA private scalar length mismatch for ${curve}`);
    }
    const sig = noble.sign(digestBytes, dBytes, { prehash: false, format: 'compact' });
    return new Uint8Array(sig);
  },
  async verifyEcdsaPrehashed(curve, digestBytes, signature, key) {
    const wp = key as WebPublicKey;
    if (wp.kind !== 'ec' || wp.curve !== curve) return false;
    // eslint-disable-next-line security/detect-object-injection -- curve narrowed.
    const fieldBytes = NOBLE_FIELD_BYTES[curve];
    if (signature.length !== fieldBytes * 2) return false;
    const x = b64uToBytes(String(wp.jwk.x ?? ''));
    const y = b64uToBytes(String(wp.jwk.y ?? ''));
    if (x.length !== fieldBytes || y.length !== fieldBytes) return false;
    const pubBytes = new Uint8Array(1 + x.length + y.length);
    pubBytes[0] = 0x04;
    pubBytes.set(x, 1);
    pubBytes.set(y, 1 + x.length);
    // eslint-disable-next-line security/detect-object-injection -- curve narrowed.
    const noble = NOBLE_CURVES[curve];
    try {
      return noble.verify(signature, digestBytes, pubBytes, { prehash: false, lowS: false });
    } catch { return false; }
  },
};

function rsaPrivateParamsFromJwk(jwk: JwkPublicKey): {
  n: bigint; e: bigint; d: bigint;
  p?: bigint; q?: bigint; dp?: bigint; dq?: bigint; qi?: bigint;
} {
  if (jwk.kty !== 'RSA') throw new Error('RSA private params require kty=RSA');
  if (!jwk.n || !jwk.e || typeof (jwk as Record<string, unknown>).d !== 'string') {
    throw new Error('RSA JWK missing required private parameters');
  }
  const r = jwk as unknown as Record<string, string | undefined>;
  return {
    n: decodeJwkBigInt(r.n!),
    e: decodeJwkBigInt(r.e!),
    d: decodeJwkBigInt(r.d!),
    p: r.p ? decodeJwkBigInt(r.p) : undefined,
    q: r.q ? decodeJwkBigInt(r.q) : undefined,
    dp: r.dp ? decodeJwkBigInt(r.dp) : undefined,
    dq: r.dq ? decodeJwkBigInt(r.dq) : undefined,
    qi: r.qi ? decodeJwkBigInt(r.qi) : undefined,
  };
}

function rsaPublicParamsFromJwk(jwk: JwkPublicKey): { n: bigint; e: bigint } {
  if (jwk.kty !== 'RSA') throw new Error('RSA public params require kty=RSA');
  if (!jwk.n || !jwk.e) throw new Error('RSA JWK missing n or e');
  return { n: decodeJwkBigInt(jwk.n), e: decodeJwkBigInt(jwk.e) };
}

/**
 * Walk an X.509 certificate DER and return the encoded SPKI bytes.
 *
 * Certificate ::= SEQUENCE {
 *   tbsCertificate TBSCertificate,
 *   signatureAlgorithm AlgorithmIdentifier,
 *   signatureValue BIT STRING }
 *
 * TBSCertificate ::= SEQUENCE {
 *   version [0] EXPLICIT Version DEFAULT v1,
 *   serialNumber CertificateSerialNumber,
 *   signature AlgorithmIdentifier,
 *   issuer Name,
 *   validity Validity,
 *   subject Name,
 *   subjectPublicKeyInfo SubjectPublicKeyInfo,
 *   ... }
 */
function extractSpkiFromX509(certDer: Uint8Array): Uint8Array {
  const top = readSeq(certDer, 0);
  const tbs = readSeq(certDer, top.body);
  let p = tbs.body;
  // Skip optional version [0]
  if (certDer[p] === 0xa0) {
    const len = readDerLength(certDer, p + 1);
    p = len.contentStart + len.length;
  }
  // Skip serialNumber INTEGER
  p = skipDerField(certDer, p);
  // Skip signature AlgorithmIdentifier SEQUENCE
  p = skipDerField(certDer, p);
  // Skip issuer Name SEQUENCE
  p = skipDerField(certDer, p);
  // Skip validity SEQUENCE
  p = skipDerField(certDer, p);
  // Skip subject Name SEQUENCE
  p = skipDerField(certDer, p);
  // subjectPublicKeyInfo is the next SEQUENCE.
  if (certDer[p] !== 0x30) throw new Error('X.509: expected SPKI SEQUENCE');
  const len = readDerLength(certDer, p + 1);
  return certDer.subarray(p, len.contentStart + len.length);
}

function skipDerField(der: Uint8Array, p: number): number {
  p += 1;  // skip tag
  const len = readDerLength(der, p);
  return len.contentStart + len.length;
}
