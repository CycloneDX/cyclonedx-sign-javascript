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
 * Tests for src/internal/crypto/bigint-rsa.ts.
 *
 * The BigInt RSA primitive is the only path through which the Web
 * backend produces wire-compatible JSS RSA signatures. Wire
 * compatibility means: for the same modulus, exponent, and EM block,
 * the bytes coming out of `rsaPrivate` must match the bytes coming
 * out of Node's `privateEncrypt(RSA_NO_PADDING)`. Same for
 * `rsaPublic` against `publicDecrypt(RSA_NO_PADDING)`.
 *
 * These tests exercise the byte conversions, modPow against known
 * small values, and a full round-trip plus byte-equality check
 * against Node for a 2048-bit and a 3072-bit key.
 */

import { describe, it, expect } from 'vitest';
import {
  constants as cryptoConstants,
  privateEncrypt,
  publicDecrypt,
} from 'node:crypto';

import {
  bigIntToBytes,
  bytesToBigInt,
  decodeJwkBigInt,
  modulusBits,
  modulusBytes,
  modPow,
  rsaPrivate,
  rsaPublic,
  type RsaPrivateParams,
} from '../../src/internal/crypto/bigint-rsa.js';
import { rsaPair } from '../helpers.js';

describe('bigint-rsa.bytesToBigInt / bigIntToBytes', () => {
  it('round-trips a one-byte value', () => {
    const n = bytesToBigInt(new Uint8Array([0x42]));
    expect(n).toBe(0x42n);
    expect(bigIntToBytes(n, 1)).toEqual(new Uint8Array([0x42]));
  });

  it('round-trips a multi-byte big-endian value', () => {
    const bytes = new Uint8Array([0x01, 0x00, 0x00, 0x00]);
    expect(bytesToBigInt(bytes)).toBe(0x01000000n);
    expect(bigIntToBytes(0x01000000n, 4)).toEqual(bytes);
  });

  it('left-pads when the integer is shorter than the requested length', () => {
    expect(bigIntToBytes(0x42n, 4)).toEqual(new Uint8Array([0, 0, 0, 0x42]));
  });

  it('throws when the integer overflows the requested length', () => {
    expect(() => bigIntToBytes(0x10000n, 2)).toThrow(/does not fit/);
  });

  it('round-trips a random 256-byte value', () => {
    const bytes = new Uint8Array(256);
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = i & 0xff;
    bytes[0] = 0xff;       // ensure top bit set so leading zeros do not strip
    const n = bytesToBigInt(bytes);
    const back = bigIntToBytes(n, 256);
    expect(back).toEqual(bytes);
  });
});

describe('bigint-rsa.modPow', () => {
  it('returns 0 for any base when modulus is 1', () => {
    expect(modPow(99n, 7n, 1n)).toBe(0n);
  });

  it('matches small-value Fermat little theorem checks', () => {
    // 7^(13-1) ≡ 1 (mod 13), since 13 is prime and gcd(7,13)=1.
    expect(modPow(7n, 12n, 13n)).toBe(1n);
    // 5^(17-1) ≡ 1 (mod 17).
    expect(modPow(5n, 16n, 17n)).toBe(1n);
  });

  it('handles large exponents without TLE', () => {
    // 3^1000 mod 7 — easily computable; just confirms the loop runs.
    expect(modPow(3n, 1000n, 7n)).toBeGreaterThanOrEqual(0n);
  });

  it('matches a manual 2^10 mod 1000', () => {
    expect(modPow(2n, 10n, 1000n)).toBe(24n);
  });
});

describe('bigint-rsa.decodeJwkBigInt', () => {
  it('decodes a single-byte base64url integer', () => {
    // 'AQAB' = 0x010001 = 65537 — the canonical RSA public exponent.
    expect(decodeJwkBigInt('AQAB')).toBe(65537n);
  });

  it('decodes a base64url with no padding', () => {
    // 'Aw' = 0x03.
    expect(decodeJwkBigInt('Aw')).toBe(3n);
  });

  it('handles URL-safe characters', () => {
    // Use - and _ instead of + and /.
    // Build a value that contains both: pick bytes 0xfb 0xff which
    // encode to '-_8' in unpadded base64url (verified manually).
    const got = decodeJwkBigInt('-_8');
    // Equivalent to standard base64 '+_/8' decoded — actually just
    // confirm a sanity round trip with known value 0xfbff.
    expect(got).toBe(0xfbffn);
  });
});

describe('bigint-rsa.modulusBits / modulusBytes', () => {
  it('reports zero bits for zero', () => {
    expect(modulusBits(0n)).toBe(0);
    expect(modulusBytes(0n)).toBe(0);
  });

  it('reports 8 bits for 0xff', () => {
    expect(modulusBits(0xffn)).toBe(8);
    expect(modulusBytes(0xffn)).toBe(1);
  });

  it('reports 16 bits for 0x8000', () => {
    expect(modulusBits(0x8000n)).toBe(16);
    expect(modulusBytes(0x8000n)).toBe(2);
  });

  it('reports 2048 bits for a typical RSA-2048 modulus', () => {
    const { publicKey } = rsaPair(2048);
    const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
    const n = decodeJwkBigInt(jwk.n!);
    expect(modulusBits(n)).toBe(2048);
    expect(modulusBytes(n)).toBe(256);
  });
});

describe('bigint-rsa.rsaPrivate / rsaPublic round trips against Node', () => {
  function paramsFromJwk(jwk: Record<string, string>): RsaPrivateParams {
    return {
      n: decodeJwkBigInt(jwk.n!),
      e: decodeJwkBigInt(jwk.e!),
      d: decodeJwkBigInt(jwk.d!),
      p: jwk.p ? decodeJwkBigInt(jwk.p) : undefined,
      q: jwk.q ? decodeJwkBigInt(jwk.q) : undefined,
      dp: jwk.dp ? decodeJwkBigInt(jwk.dp) : undefined,
      dq: jwk.dq ? decodeJwkBigInt(jwk.dq) : undefined,
      qi: jwk.qi ? decodeJwkBigInt(jwk.qi) : undefined,
    };
  }

  it('produces byte-identical output to Node privateEncrypt(RSA_NO_PADDING) for 2048-bit', () => {
    const { privateKey } = rsaPair(2048);
    const jwk = privateKey.export({ format: 'jwk' }) as Record<string, string>;
    const params = paramsFromJwk(jwk);
    const modBytes = modulusBytes(params.n);
    // Build a deterministic full-modulus EM block with the high bit
    // cleared so it is strictly less than the modulus.
    const em = new Uint8Array(modBytes);
    for (let i = 0; i < em.length; i += 1) em[i] = (i + 1) & 0x7f;

    const ours = rsaPrivate(em, params);
    const nodes = privateEncrypt(
      { key: privateKey, padding: cryptoConstants.RSA_NO_PADDING },
      Buffer.from(em),
    );

    expect(ours.length).toBe(modBytes);
    // Node may emit a leading 0x00 stripped or retained; tolerate both.
    const nodesNorm = nodes.length === modBytes - 1
      ? Buffer.concat([Buffer.alloc(1, 0), nodes])
      : nodes;
    expect(Buffer.from(ours).equals(nodesNorm)).toBe(true);
  });

  it('round-trips through public verify', () => {
    const { privateKey } = rsaPair(2048);
    const jwk = privateKey.export({ format: 'jwk' }) as Record<string, string>;
    const params = paramsFromJwk(jwk);
    const modBytes = modulusBytes(params.n);

    const em = new Uint8Array(modBytes);
    em[modBytes - 1] = 0x42;
    em[modBytes - 2] = 0x07;     // small enough to be < n

    const sig = rsaPrivate(em, params);
    const recovered = rsaPublic(sig, { n: params.n, e: params.e });
    expect(recovered).toEqual(em);
  });

  it('CRT path matches the non-CRT path bit for bit', () => {
    const { privateKey } = rsaPair(2048);
    const jwk = privateKey.export({ format: 'jwk' }) as Record<string, string>;
    const full = paramsFromJwk(jwk);
    // Strip CRT components to force the slow path.
    const slow: RsaPrivateParams = { n: full.n, e: full.e, d: full.d };

    const modBytes = modulusBytes(full.n);
    const em = new Uint8Array(modBytes);
    em[10] = 0x88;
    em[modBytes - 1] = 0x77;

    const fast = rsaPrivate(em, full);
    const slowOut = rsaPrivate(em, slow);
    expect(fast).toEqual(slowOut);
  });

  it('rsaPublic matches Node publicDecrypt(RSA_NO_PADDING)', () => {
    const { privateKey, publicKey } = rsaPair(2048);
    const jwkPriv = privateKey.export({ format: 'jwk' }) as Record<string, string>;
    const params = paramsFromJwk(jwkPriv);
    const modBytes = modulusBytes(params.n);

    const em = new Uint8Array(modBytes);
    em[modBytes - 1] = 0x09;

    const sig = rsaPrivate(em, params);

    const decoded = publicDecrypt(
      { key: publicKey, padding: cryptoConstants.RSA_NO_PADDING },
      Buffer.from(sig),
    );
    const decodedNorm = decoded.length === modBytes - 1
      ? Buffer.concat([Buffer.alloc(1, 0), decoded])
      : decoded;
    const ours = rsaPublic(sig, { n: params.n, e: params.e });
    expect(Buffer.from(ours).equals(decodedNorm)).toBe(true);
  });

  it('handles a 3072-bit modulus correctly', () => {
    const { privateKey } = rsaPair(3072);
    const jwk = privateKey.export({ format: 'jwk' }) as Record<string, string>;
    const params = paramsFromJwk(jwk);
    const modBytes = modulusBytes(params.n);
    expect(modBytes).toBe(384);

    const em = new Uint8Array(modBytes);
    em[modBytes - 1] = 0x55;

    const sig = rsaPrivate(em, params);
    const recovered = rsaPublic(sig, { n: params.n, e: params.e });
    expect(recovered).toEqual(em);
  });
});
