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

import { describe, it, expect } from 'vitest';
import {
  decodeBase64Url,
  encodeBase64Url,
  encodeBase64UrlBigInteger } from '../src/base64url.js';

describe('base64url', () => {
  it('round-trips arbitrary bytes', () => {
    for (let len = 0; len <= 32; len += 1) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i += 1) bytes[i] = (i * 17) & 0xff;
      const encoded = encodeBase64Url(bytes);
      expect(/^[A-Za-z0-9_-]*$/.test(encoded)).toBe(true);
      const decoded = decodeBase64Url(encoded);
      expect(Array.from(decoded)).toEqual(Array.from(bytes));
    }
  });

  it('emits unpadded output', () => {
    expect(encodeBase64Url(Buffer.from('any'))).not.toMatch(/=/);
    expect(encodeBase64Url(Buffer.from('a'))).not.toMatch(/=/);
    expect(encodeBase64Url(Buffer.from('ab'))).not.toMatch(/=/);
  });

  it('uses - and _ in place of + and /', () => {
    // Crafted bytes that produce + and / in standard base64.
    const bytes = Buffer.from([0xfb, 0xef, 0xff]);
    expect(bytes.toString('base64')).toBe('++//');
    expect(encodeBase64Url(bytes)).toBe('--__');
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => decodeBase64Url('abc=')).toThrow(/alphabet/);
    expect(() => decodeBase64Url('abc!')).toThrow(/alphabet/);
    expect(() => decodeBase64Url('a b')).toThrow(/alphabet/);
  });

  it('strips leading zero bytes for big-integer encoding', () => {
    const padded = Buffer.from([0x00, 0x00, 0x01, 0x00]);
    expect(encodeBase64UrlBigInteger(padded)).toBe(encodeBase64Url(Buffer.from([0x01, 0x00])));
  });

  it('keeps a single zero byte for the value zero', () => {
    expect(encodeBase64UrlBigInteger(Buffer.from([0x00]))).toBe(encodeBase64Url(Buffer.from([0x00])));
  });
});
