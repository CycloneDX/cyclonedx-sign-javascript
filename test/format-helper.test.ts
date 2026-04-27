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
 * Tests for the top-level format helper: sign, verify, detectFormat,
 * and the JSS stub throwing JssNotImplementedError.
 *
 * The helper treats the caller as the authority on which CycloneDX
 * major version is in play (and therefore which signing format to
 * use). It never inspects BOM structure. These tests cover three
 * shapes of call: signing the whole BOM, signing a sub-object of a
 * BOM (for example a declarations block), and signing arbitrary JSON
 * without a BOM wrapper.
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';

import {
  sign,
  verify,
  detectFormat,
  cyclonedxFormat,
  CycloneDxMajor,
} from '../src/index.js';
import { sign as signJss, verify as verifyJss } from '../src/jss/index.js';
import { JssNotImplementedError, SignatureError, JsfError } from '../src/errors.js';
import type { JsonObject } from '../src/types.js';
import { ecPair, type KeyPair } from './helpers.js';

describe('sign and verify', () => {
  it('throws when cyclonedxVersion is omitted on sign (no default)', async () => {
    const { privateKey } = ecPair();
    await expect(
      sign(
        { hello: 'world' },
        // @ts-expect-error -- intentionally omitting required cyclonedxVersion to assert the runtime guard.
        { signer: { algorithm: 'ES256', privateKey } },
      ),
    ).rejects.toThrow(/cyclonedxVersion/);
  });

  it('throws on verify when neither caller nor detection can determine the version', async () => {
    // Plain JSON with nothing signature-shaped under the signature property.
    await expect(verify({ hello: 'world' })).rejects.toThrow(/cyclonedxVersion/);
  });

  it('routes to JSF when cyclonedxVersion is V1', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { hello: 'world' },
      {
        cyclonedxVersion: CycloneDxMajor.V1,
        signer: { algorithm: 'ES256', privateKey },
      },
    );
    const result = await verify(signed, { cyclonedxVersion: CycloneDxMajor.V1 });
    expect(result.valid).toBe(true);
    expect(result.cyclonedxVersion).toBe(CycloneDxMajor.V1);
  });

  it('routes to JSS (V2) and signs with an Ed25519 key', async () => {
    const ed = generateKeyPairSync('ed25519') as unknown as { privateKey: KeyObject; publicKey: KeyObject };
    const signed = await sign(
      { hello: 'world' },
      {
        cyclonedxVersion: CycloneDxMajor.V2,
        signer: { algorithm: 'Ed25519', privateKey: ed.privateKey, public_key: 'auto' },
      },
    );
    expect(Array.isArray(signed.signatures)).toBe(true);
    const result = await verify(signed, { cyclonedxVersion: CycloneDxMajor.V2 });
    expect(result.valid).toBe(true);
    expect(result.cyclonedxVersion).toBe(CycloneDxMajor.V2);
  });

  it('JSS V2 routes ES256 through the implemented ECDSA path', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { hello: 'world' },
      {
        cyclonedxVersion: CycloneDxMajor.V2,
        signer: { algorithm: 'ES256', privateKey, public_key: 'auto' },
      },
    );
    expect(Array.isArray(signed.signatures)).toBe(true);
    const result = await verify(signed, { cyclonedxVersion: CycloneDxMajor.V2 });
    expect(result.valid).toBe(true);
  });

  it('detects JSF on verify without an explicit version', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { a: 1 },
      { cyclonedxVersion: CycloneDxMajor.V1, signer: { algorithm: 'ES256', privateKey } },
    );
    // No cyclonedxVersion on verify: detection must recognize the JSF envelope shape.
    const result = await verify(signed);
    expect(result.cyclonedxVersion).toBe(CycloneDxMajor.V1);
    expect(result.valid).toBe(true);
  });

  it('detects JSS on verify without an explicit version', async () => {
    const ed = generateKeyPairSync('ed25519') as unknown as { privateKey: KeyObject; publicKey: KeyObject };
    const signed = await sign(
      { a: 1 },
      {
        cyclonedxVersion: CycloneDxMajor.V2,
        signer: { algorithm: 'Ed25519', privateKey: ed.privateKey, public_key: 'auto' },
      },
    );
    const result = await verify(signed);
    expect(result.cyclonedxVersion).toBe(CycloneDxMajor.V2);
    expect(result.valid).toBe(true);
  });
});

describe('signing CycloneDX shapes', () => {
  it('signs a whole CycloneDX 1.x BOM', async () => {
    const { privateKey } = ecPair();
    const bom: JsonObject = {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      components: [],
    };
    const signed = await sign(bom, {
      cyclonedxVersion: CycloneDxMajor.V1,
      signer: { algorithm: 'ES256', privateKey },
    });
    expect(signed.signature).toBeDefined();
    expect((signed.signature as { algorithm: string }).algorithm).toBe('ES256');
    const result = await verify(signed, { cyclonedxVersion: CycloneDxMajor.V1 });
    expect(result.valid).toBe(true);
  });

  it('signs a sub-object of a BOM without touching the rest of the BOM', async () => {
    const { privateKey } = ecPair();
    const bom: JsonObject = {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      components: [{ name: 'libfoo', version: '1.0.0' }] as unknown as JsonObject[] as unknown as JsonObject,
      declarations: {
        assessors: [{ name: 'Alice' }],
      } as unknown as JsonObject,
    };
    const signedDecls = await sign(bom.declarations as JsonObject, {
      cyclonedxVersion: CycloneDxMajor.V1,
      signer: { algorithm: 'ES256', privateKey },
    });
    bom.declarations = signedDecls;
    expect(bom.signature).toBeUndefined();
    expect((bom.declarations as JsonObject).signature).toBeDefined();
    const result = await verify(bom.declarations as JsonObject, {
      cyclonedxVersion: CycloneDxMajor.V1,
    });
    expect(result.valid).toBe(true);
    (bom.components as unknown as Array<{ name: string }>)[0]!.name = 'libbar';
    const result2 = await verify(bom.declarations as JsonObject, {
      cyclonedxVersion: CycloneDxMajor.V1,
    });
    expect(result2.valid).toBe(true);
  });

  it('signs a single signatory inside a BOM', async () => {
    const { privateKey } = ecPair();
    const signatory: JsonObject = { name: 'Alice', role: 'lead-assessor' };
    const signed = await sign(signatory, {
      cyclonedxVersion: CycloneDxMajor.V1,
      signer: { algorithm: 'ES256', privateKey },
    });
    expect(signed.signature).toBeDefined();
    const result = await verify(signed, { cyclonedxVersion: CycloneDxMajor.V1 });
    expect(result.valid).toBe(true);
  });
});

describe('format detection and conversion helpers', () => {
  it('detectFormat returns jsf for a JSF envelope', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { a: 1 },
      { cyclonedxVersion: CycloneDxMajor.V1, signer: { algorithm: 'ES256', privateKey } },
    );
    expect(detectFormat(signed)).toBe('jsf');
  });

  it('detectFormat returns jsf for a JSF multi/chain wrapper', () => {
    expect(detectFormat({ signature: { signers: [] } })).toBe('jsf');
    expect(detectFormat({ signature: { chain: [] } })).toBe('jsf');
  });

  it('detectFormat returns null for an object without a recognizable signer', () => {
    expect(detectFormat({ a: 1 })).toBeNull();
    expect(detectFormat({ signature: { random: 'junk' } })).toBeNull();
  });

  it('cyclonedxFormat maps CycloneDxMajor to the internal format', () => {
    expect(cyclonedxFormat(CycloneDxMajor.V1)).toBe('jsf');
    expect(cyclonedxFormat(CycloneDxMajor.V2)).toBe('jss');
  });
});

describe('JSS subpath surface', () => {
  it('JSS sign + verify round-trip via the subpath import', async () => {
    const ed = generateKeyPairSync('ed25519') as unknown as { privateKey: KeyObject; publicKey: KeyObject };
    const signed = await signJss({ a: 1 }, {
      signer: { algorithm: 'Ed25519', privateKey: ed.privateKey, public_key: 'auto' },
    });
    expect(Array.isArray(signed.signatures)).toBe(true);
    const r = await verifyJss(signed);
    expect(r.valid).toBe(true);
  });

  it('ECDSA family round-trips through the JSS subpath', async () => {
    const { privateKey } = ecPair();
    const signed = await signJss({ a: 1 }, {
      signer: { algorithm: 'ES256', privateKey, public_key: 'auto' },
    });
    const r = await verifyJss(signed);
    expect(r.valid).toBe(true);
  });

  it('JssNotImplementedError still classifies as SignatureError and is not a JsfError', () => {
    // The error class is retained for future use cases (e.g., XMSS / LMS),
    // even though no algorithm currently throws it. Walk the inheritance
    // chain on a freshly-constructed instance.
    const e = new JssNotImplementedError('test');
    expect(e).toBeInstanceOf(SignatureError);
    expect(e).toBeInstanceOf(JssNotImplementedError);
    expect(e).not.toBeInstanceOf(JsfError);
  });
});
