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

interface KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

function ecPair(): KeyPair {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' }) as unknown as KeyPair;
}

describe('sign and verify', () => {
  it('defaults to V1 (JSF) when cyclonedxVersion is omitted', async () => {
    const { privateKey } = ecPair();
    const signed = await sign(
      { hello: 'world' },
      { signer: { algorithm: 'ES256', privateKey } },
    );
    expect(signed.signature).toBeDefined();
    const result = await verify(signed);
    expect(result.valid).toBe(true);
    expect(result.cyclonedxVersion).toBe(CycloneDxMajor.V1);
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

  it('JSS V2 still throws JssNotImplementedError for the deferred ECDSA family', async () => {
    const { privateKey } = ecPair();
    await expect(
      sign(
        { hello: 'world' },
        {
          cyclonedxVersion: CycloneDxMajor.V2,
          signer: { algorithm: 'ES256', privateKey, public_key: 'auto' },
        },
      ),
    ).rejects.toThrow(JssNotImplementedError);
  });

  it('detects JSF on verify without an explicit version', async () => {
    const { privateKey } = ecPair();
    const signed = await sign({ a: 1 }, { signer: { algorithm: 'ES256', privateKey } });
    const result = await verify(signed);
    expect(result.cyclonedxVersion).toBe(CycloneDxMajor.V1);
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
    const signed = await sign({ a: 1 }, { signer: { algorithm: 'ES256', privateKey } });
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

  it('ECDSA family still throws JssNotImplementedError', async () => {
    const { privateKey } = ecPair();
    await expect(
      signJss({ a: 1 }, { signer: { algorithm: 'ES256', privateKey, public_key: 'auto' } }),
    ).rejects.toThrow(JssNotImplementedError);
  });

  it('JssNotImplementedError remains a SignatureError and is not a JsfError', async () => {
    const { privateKey } = ecPair();
    try {
      await signJss({ a: 1 }, { signer: { algorithm: 'ES256', privateKey, public_key: 'auto' } });
    } catch (err) {
      expect(err).toBeInstanceOf(SignatureError);
      expect(err).toBeInstanceOf(JssNotImplementedError);
      expect(err).not.toBeInstanceOf(JsfError);
    }
  });
});
