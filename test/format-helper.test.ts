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
  it('defaults to V1 (JSF) when cyclonedxVersion is omitted', () => {
    const { privateKey } = ecPair();
    const signed = sign(
      { hello: 'world' },
      { algorithm: 'ES256', privateKey },
    );
    expect(signed.signature).toBeDefined();
    const result = verify(signed);
    expect(result.valid).toBe(true);
    expect(result.cyclonedxVersion).toBe(CycloneDxMajor.V1);
  });

  it('routes to JSF when cyclonedxVersion is V1', () => {
    const { privateKey } = ecPair();
    const signed = sign(
      { hello: 'world' },
      { cyclonedxVersion: CycloneDxMajor.V1, algorithm: 'ES256', privateKey },
    );
    const result = verify(signed, { cyclonedxVersion: CycloneDxMajor.V1 });
    expect(result.valid).toBe(true);
    expect(result.cyclonedxVersion).toBe(CycloneDxMajor.V1);
  });

  it('routes to the JSS stub when cyclonedxVersion is V2', () => {
    const { privateKey } = ecPair();
    expect(() =>
      sign(
        { hello: 'world' },
        { cyclonedxVersion: CycloneDxMajor.V2, algorithm: 'ES256', privateKey },
      ),
    ).toThrow(JssNotImplementedError);
  });

  it('detects JSF on verify without an explicit version', () => {
    const { privateKey } = ecPair();
    const signed = sign({ a: 1 }, { algorithm: 'ES256', privateKey });
    const result = verify(signed);
    expect(result.cyclonedxVersion).toBe(CycloneDxMajor.V1);
    expect(result.valid).toBe(true);
  });
});

describe('signing CycloneDX shapes', () => {
  it('signs a whole CycloneDX 1.x BOM', () => {
    const { privateKey } = ecPair();
    const bom: JsonObject = {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      components: [],
    };
    const signed = sign(bom, {
      cyclonedxVersion: CycloneDxMajor.V1,
      algorithm: 'ES256',
      privateKey,
    });
    expect(signed.signature).toBeDefined();
    expect((signed.signature as { algorithm: string }).algorithm).toBe('ES256');
    const result = verify(signed, { cyclonedxVersion: CycloneDxMajor.V1 });
    expect(result.valid).toBe(true);
  });

  it('signs a sub-object of a BOM without touching the rest of the BOM', () => {
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

    // Sign just the declarations block, put it back.
    const signedDecls = sign(bom.declarations as JsonObject, {
      cyclonedxVersion: CycloneDxMajor.V1,
      algorithm: 'ES256',
      privateKey,
    });
    bom.declarations = signedDecls;

    // The top-level BOM gained no signature.
    expect(bom.signature).toBeUndefined();

    // The declarations block has one.
    expect((bom.declarations as JsonObject).signature).toBeDefined();

    // Verify the sub-object's signature.
    const result = verify(bom.declarations as JsonObject, {
      cyclonedxVersion: CycloneDxMajor.V1,
    });
    expect(result.valid).toBe(true);

    // Tamper with an unrelated BOM field. The sub-object signature
    // still verifies because it is scoped to declarations.
    (bom.components as unknown as Array<{ name: string }>)[0]!.name = 'libbar';
    const result2 = verify(bom.declarations as JsonObject, {
      cyclonedxVersion: CycloneDxMajor.V1,
    });
    expect(result2.valid).toBe(true);
  });

  it('signs a single signatory inside a BOM', () => {
    const { privateKey } = ecPair();
    const signatory: JsonObject = {
      name: 'Alice',
      role: 'lead-assessor',
    };
    const signed = sign(signatory, {
      cyclonedxVersion: CycloneDxMajor.V1,
      algorithm: 'ES256',
      privateKey,
    });
    expect(signed.signature).toBeDefined();
    const result = verify(signed, { cyclonedxVersion: CycloneDxMajor.V1 });
    expect(result.valid).toBe(true);
  });
});

describe('format detection and conversion helpers', () => {
  it('detectFormat returns jsf for a JSF envelope', () => {
    const { privateKey } = ecPair();
    const signed = sign({ a: 1 }, { algorithm: 'ES256', privateKey });
    expect(detectFormat(signed)).toBe('jsf');
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

describe('JSS stub surface', () => {
  it('JSS sign throws JssNotImplementedError', () => {
    const { privateKey } = ecPair();
    expect(() =>
      signJss({ a: 1 }, { algorithm: 'ES256', privateKey }),
    ).toThrow(JssNotImplementedError);
  });

  it('JSS verify throws JssNotImplementedError', () => {
    expect(() => verifyJss({ a: 1 }, {})).toThrow(JssNotImplementedError);
  });

  it('JssNotImplementedError is a SignatureError', () => {
    try {
      signJss({}, { algorithm: 'ES256', privateKey: '' });
    } catch (err) {
      expect(err).toBeInstanceOf(SignatureError);
      expect(err).toBeInstanceOf(JssNotImplementedError);
      // And importantly NOT a JsfError, so catch-JSF-only code does not swallow it.
      expect(err).not.toBeInstanceOf(JsfError);
    }
  });
});
