/**
 * Tests for the top-level format helper: sign, verify, signBom,
 * verifyBom, and the JSS stub throwing JssNotImplementedError.
 *
 * These cover the ergonomics of the top-level helpers that tool
 * authors will rely on: a single call site that chooses JSF or JSS
 * based on either an explicit format option or the CycloneDX
 * specVersion.
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';

import {
  sign,
  verify,
  signBom,
  verifyBom,
  detectFormat,
  inferFormatFromBom,
  signJss,
  verifyJss,
} from '../src/index.js';
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
  it('defaults to JSF when format is omitted', () => {
    const { privateKey } = ecPair();
    const signed = sign(
      { hello: 'world' },
      { algorithm: 'ES256', privateKey },
    );
    expect(signed.signature).toBeDefined();
    const result = verify(signed);
    expect(result.valid).toBe(true);
    expect(result.format).toBe('jsf');
  });

  it('routes to JSF when format=jsf is explicit', () => {
    const { privateKey } = ecPair();
    const signed = sign(
      { hello: 'world' },
      { format: 'jsf', algorithm: 'ES256', privateKey },
    );
    const result = verify(signed, { format: 'jsf' });
    expect(result.valid).toBe(true);
    expect(result.format).toBe('jsf');
  });

  it('routes to the JSS stub when format=jss is explicit', () => {
    const { privateKey } = ecPair();
    expect(() =>
      sign(
        { hello: 'world' },
        { format: 'jss', algorithm: 'ES256', privateKey },
      ),
    ).toThrow(JssNotImplementedError);
  });

  it('detects JSF on verify without an explicit format', () => {
    const { privateKey } = ecPair();
    const signed = sign({ a: 1 }, { algorithm: 'ES256', privateKey });
    const result = verify(signed);
    expect(result.format).toBe('jsf');
    expect(result.valid).toBe(true);
  });
});

describe('signBom and verifyBom', () => {
  it('routes CycloneDX 1.x to JSF based on specVersion', () => {
    const { privateKey } = ecPair();
    const bom: JsonObject = {
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      components: [],
    };
    const signed = signBom(bom, { algorithm: 'ES256', privateKey });
    expect(signed.signature).toBeDefined();
    const result = verifyBom(signed);
    expect(result.valid).toBe(true);
    expect(result.format).toBe('jsf');
  });

  it('routes CycloneDX 2.x to the JSS stub based on specVersion', () => {
    const { privateKey } = ecPair();
    const bom: JsonObject = {
      bomFormat: 'CycloneDX',
      specVersion: '2.0',
      version: 1,
      components: [],
    };
    expect(() =>
      signBom(bom, { algorithm: 'ES256', privateKey }),
    ).toThrow(JssNotImplementedError);
  });

  it('honours an explicit format override on signBom', () => {
    const { privateKey } = ecPair();
    const bom: JsonObject = {
      bomFormat: 'CycloneDX',
      specVersion: '2.0',
      version: 1,
      components: [],
    };
    // Force JSF even though specVersion suggests JSS. Useful for
    // testing or for transitional tooling.
    const signed = signBom(bom, { format: 'jsf', algorithm: 'ES256', privateKey });
    expect(signed.signature).toBeDefined();
    const result = verifyBom(signed, { format: 'jsf' });
    expect(result.valid).toBe(true);
    expect(result.format).toBe('jsf');
  });
});

describe('format detection helpers', () => {
  it('detectFormat returns jsf for a JSF envelope', () => {
    const { privateKey } = ecPair();
    const signed = sign({ a: 1 }, { algorithm: 'ES256', privateKey });
    expect(detectFormat(signed)).toBe('jsf');
  });

  it('detectFormat returns null for an object without a recognizable signer', () => {
    expect(detectFormat({ a: 1 })).toBeNull();
    expect(detectFormat({ signature: { random: 'junk' } })).toBeNull();
  });

  it('inferFormatFromBom maps specVersion major to format', () => {
    expect(inferFormatFromBom({ specVersion: '1.4' })).toBe('jsf');
    expect(inferFormatFromBom({ specVersion: '1.6' })).toBe('jsf');
    expect(inferFormatFromBom({ specVersion: '2.0' })).toBe('jss');
    expect(inferFormatFromBom({ specVersion: '3.1' })).toBe('jss');
    expect(inferFormatFromBom({})).toBeNull();
    expect(inferFormatFromBom({ specVersion: 'not-a-version' })).toBeNull();
  });
});

describe('JSS stub surface', () => {
  it('signJss throws JssNotImplementedError', () => {
    const { privateKey } = ecPair();
    expect(() =>
      signJss({ a: 1 }, { algorithm: 'ES256', privateKey }),
    ).toThrow(JssNotImplementedError);
  });

  it('verifyJss throws JssNotImplementedError', () => {
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
