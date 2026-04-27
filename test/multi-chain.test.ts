/**
 * Multi-signature and signature-chain tests covering:
 *
 *   - per-signer round trip in multi and chain modes
 *   - tamper detection (chain: tamper signer i fails i and all higher)
 *   - chain order
 *   - policy aggregation
 *   - counter-signing via appendChainSigner / appendMultiSigner
 *   - promotion rejection
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';

import {
  sign,
  verify,
  appendChainSigner,
  appendMultiSigner } from '../src/jsf/index.js';
import { JsfChainOrderError } from '../src/errors.js';
import type { JsonObject } from '../src/types.js';
import { ecPair, edPair, rsaPair, type KeyPair } from './helpers.js';

function payload(): JsonObject {
  return {
    subject: 'doc-7',
    body: 'hello, world',
    meta: { source: 'pipeline-A', timestamp: '2026-04-01T00:00:00Z' } };
}

describe('JSF multi-signature mode', () => {
  it('signs and verifies two signers (mixed algorithms)', async () => {
    const a = ecPair();
    const b = rsaPair();
    const signed = await sign(payload(), {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'RS256', privateKey: b.privateKey },
      ],
      mode: 'multi' });
    expect(Array.isArray((signed.signature as { signers?: unknown[] }).signers)).toBe(true);
    const result = await verify(signed);
    expect(result.valid).toBe(true);
    expect(result.mode).toBe('multi');
    expect(result.signers).toHaveLength(2);
    expect(result.signers[0]?.algorithm).toBe('ES256');
    expect(result.signers[1]?.algorithm).toBe('RS256');
  });

  it('tampering a signer value flips only that signer', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign(payload(), {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'multi' });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const arr = (wire.signature as { signers: { value: string }[] }).signers;
    const v = arr[0]!.value;
    arr[0]!.value = (v.startsWith('A') ? 'B' : 'A') + v.slice(1);
    const result = await verify(wire);
    expect(result.valid).toBe(false);
    expect(result.signers[0]?.valid).toBe(false);
    expect(result.signers[1]?.valid).toBe(true);
  });

  it('policy any accepts when one signer fails', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign(payload(), {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'multi' });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const arr = (wire.signature as { signers: { value: string }[] }).signers;
    arr[0]!.value = 'AAAA';
    const all = await verify(wire);
    expect(all.valid).toBe(false);
    const any = await verify(wire, { policy: 'any' });
    expect(any.valid).toBe(true);
    const at2 = await verify(wire, { policy: { atLeast: 2 } });
    expect(at2.valid).toBe(false);
  });

  it('honours wrapper-level excludes', async () => {
    const a = ecPair();
    const signed = await sign(
      { subject: 'x', body: 'b', transient: 't' },
      {
        signers: [
          { algorithm: 'ES256', privateKey: a.privateKey },
          { algorithm: 'ES256', privateKey: ecPair().privateKey },
        ],
        mode: 'multi',
        excludes: ['transient'] },
    );
    expect((signed.signature as { excludes: string[] }).excludes).toEqual(['transient']);
    const mutated = { ...signed, transient: 'changed' } as JsonObject;
    const result = await verify(mutated);
    expect(result.valid).toBe(true);
  });
});

describe('JSF signature chain mode', () => {
  it('signs and verifies a two-link chain', async () => {
    const a = ecPair();
    const b = rsaPair();
    const signed = await sign(payload(), {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'RS256', privateKey: b.privateKey },
      ],
      mode: 'chain' });
    expect(Array.isArray((signed.signature as { chain?: unknown[] }).chain)).toBe(true);
    const result = await verify(signed);
    expect(result.valid).toBe(true);
    expect(result.mode).toBe('chain');
    expect(result.signers).toHaveLength(2);
    expect(result.signers[0]?.valid).toBe(true);
    expect(result.signers[1]?.valid).toBe(true);
  });

  it('tampering signer 0 fails signer 0 AND signer 1', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign(payload(), {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'chain' });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const arr = (wire.signature as { chain: { value: string }[] }).chain;
    const v = arr[0]!.value;
    arr[0]!.value = (v.startsWith('A') ? 'B' : 'A') + v.slice(1);
    const result = await verify(wire);
    expect(result.valid).toBe(false);
    expect(result.signers[0]?.valid).toBe(false);
    expect(result.signers[1]?.valid).toBe(false);
  });

  it('reordering the chain array breaks verification', async () => {
    const a = ecPair();
    const b = ecPair();
    const signed = await sign(payload(), {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'chain' });
    const wire = JSON.parse(JSON.stringify(signed)) as JsonObject;
    const w = wire.signature as { chain: unknown[] };
    w.chain = w.chain.slice().reverse();
    const result = await verify(wire);
    expect(result.valid).toBe(false);
  });
});

describe('appendChainSigner', () => {
  it('appends a counter-signer to an existing chain', async () => {
    const a = ecPair();
    const b = rsaPair();
    const c = edPair();
    const initial = await sign(payload(), {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'chain' });
    const two = await appendChainSigner(
      initial,
      { algorithm: 'RS256', privateKey: b.privateKey },
      { publicKeys: new Map([[0, a.publicKey]]) },
    );
    const three = await appendChainSigner(
      two,
      { algorithm: 'Ed25519', privateKey: c.privateKey },
      { publicKeys: new Map([[0, a.publicKey], [1, b.publicKey]]) },
    );
    const result = await verify(three);
    expect(result.valid).toBe(true);
    expect(result.signers).toHaveLength(3);
    for (const s of result.signers) expect(s.valid).toBe(true);
  });

  it('rejects appendChainSigner on a single-mode envelope', async () => {
    const a = ecPair();
    const single = await sign(payload(), {
      signer: { algorithm: 'ES256', privateKey: a.privateKey } });
    await expect(
      appendChainSigner(
        single,
        { algorithm: 'ES256', privateKey: ecPair().privateKey },
        { publicKeys: new Map([[0, a.publicKey]]) },
      ),
    ).rejects.toThrow(JsfChainOrderError);
  });

  it('rejects appendMultiSigner on a chain envelope', async () => {
    const a = ecPair();
    const chain = await sign(payload(), {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'chain' });
    await expect(
      appendMultiSigner(
        chain,
        { algorithm: 'ES256', privateKey: ecPair().privateKey },
        { publicKeys: new Map([[0, a.publicKey]]) },
      ),
    ).rejects.toThrow(JsfChainOrderError);
  });

  it('appendMultiSigner adds an independent peer signer', async () => {
    const a = ecPair();
    const b = ecPair();
    const initial = await sign(payload(), {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'multi' });
    const both = await appendMultiSigner(
      initial,
      { algorithm: 'ES256', privateKey: b.privateKey },
      { publicKeys: new Map([[0, a.publicKey]]) },
    );
    const result = await verify(both);
    expect(result.valid).toBe(true);
    expect(result.signers).toHaveLength(2);
  });

  it('rejects append when neither publicKeys nor skipVerifyExisting is supplied', async () => {
    const a = ecPair();
    const initial = await sign(payload(), {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'chain' });
    await expect(
      appendChainSigner(initial, { algorithm: 'ES256', privateKey: ecPair().privateKey }),
    ).rejects.toThrow(/publicKeys|skipVerifyExisting/);
  });

  it('rejects append when publicKeys is missing an entry for an existing signer', async () => {
    const a = ecPair();
    const b = ecPair();
    const initial = await sign(payload(), {
      signers: [
        { algorithm: 'ES256', privateKey: a.privateKey },
        { algorithm: 'ES256', privateKey: b.privateKey },
      ],
      mode: 'multi' });
    await expect(
      appendMultiSigner(
        initial,
        { algorithm: 'ES256', privateKey: ecPair().privateKey },
        { publicKeys: new Map([[0, a.publicKey]]) }, // missing index 1
      ),
    ).rejects.toThrow(/missing an entry for existing signer #1/);
  });
});

describe('appendChainSigner verify-first defense (CWE-345 / CWE-347)', () => {
  it('refuses to append to a chain whose existing signer was tampered with', async () => {
    const a = ecPair();
    const b = ecPair();
    const initial = await sign(payload(), {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'chain' });
    // Attacker tampers with the existing signer's value before the
    // legitimate counter-signer attempts to append.
    const tampered = JSON.parse(JSON.stringify(initial)) as JsonObject;
    const arr = (tampered.signature as { chain: { value: string }[] }).chain;
    const v = arr[0]!.value;
    arr[0]!.value = (v.startsWith('A') ? 'B' : 'A') + v.slice(1);

    // Caller passes the genuine signer-0 publicKey: verify-first uses
    // the trusted key, sees the tampered value does not match, and
    // refuses to append.
    await expect(
      appendChainSigner(
        tampered,
        { algorithm: 'ES256', privateKey: b.privateKey },
        { publicKeys: new Map([[0, a.publicKey]]) },
      ),
    ).rejects.toThrow(JsfChainOrderError);
    await expect(
      appendChainSigner(
        tampered,
        { algorithm: 'ES256', privateKey: b.privateKey },
        { publicKeys: new Map([[0, a.publicKey]]) },
      ),
    ).rejects.toThrow(/did not verify/);
  });

  it('refuses to append-multi when an existing peer signer is tampered', async () => {
    const a = ecPair();
    const b = ecPair();
    const initial = await sign(payload(), {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'multi' });
    const tampered = JSON.parse(JSON.stringify(initial)) as JsonObject;
    const arr = (tampered.signature as { signers: { value: string }[] }).signers;
    const v = arr[0]!.value;
    arr[0]!.value = (v.startsWith('A') ? 'B' : 'A') + v.slice(1);

    await expect(
      appendMultiSigner(
        tampered,
        { algorithm: 'ES256', privateKey: b.privateKey },
        { publicKeys: new Map([[0, a.publicKey]]) },
      ),
    ).rejects.toThrow(JsfChainOrderError);
  });

  it('refuses to append when an attacker substitutes BOTH value AND embedded publicKey', async () => {
    // The defense's reason for being. Attacker forges a fake initial
    // signer using their own keypair and embeds the matching publicKey.
    // Embedded-key fallback would have rubber-stamped this; the strict
    // mode requires caller-supplied trusted keys and refuses.
    const a = ecPair(); // legitimate signer
    const eve = ecPair(); // attacker
    const fakeInitial = await sign(payload(), {
      signers: [{ algorithm: 'ES256', privateKey: eve.privateKey }],
      mode: 'chain' });
    const b = ecPair(); // legitimate counter-signer
    // Caller provides the genuine signer-0 trusted key (a.publicKey),
    // not the attacker's embedded one. Verify-first fails.
    await expect(
      appendChainSigner(
        fakeInitial,
        { algorithm: 'ES256', privateKey: b.privateKey },
        { publicKeys: new Map([[0, a.publicKey]]) },
      ),
    ).rejects.toThrow(/did not verify/);
  });

  it('skipVerifyExisting opts out of the verify-first defense (use with care)', async () => {
    const a = ecPair();
    const b = ecPair();
    const initial = await sign(payload(), {
      signers: [{ algorithm: 'ES256', privateKey: a.privateKey }],
      mode: 'chain' });
    const tampered = JSON.parse(JSON.stringify(initial)) as JsonObject;
    const arr = (tampered.signature as { chain: { value: string }[] }).chain;
    const v = arr[0]!.value;
    arr[0]!.value = (v.startsWith('A') ? 'B' : 'A') + v.slice(1);

    // With the opt-out flag, append succeeds; the appender is on
    // their own to have verified out of band.
    const grown = await appendChainSigner(
      tampered,
      { algorithm: 'ES256', privateKey: b.privateKey },
      { skipVerifyExisting: true },
    );
    // Resulting envelope: signer 0 still tampered; signer 1 is a valid
    // signature OVER the tampered signer 0. Default 'all' policy fails.
    const r = await verify(grown);
    expect(r.valid).toBe(false);
    expect(r.signers[0]?.valid).toBe(false);
  });

  it('publicKeys override allows verifying when prior signers used keyId only', async () => {
    const a = ecPair();
    const b = ecPair();
    // Initial signer with publicKey omitted — only keyId, no embedded JWK.
    const initial = await sign(payload(), {
      signers: [
        {
          algorithm: 'ES256',
          privateKey: a.privateKey,
          publicKey: false,
          keyId: 'a' },
      ],
      mode: 'chain' });
    // Without publicKeys override, append refuses up front under the
    // strict verify-first posture (no embedded-key fallback allowed).
    await expect(
      appendChainSigner(initial, { algorithm: 'ES256', privateKey: b.privateKey }),
    ).rejects.toThrow(/publicKeys|skipVerifyExisting/);

    // With publicKeys override, append succeeds.
    const grown = await appendChainSigner(
      initial,
      { algorithm: 'ES256', privateKey: b.privateKey },
      { publicKeys: new Map([[0, a.publicKey]]) },
    );
    const r = await verify(grown, {
      publicKeys: new Map([[0, a.publicKey]]) });
    expect(r.valid).toBe(true);
  });
});
