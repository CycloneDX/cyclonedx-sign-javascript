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
 * JSS format binding (ITU-T X.590, 10/2023).
 *
 * Implements `FormatBinding` for JSS:
 *
 *   - Wire shape: a JSON array under `payload[signatureProperty]`
 *     (default `signatures`). Each element is a signaturecore object
 *     with `algorithm`, `hash_algorithm`, `value`, plus key
 *     identification, optional metadata, and optional nested counter
 *     signature.
 *   - Mode mapping: `'single'` and `'multi'` both map to the array.
 *     Single = length 1, multi = length > 1. JSS multi-signature is
 *     INDEPENDENT (§ 7.1): each signer's canonical view contains only
 *     itself in the array.
 *   - Pre-hash: per X.590 § 6.2.1, each signer pre-hashes the canonical
 *     bytes with `hash_algorithm` before invoking the asymmetric
 *     primitive. The binding's `toSigner` / `toVerifier` returns
 *     closures that perform the pre-hash step.
 *   - Counter signing is NOT a binding mode; it is a separate
 *     operation handled by `src/jss/sign.ts` (`countersign()`). The
 *     binding's canonical-view builder accepts a special "counter"
 *     state via the standard JssWrapperState shape (using `mode='chain'`
 *     to signal a nested counter sign view).
 */

import type { Signer, Verifier } from '../core/signer.js';
import type {
  JssEnvelopeView,
  JssSignerDescriptor,
  JssSignerKeyInput,
  JssVerifierKeyInput,
  JssWrapperState,
} from './internal-types.js';
import type { JsonObject, JsonValue, KeyInput, SignatureFormat } from '../types.js';
import { JssEnvelopeError, JssInputError } from '../errors.js';
import {
  isRegisteredAlgorithm,
  signHash,
  verifyHash,
} from './algorithms.js';
import { hashBytes, isRegisteredHashAlgorithm } from './hash.js';
import {
  pemBodyFromPublicKey,
  publicKeyFromPemBody,
  toPrivateKey,
  toPublicKey,
} from './pem.js';
import { X509Certificate, createPublicKey, KeyObject } from 'node:crypto';

/** Properties JSS reserves on a signaturecore (X.590 § 6.2.1). */
const JSS_RESERVED = new Set([
  'algorithm',
  'hash_algorithm',
  'public_key',
  'public_cert_chain',
  'cert_url',
  'thumbprint',
  'value',
  'signature',
]);

/**
 * Extra fields we stash on a JssSignerDescriptor that the format-agnostic
 * core does not know about. We tunnel them through `extensionValues`,
 * which is treated by JSS as the metadata bag.
 *
 * Internally we also need to carry `hash_algorithm` per signer because
 * each JSS signer specifies its own. The descriptor's `algorithm`
 * field carries the asymmetric algorithm; we encode the hash algorithm
 * by stashing it in a JSS-private extensionValues sentinel `__jss_hash_algorithm__`,
 * which never appears on the wire (the JSS binding's render/parse
 * functions filter it out).
 */
const HASH_ALGO_KEY = '__jss_hash_algorithm__';
const COUNTERSIG_KEY = '__jss_countersignature__';

export class JssBinding {
  readonly format: SignatureFormat = 'jss';

  // -- detect ----------------------------------------------------------------

  detect(payload: JsonObject, signatureProperty: string): JssEnvelopeView | null {
    // eslint-disable-next-line security/detect-object-injection -- caller-controlled, defaults to 'signatures'.
    const slot = payload[signatureProperty];
    if (slot === undefined) return null;
    if (!Array.isArray(slot) || slot.length === 0) {
      throw new JssEnvelopeError(`"${signatureProperty}" must be a non-empty array`);
    }
    const signers: JssSignerDescriptor[] = slot.map((el, i) => {
      if (!el || typeof el !== 'object' || Array.isArray(el)) {
        throw new JssEnvelopeError(`${signatureProperty}[${i}] must be a signaturecore object`);
      }
      return this.descriptorFromWire(el as JsonObject, {});
    });
    // Always 'multi' from the orchestrator's perspective; single = length 1.
    const mode = signers.length === 1 ? 'single' : 'multi';
    return { mode, options: {}, signers };
  }

  // -- descriptor (de)serialization -----------------------------------------

  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- options unused in JSS but the FormatBinding signature requires it.
  descriptorFromWire(core: JsonObject, _options: Record<string, never>): JssSignerDescriptor {
    if (typeof core.algorithm !== 'string' || core.algorithm.length === 0) {
      throw new JssEnvelopeError('signaturecore is missing algorithm');
    }
    if (typeof core.hash_algorithm !== 'string' || core.hash_algorithm.length === 0) {
      throw new JssEnvelopeError('signaturecore is missing hash_algorithm');
    }
    const desc: JssSignerDescriptor = { algorithm: core.algorithm };
    if (typeof core.value === 'string') desc.value = core.value;

    // Stash the hash algorithm on extensionValues; it never travels back
    // out to the wire from this slot. The render path emits it via the
    // `hash_algorithm` field directly.
    const ext: Record<string, JsonValue> = { [HASH_ALGO_KEY]: core.hash_algorithm };
    if (typeof core.public_key === 'string') ext.public_key = core.public_key;
    if (Array.isArray(core.public_cert_chain)) {
      ext.public_cert_chain = core.public_cert_chain as JsonValue[];
    }
    if (typeof core.cert_url === 'string') ext.cert_url = core.cert_url;
    if (typeof core.thumbprint === 'string') ext.thumbprint = core.thumbprint;

    // Custom metadata: anything not in the reserved set.
    for (const key of Object.keys(core)) {
      if (JSS_RESERVED.has(key)) continue;
      // eslint-disable-next-line security/detect-object-injection -- key from Object.keys
      const v = core[key];
      if (v === undefined) continue;
      // eslint-disable-next-line security/detect-object-injection -- key from Object.keys
      ext[key] = v;
    }

    // Counter signature (nested `signature` property).
    if (core.signature && typeof core.signature === 'object' && !Array.isArray(core.signature)) {
      ext[COUNTERSIG_KEY] = core.signature as JsonObject;
    }

    desc.extensionValues = ext;
    return desc;
  }

  // -- canonical view --------------------------------------------------------

  buildCanonicalView(
    payload: JsonObject,
    state: JssWrapperState,
    index: number,
    signatureProperty: string,
  ): JsonObject {
    const view: JsonObject = {};
    for (const key of Object.keys(payload)) {
      if (key === signatureProperty) continue;
      // eslint-disable-next-line security/detect-object-injection -- key from Object.keys(payload)
      view[key] = payload[key] as JsonValue;
    }

    // For a top-level signer (mode === 'single' or 'multi'), only the
    // target signer is present in the array; its `value` is stripped.
    // X.590 § 7.1.2 / § 8.1.2 / dotnet-jss JssVerifier semantics.
    const target = renderSignaturecore(state.signers[index]!, { stripValue: true });
    // eslint-disable-next-line security/detect-object-injection -- caller-controlled
    view[signatureProperty] = [target];
    return view;
  }

  /**
   * Build the canonical view for verifying or signing a counter
   * signature. The signing-time view contains the existing target
   * signer in full (with its `value`) plus the new countersig
   * (without `value`) under the target's `signature` property.
   */
  buildCounterCanonicalView(
    payload: JsonObject,
    state: JssWrapperState,
    targetIndex: number,
    signatureProperty: string,
  ): JsonObject {
    const view: JsonObject = {};
    for (const key of Object.keys(payload)) {
      if (key === signatureProperty) continue;
      // eslint-disable-next-line security/detect-object-injection -- key from Object.keys(payload)
      view[key] = payload[key] as JsonValue;
    }

    // The target keeps its `value`. The countersig stashed at HASH_ALGO_KEY
    // sentinel is the new signer being added; its `value` is stripped
    // for canonicalization.
    const target = renderSignaturecore(state.signers[targetIndex]!, { stripValue: false });
    const counterDesc = this.extractCounterDescriptor(state.signers[targetIndex]!);
    if (!counterDesc) {
      throw new JssInputError('counter signature missing on target signer');
    }
    const counter = renderSignaturecore(counterDesc, { stripValue: true });
    target.signature = counter;
    // eslint-disable-next-line security/detect-object-injection -- caller-controlled
    view[signatureProperty] = [target];
    return view;
  }

  private extractCounterDescriptor(desc: JssSignerDescriptor): JssSignerDescriptor | null {
    const ev = desc.extensionValues;
    if (!ev) return null;
    const counterWire = ev[COUNTERSIG_KEY];
    if (!counterWire || typeof counterWire !== 'object' || Array.isArray(counterWire)) return null;
    return this.descriptorFromWire(counterWire as JsonObject, {});
  }

  // -- emit -----------------------------------------------------------------

  emit(payload: JsonObject, state: JssWrapperState, signatureProperty: string): JsonObject {
    if (signatureProperty in payload) {
      throw new JssInputError(
        `Payload already has a "${signatureProperty}" property; refusing to overwrite`,
      );
    }
    const out: JsonObject = { ...payload };
    const arr = state.signers.map((s) => renderSignaturecore(s, { stripValue: false }));
    // eslint-disable-next-line security/detect-object-injection -- caller-controlled
    out[signatureProperty] = arr;
    return out;
  }

  // -- key plumbing ---------------------------------------------------------

  toSigner(input: JssSignerKeyInput): Signer {
    if (input.signer) return input.signer;
    if (!input.privateKey) {
      throw new JssInputError('Either privateKey or a Signer must be provided');
    }
    if (!isRegisteredAlgorithm(input.algorithm)) {
      throw new JssInputError(`Unsupported JSS algorithm: ${input.algorithm}`);
    }
    const hashAlgorithm = (input.extensionValues?.[HASH_ALGO_KEY] as string | undefined) ?? 'sha-256';
    if (!isRegisteredHashAlgorithm(hashAlgorithm)) {
      throw new JssInputError(`Unsupported JSS hash algorithm: ${hashAlgorithm}`);
    }
    const algorithm = input.algorithm;
    const privateKey = toPrivateKey(input.privateKey);
    // Body has no await; return a resolved promise to satisfy the
    // async `Signer` contract without an empty `async` keyword.
    return {
      sign: (canonicalBytes) => {
        const digest = hashBytes(hashAlgorithm, canonicalBytes);
        const sig = signHash(algorithm, hashAlgorithm, digest, privateKey);
        return Promise.resolve(new Uint8Array(sig));
      },
    };
  }

  toVerifier(input: JssVerifierKeyInput): Verifier {
    if (!isRegisteredAlgorithm(input.algorithm)) {
      throw new JssInputError(`Unsupported JSS algorithm: ${input.algorithm}`);
    }
    const algorithm = input.algorithm;
    return {
      verify: (canonicalBytes, signature) => {
        const hashAlgorithm = (input as { hashAlgorithm?: string }).hashAlgorithm ?? 'sha-256';
        if (!isRegisteredHashAlgorithm(hashAlgorithm)) {
          throw new JssInputError(`Unsupported JSS hash algorithm: ${hashAlgorithm}`);
        }
        const digest = hashBytes(hashAlgorithm, canonicalBytes);
        const publicKey = resolveVerifyingKey(input);
        return Promise.resolve(
          verifyHash(algorithm, hashAlgorithm, digest, Buffer.from(signature), publicKey),
        );
      },
    };
  }

  resolveEmbeddedPublicKey(input: JssSignerKeyInput): never | null {
    // JSF returns a JWK; JSS uses a PEM body. Return null here so the
    // orchestrator does not stamp a JWK onto the descriptor; the
    // sign-time path puts the PEM body into `extensionValues.public_key`
    // before invoking the orchestrator.
    void input;
    return null;
  }
}

/** Singleton — the binding is stateless. */
export const JSS_BINDING = new JssBinding();

// -- Helpers -----------------------------------------------------------------

/** Render a JssSignerDescriptor to the on-the-wire signaturecore object. */
export function renderSignaturecore(
  d: JssSignerDescriptor,
  opts: { stripValue: boolean },
): JsonObject {
  const ext = d.extensionValues ?? {};
  const hashAlgorithm = (ext[HASH_ALGO_KEY] as string | undefined) ?? 'sha-256';
  const core: JsonObject = {
    algorithm: d.algorithm,
    hash_algorithm: hashAlgorithm,
  };

  if (typeof ext.public_key === 'string') core.public_key = ext.public_key;
  if (Array.isArray(ext.public_cert_chain)) {
    core.public_cert_chain = ext.public_cert_chain as JsonValue;
  }
  if (typeof ext.cert_url === 'string') core.cert_url = ext.cert_url;
  if (typeof ext.thumbprint === 'string') core.thumbprint = ext.thumbprint;

  // Custom metadata: any other extensionValues key that is not an
  // internal sentinel and not a reserved JSS field.
  for (const k of Object.keys(ext)) {
    if (k === HASH_ALGO_KEY || k === COUNTERSIG_KEY) continue;
    if (JSS_RESERVED.has(k)) continue;
    if (k === 'public_key' || k === 'public_cert_chain' || k === 'cert_url' || k === 'thumbprint') continue;
    // eslint-disable-next-line security/detect-object-injection -- k from Object.keys(ext)
    const v = ext[k];
    if (v === undefined) continue;
    // eslint-disable-next-line security/detect-object-injection -- k from Object.keys(ext)
    core[k] = v;
  }

  // Nested counter signature.
  const counterWire = ext[COUNTERSIG_KEY];
  if (counterWire && typeof counterWire === 'object' && !Array.isArray(counterWire)) {
    core.signature = counterWire as JsonObject;
  }

  if (!opts.stripValue && d.value !== undefined) core.value = d.value;
  return core;
}

/**
 * Public helper for sign.ts: derive the embedded `public_key` PEM body
 * from a `JssSignerInput.public_key` setting.
 */
export function deriveEmbeddedPublicKeyPemBody(
  privateKeyInput: KeyInput | undefined,
  publicKeyInput: KeyInput | false | 'auto' | undefined,
): string | null {
  if (publicKeyInput === false) return null;
  if (publicKeyInput === undefined || publicKeyInput === 'auto') {
    if (!privateKeyInput) return null;
    const priv = toPrivateKey(privateKeyInput);
    const pub = createPublicKey(priv);
    return pemBodyFromPublicKey(pub);
  }
  // Explicit override: convert any KeyInput to a PEM body.
  return pemBodyFromPublicKey(toPublicKey(publicKeyInput));
}

function resolveVerifyingKey(input: JssVerifierKeyInput): KeyObject {
  if (input.publicKey !== undefined) return toPublicKey(input.publicKey);
  // No JWK embedded for JSS; instead the JSS sign path provides
  // `embeddedPublicKey` as a PEM body string.
  if (typeof (input as { embeddedPemBody?: string }).embeddedPemBody === 'string') {
    return publicKeyFromPemBody((input as { embeddedPemBody?: string }).embeddedPemBody!);
  }
  // Cert chain leaf: extract public key from the first base64 DER cert.
  const certChain = (input as { embeddedCertChain?: string[] }).embeddedCertChain;
  if (Array.isArray(certChain) && certChain.length > 0) {
    return certPublicKey(certChain[0]!);
  }
  throw new JssInputError(
    'No verification key available: provide options.publicKey/publicKeys, or include public_key/public_cert_chain in the signaturecore',
  );
}

function certPublicKey(b64Der: string): KeyObject {
  const der = Buffer.from(b64Der, 'base64');
  return new X509Certificate(der).publicKey;
}

export {
  JSS_RESERVED,
  HASH_ALGO_KEY as JSS_HASH_ALGO_KEY,
  COUNTERSIG_KEY as JSS_COUNTERSIG_KEY,
};
