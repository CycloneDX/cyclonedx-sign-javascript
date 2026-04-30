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
 * JSF 0.82 sign / verify entry points.
 *
 * The thin layer over `core/` that:
 *
 *   - normalizes the unified `JsfSignOptions` into a list of signer
 *     inputs and an `JsfEnvelopeMode`,
 *   - calls `signEnvelope` / `verifyEnvelope` with the JSF binding,
 *   - maps the format-agnostic result into `JsfVerifyResult`.
 *
 * This module also implements the helpers `appendChainSigner`,
 * `appendMultiSigner`, and `computeCanonicalInputs`.
 */

import { canonicalize } from '../jcs.js';
import { enforceVerifyFirst } from '../core/verify-first.js';
import {
  appendDescriptor,
  signEnvelope,
  verifyEnvelope,
} from "./orchestrate.js";
import type {
  JsfEnvelopeMode,
  JsfEnvelopeOptions,
  JsfSignerDescriptor,
  JsfWrapperState,
} from "./internal-types.js";
import type { JsfSignerKeyInput } from "./internal-binding.js";
import { isJsfReservedWord } from "./reserved.js";
import { JSF_BINDING } from './binding.js';
import {
  JsfChainOrderError,
  JsfEnvelopeError,
  JsfInputError,
  JsfMultiSignerInputError,
  JsfVerifyError,
} from '../errors.js';
import type {
  JsfAppendOptions,
  JsfCanonicalInputState,
  JsfSigner,
  JsfSignOptions,
  JsfSignerInput,
  JsfSignerVerifyResult,
  JsfVerifyOptions,
  JsfVerifyResult,
} from './types.js';
import type { JsonObject, JsonValue, KeyInput } from '../types.js';

const DEFAULT_SIGNATURE_PROPERTY = 'signature';

// -- sign --------------------------------------------------------------------

export async function sign(payload: JsonObject, options: JsfSignOptions): Promise<JsonObject> {
  assertObject(payload, 'sign');
   
  if (!options || typeof options !== 'object') {
    throw new JsfInputError('JSF sign requires an options object');
  }

  const signers = collectSigners(options);
  const mode = inferMode(signers.length, options.mode);

  // Compute the effective extensions list: caller-supplied or the
  // union of every signer's extensionValues keys.
  const extensions = options.extensions
    ? [...options.extensions]
    : unionExtensionKeys(signers);

  const envelopeOptions: JsfEnvelopeOptions = {};
  if (options.excludes !== undefined) envelopeOptions.excludes = [...options.excludes];
  if (extensions.length > 0) envelopeOptions.extensions = extensions;

  const inputs: JsfSignerKeyInput[] = signers.map((s) => signerInputToCore(s));

  return signEnvelope({
    payload,
    inputs,
    mode,
    options: envelopeOptions,
    binding: JSF_BINDING,
    signatureProperty: options.signatureProperty ?? DEFAULT_SIGNATURE_PROPERTY,
    raiseInput: (m) => {
      throw new JsfInputError(m);
    },
  });
}

// -- verify ------------------------------------------------------------------

export async function verify(
  payload: JsonObject,
  options: JsfVerifyOptions = {},
): Promise<JsfVerifyResult> {
  assertObject(payload, 'verify');
  const signatureProperty = options.signatureProperty ?? DEFAULT_SIGNATURE_PROPERTY;

  // Build a per-index publicKey override map. The classic single-key
  // option folds into index 0.
  const publicKeys: ReadonlyMap<number, KeyInput> | undefined =
    options.publicKeys ??
    (options.publicKey !== undefined
      ? new Map<number, KeyInput>([[0, options.publicKey]])
      : undefined);

  const result = await verifyEnvelope({
    payload,
    binding: JSF_BINDING,
    signatureProperty,
    publicKeys: publicKeys,
    allowedAlgorithms: options.allowedAlgorithms,
    requireEmbeddedPublicKey: options.requireEmbeddedPublicKey,
    policy: options.policy,
    allowedExcludes: options.allowedExcludes,
    allowedExtensions: options.allowedExtensions,
    raiseEnvelope: (m) => {
      throw new JsfEnvelopeError(m);
    },
    raiseVerify: (m) => {
      throw new JsfVerifyError(m);
    },
    rawWrapper: () => extractRawWrapper(payload, signatureProperty),
    rawSignatureCores: () => extractRawCores(payload, signatureProperty),
  });

  const out: JsfVerifyResult = {
    valid: result.valid,
    mode: result.mode,
    signers: result.signers.map((o): JsfSignerVerifyResult => {
      const r: JsfSignerVerifyResult = {
        index: o.index,
        valid: o.valid,
        algorithm: o.algorithm,
        errors: [...o.errors],
      };
      if (o.keyId !== undefined) r.keyId = o.keyId;
      if (o.publicKey !== undefined) r.publicKey = o.publicKey;
      if (o.certificatePath !== undefined) r.certificatePath = o.certificatePath;
      if (o.extensionValues !== undefined) r.extensionValues = o.extensionValues;
      return r;
    }),
    errors: [...result.envelopeErrors],
  };
  if (result.excludes !== undefined) out.excludes = result.excludes;
  if (result.extensions !== undefined) out.extensions = result.extensions;
  return out;
}

// -- appendChainSigner / appendMultiSigner -----------------------------------

export async function appendChainSigner(
  signedPayload: JsonObject,
  signer: JsfSignerInput,
  options: JsfAppendOptions = {},
): Promise<JsonObject> {
  return appendInternal(signedPayload, signer, options, 'chain');
}

export async function appendMultiSigner(
  signedPayload: JsonObject,
  signer: JsfSignerInput,
  options: JsfAppendOptions = {},
): Promise<JsonObject> {
  return appendInternal(signedPayload, signer, options, 'multi');
}

async function appendInternal(
  signedPayload: JsonObject,
  signer: JsfSignerInput,
  options: JsfAppendOptions,
  expectedMode: 'multi' | 'chain',
): Promise<JsonObject> {
  assertObject(signedPayload, expectedMode === 'chain' ? 'appendChainSigner' : 'appendMultiSigner');
  const signatureProperty = options.signatureProperty ?? DEFAULT_SIGNATURE_PROPERTY;
  const view = JSF_BINDING.detect(signedPayload, signatureProperty);
  if (!view) {
    throw new JsfEnvelopeError(`Payload has no "${signatureProperty}" property`);
  }
  if (view.mode !== expectedMode) {
    throw new JsfChainOrderError(
      `cannot append a ${expectedMode} signer to an envelope in '${view.mode}' mode; ` +
        `start the envelope with mode: '${expectedMode}' from the first signer`,
    );
  }

  validateAppendExtensions(signer, view.options.extensions);

  const newDescriptor: JsfSignerDescriptor = await signerInputToDescriptor(signer);
  const baseState: JsfWrapperState = {
    mode: view.mode,
    options: view.options,
    signers: view.signers,
    finalized: view.signers.map((s) => s.value !== undefined),
  };

  // Verify lower-order signers exist (they should; came off the wire).
  for (let i = 0; i < baseState.finalized.length; i++) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop index
    if (!baseState.finalized[i]) {
      throw new JsfChainOrderError(
        `existing signer #${i} has no value; cannot append`,
      );
    }
  }

  // Strong verify-first defense against CWE-345 / CWE-347.
  //
  // The new signer's canonical view in chain mode commits to every
  // prior signaturecore in full (including its `value`); in multi
  // mode the signer is independent but the resulting envelope still
  // ships any forged sibling. Either way, an appender that does not
  // authenticate prior signers risks endorsing a tampered envelope.
  // Shared shape lives in `core/verify-first.ts`.
  await enforceVerifyFirst<KeyInput>({
    expectedSignerCount: baseState.signers.length,
    publicKeys: options.publicKeys,
    skipVerifyExisting: options.skipVerifyExisting,
    action: 'append',
    raise: (message) => { throw new JsfChainOrderError(message); },
    verify: async (trustedKeys) => {
      const result = await verify(signedPayload, {
        signatureProperty,
        publicKeys: trustedKeys,
      });
      if (result.valid) return null;
      const failed = result.signers
        .filter((s) => !s.valid)
        .map((s) => `#${s.index}: ${s.errors.join('; ')}`)
        .join(' | ');
      const envelope = result.errors.join('; ');
      return `envelope errors: ${envelope || 'none'}; signer errors: ${failed || 'none'}`;
    },
  });

  const extended = appendDescriptor(baseState, newDescriptor);
  const newIndex = extended.signers.length - 1;

  // Build the canonical view for the new signer and sign it.
  const signerImpl = await JSF_BINDING.toSigner(signerInputToCore(signer));

  // Strip the value off the to-be-signed descriptor so the canonical
  // view matches what other implementations would produce.
  const stateForSign: JsfWrapperState = {
    ...extended,
    finalized: extended.finalized.map((f, i) => (i === newIndex ? false : f)),
  };
  const view2 = JSF_BINDING.buildCanonicalView(
    payloadWithoutSignature(signedPayload, signatureProperty),
    stateForSign,
    newIndex,
    signatureProperty,
  );
  const bytes = canonicalize(view2);
  const sigBytes = await signerImpl.sign(bytes);
  // eslint-disable-next-line security/detect-object-injection -- newIndex is computed
  extended.signers[newIndex]!.value = base64url(sigBytes);
  // eslint-disable-next-line security/detect-object-injection -- newIndex is computed
  extended.finalized[newIndex] = true;

  return JSF_BINDING.emit(
    payloadWithoutSignature(signedPayload, signatureProperty),
    extended,
    signatureProperty,
  );
}

function validateAppendExtensions(
  signer: JsfSignerInput,
  declared: readonly string[] | undefined,
): void {
  if (!signer.extensionValues) return;
  const declaredSet = declared ? new Set(declared) : null;
  for (const k of Object.keys(signer.extensionValues)) {
    if (isJsfReservedWord(k)) {
      throw new JsfInputError(
        `extensionValues key "${k}" collides with a JSF reserved word`,
      );
    }
    if (!declaredSet?.has(k)) {
      throw new JsfInputError(
        `extensionValues key "${k}" is not declared in the existing envelope's extensions list; ` +
          'appending cannot grow the extensions list because that would invalidate prior signers',
      );
    }
  }
}

function payloadWithoutSignature(payload: JsonObject, signatureProperty: string): JsonObject {
  const out: JsonObject = { ...payload };
  // eslint-disable-next-line security/detect-object-injection -- caller-controlled property name
  delete out[signatureProperty];
  return out;
}

// -- computeCanonicalInputs --------------------------------------------------

export function computeCanonicalInputs(
  payload: JsonObject,
  state: JsfCanonicalInputState,
  signatureProperty: string = DEFAULT_SIGNATURE_PROPERTY,
): Uint8Array[] {
  if (!Array.isArray(state.signers) || state.signers.length === 0) {
    throw new JsfInputError('state.signers must be a non-empty array');
  }
  if (state.finalized.length !== state.signers.length) {
    throw new JsfInputError('state.finalized.length must equal state.signers.length');
  }
  const descriptors: JsfSignerDescriptor[] = state.signers.map((s) => {
    const obj = s as unknown as Record<string, unknown>;
    const d: JsfSignerDescriptor = { algorithm: String(obj.algorithm) };
    if (typeof obj.keyId === 'string') d.keyId = obj.keyId;
    if (obj.publicKey && typeof obj.publicKey === 'object' && !Array.isArray(obj.publicKey)) {
      d.publicKey = obj.publicKey as unknown as JsfSignerDescriptor['publicKey'];
    }
    if (Array.isArray(obj.certificatePath)) {
      d.certificatePath = (obj.certificatePath as unknown[]).map(String);
    }
    const ev = collectExtensionValuesFromCore(s as unknown as JsonObject);
    if (ev) d.extensionValues = ev;
    return d;
  });
  // Lower-order finalized values get added back so chain canonical
  // view sees them.
  for (let i = 0; i < state.signers.length; i++) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop index
    if (state.finalized[i]) {
      // eslint-disable-next-line security/detect-object-injection -- counted loop index
      const v = (state.signers[i] as unknown as { value?: string }).value;
      // eslint-disable-next-line security/detect-object-injection -- counted loop index
      if (typeof v === 'string') descriptors[i]!.value = v;
    }
  }
  const wrap: JsfWrapperState = {
    mode: state.mode,
    options: {
      ...(state.excludes !== undefined ? { excludes: [...state.excludes] } : {}),
      ...(state.extensions !== undefined ? { extensions: [...state.extensions] } : {}),
    },
    signers: descriptors,
    finalized: [...state.finalized],
  };
  const out: Uint8Array[] = [];
  for (let i = 0; i < descriptors.length; i++) {
    const view = JSF_BINDING.buildCanonicalView(payload, wrap, i, signatureProperty);
    out.push(canonicalize(view));
  }
  return out;
}

function collectExtensionValuesFromCore(core: JsonObject): Record<string, JsonValue> | undefined {
  const known = new Set([
    'algorithm', 'value', 'keyId', 'publicKey', 'certificatePath', 'excludes', 'extensions',
  ]);
  const out: Record<string, JsonValue> = {};
  let any = false;
  for (const k of Object.keys(core)) {
    if (known.has(k)) continue;
    // eslint-disable-next-line security/detect-object-injection -- k from Object.keys
    const v = core[k];
    if (v === undefined) continue;
    // eslint-disable-next-line security/detect-object-injection -- k from Object.keys
    out[k] = v;
    any = true;
  }
  return any ? out : undefined;
}

// -- internals ---------------------------------------------------------------

function assertObject(payload: JsonObject, op: string): void {
   
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new JsfInputError(`JSF ${op} requires a JSON object payload`);
  }
}

function collectSigners(options: JsfSignOptions): JsfSignerInput[] {
  const hasSigner = options.signer !== undefined;
  const hasSigners = options.signers !== undefined;
  if (hasSigner && hasSigners) {
    throw new JsfMultiSignerInputError(
      'Provide either `signer` or `signers`, not both',
    );
  }
  if (hasSigner) {
    return [options.signer!];
  }
  if (!hasSigners || !options.signers || options.signers.length === 0) {
    throw new JsfMultiSignerInputError(
      'JSF sign requires at least one signer (use `signer: x` or `signers: [...]`)',
    );
  }
  return options.signers;
}

function inferMode(count: number, mode: 'multi' | 'chain' | undefined): JsfEnvelopeMode {
  // Length 1, no explicit mode -> bare signaturecore (single mode).
  // Length 1 with mode='multi' or 'chain' -> emit a length-1 wrapper so
  // that later appendMultiSigner / appendChainSigner can grow the
  // envelope without invalidating the first signer.
  if (count === 1) {
    return mode ?? 'single';
  }
  if (mode === undefined) {
    throw new JsfMultiSignerInputError(
      '`mode` is required (\'multi\' or \'chain\') when more than one signer is provided',
    );
  }
  return mode;
}

function unionExtensionKeys(signers: readonly JsfSignerInput[]): string[] {
  const set = new Set<string>();
  for (const s of signers) {
    if (!s.extensionValues) continue;
    for (const k of Object.keys(s.extensionValues)) set.add(k);
  }
  return Array.from(set);
}

function signerInputToCore(s: JsfSignerInput): JsfSignerKeyInput {
  const out: JsfSignerKeyInput = { algorithm: s.algorithm };
  if (s.privateKey !== undefined) out.privateKey = s.privateKey;
  if (s.signer !== undefined) out.signer = s.signer;
  if (s.publicKey !== undefined) out.publicKey = s.publicKey;
  if (s.keyId !== undefined) out.keyId = s.keyId;
  if (s.certificatePath !== undefined) out.certificatePath = [...s.certificatePath];
  if (s.extensionValues !== undefined) out.extensionValues = { ...s.extensionValues };
  return out;
}

async function signerInputToDescriptor(s: JsfSignerInput): Promise<JsfSignerDescriptor> {
  const d: JsfSignerDescriptor = { algorithm: s.algorithm };
  if (s.keyId !== undefined) d.keyId = s.keyId;
  if (s.certificatePath !== undefined) d.certificatePath = [...s.certificatePath];
  if (s.extensionValues !== undefined) d.extensionValues = { ...s.extensionValues };
  // Embedded public key on the descriptor is what JSF will write to
  // the wire; mirror toSigner's rules.
  const embedded = await JSF_BINDING.resolveEmbeddedPublicKey(signerInputToCore(s));
  if (embedded) d.publicKey = embedded;
  return d;
}

function extractRawWrapper(
  payload: JsonObject,
  signatureProperty: string,
): Record<string, unknown> | null {
  // eslint-disable-next-line security/detect-object-injection -- caller-controlled
  const slot = payload[signatureProperty];
  if (!slot || typeof slot !== 'object' || Array.isArray(slot)) return null;
  const obj = slot as Record<string, unknown>;
  if (Array.isArray(obj.signers) || Array.isArray(obj.chain)) {
    return obj;
  }
  return null;
}

function extractRawCores(
  payload: JsonObject,
  signatureProperty: string,
): Record<string, unknown>[] {
  // eslint-disable-next-line security/detect-object-injection -- caller-controlled
  const slot = payload[signatureProperty];
  if (!slot || typeof slot !== 'object' || Array.isArray(slot)) return [];
  const obj = slot as Record<string, unknown>;
  if (Array.isArray(obj.signers)) {
    return (obj.signers as unknown[]).filter(
      (e) => e && typeof e === 'object' && !Array.isArray(e),
    ) as Record<string, unknown>[];
  }
  if (Array.isArray(obj.chain)) {
    return (obj.chain as unknown[]).filter(
      (e) => e && typeof e === 'object' && !Array.isArray(e),
    ) as Record<string, unknown>[];
  }
  return [obj];
}

// Local copy of the base64url encoder to avoid a circular import.
// Matches src/base64url.ts: btoa-based so the Web bundle can encode
// `value` strings without reaching for the Node-only Buffer global.
function base64url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop bounded by length.
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Re-export type aliases for external callers.
export type { JsfSigner };
