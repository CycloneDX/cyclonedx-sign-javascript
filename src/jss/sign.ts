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
 * JSS sign / verify / countersign orchestration (ITU-T X.590, 10/2023).
 *
 * The JSF binding plugs into the format-agnostic orchestrator because
 * JSF's verify-side options (allowedExcludes/allowedExtensions, JSF § 6
 * property checks) match the orchestrator's surface. JSS is simpler in
 * some ways (no excludes/extensions, no property closure rule) and
 * trickier in others (hash_algorithm per signer, PEM-body keys, counter
 * signing as a distinct nested operation), so this module owns the
 * sign/verify loops directly while still using the canonical-view
 * builder and primitives from `binding.ts`.
 */

import { canonicalize } from '../jcs.js';
import { enforceVerifyFirst } from '../core/verify-first.js';
import { decodeBase64Url, encodeBase64Url } from '../base64url.js';
import {
  JssEnvelopeError,
  JssInputError,
} from '../errors.js';
import type { JsonObject, JsonValue, KeyInput } from '../types.js';
import {
  JSS_BINDING,
  JSS_COUNTERSIG_KEY,
  JSS_HASH_ALGO_KEY,
  deriveEmbeddedPublicKeyPemBody,
  renderSignaturecore,
} from './binding.js';
import { isRegisteredAlgorithm, signHash, verifyHash } from './algorithms.js';
import { hashBytes, isRegisteredHashAlgorithm } from './hash.js';
import { publicKeyFromPemBody, toPrivateKey, toPublicKey } from './pem.js';
import type {
  JssCountersignOptions,
  JssSignerInput,
  JssSignerVerifyResult,
  JssSignOptions,
  JssVerifyOptions,
  JssVerifyResult,
} from './types.js';
import type { VerifyPolicy } from '../core/policy.js';
import type { JssSignerDescriptor, JssWrapperState } from './internal-types.js';
import { KeyObject, createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';

const DEFAULT_SIGNATURE_PROPERTY = 'signatures';
const DEFAULT_HASH_ALGORITHM = 'sha-256';

// -- sign --------------------------------------------------------------------

export async function sign(
  payload: JsonObject,
  options: JssSignOptions,
): Promise<JsonObject> {
  assertObject(payload, 'sign');
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers
  if (!options || typeof options !== 'object') {
    throw new JssInputError('JSS sign requires an options object');
  }

  const signers = collectSigners(options);
  const signatureProperty = options.signatureProperty ?? DEFAULT_SIGNATURE_PROPERTY;

  // Existing signatures (if any) on the payload must be preserved
  // around the signing operation per X.590 § 7.1.2 / § 7.1.7. Calling
  // sign() on an already-signed envelope is the normative way to add
  // an additional independent signer; the new signer does not commit
  // to the existing ones (they are temporarily removed during
  // canonicalization).
  const existing = extractExisting(payload, signatureProperty);
  const stripped: JsonObject = { ...payload };
  if (existing.length > 0) {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete, security/detect-object-injection
    delete stripped[signatureProperty];
  }

  // Sign each new signer independently; each canonical view contains
  // ONLY that signer in the array.
  const newDescriptors: JssSignerDescriptor[] = [];
  for (const input of signers) {
    const desc = await signOne(stripped, input, signatureProperty);
    newDescriptors.push(desc);
  }

  // Reassemble: existing first, new signers appended (X.590 § 7.1.7).
  const out: JsonObject = { ...payload };
  // eslint-disable-next-line @typescript-eslint/no-dynamic-delete, security/detect-object-injection
  delete out[signatureProperty];
  const arr: JsonObject[] = [
    ...existing,
    ...newDescriptors.map((d) => renderSignaturecore(d, { stripValue: false })),
  ];
  // eslint-disable-next-line security/detect-object-injection -- caller-controlled
  out[signatureProperty] = arr as unknown as JsonValue;
  return out;
}

async function signOne(
  strippedPayload: JsonObject,
  input: JssSignerInput,
  signatureProperty: string,
): Promise<JssSignerDescriptor> {
  validateSignerInput(input);
  const algorithm = input.algorithm;
  const hashAlgorithm = input.hash_algorithm ?? DEFAULT_HASH_ALGORITHM;

  const desc = signerInputToDescriptor(input, hashAlgorithm);

  // Build the per-signer canonical view: payload (without prior
  // signatures) plus a `signatures` array containing only this signer
  // (without `value`).
  const state: JssWrapperState = {
    mode: 'single',
    options: {},
    signers: [desc],
    finalized: [false],
  };
  const view = JSS_BINDING.buildCanonicalView(
    strippedPayload,
    state,
    0,
    signatureProperty,
  );
  const canonicalBytes = canonicalize(view);
  const digest = hashBytes(hashAlgorithm, canonicalBytes);

  if (input.signer) {
    const sigBytes = await input.signer.sign(canonicalBytes);
    desc.value = encodeBase64Url(sigBytes);
    return desc;
  }
  if (!input.privateKey) {
    throw new JssInputError('Either privateKey or a Signer must be provided');
  }
  const privateKey = toPrivateKey(input.privateKey);
  const sig = signHash(algorithm, hashAlgorithm, digest, privateKey);
  desc.value = encodeBase64Url(sig);
  return desc;
}

function signerInputToDescriptor(input: JssSignerInput, hashAlgorithm: string): JssSignerDescriptor {
  const desc: JssSignerDescriptor = { algorithm: input.algorithm };
  const ext: Record<string, JsonValue> = { [JSS_HASH_ALGO_KEY]: hashAlgorithm };

  // Derive embedded public_key PEM body if requested.
  const embedded = deriveEmbeddedPublicKeyPemBody(input.privateKey, input.public_key);
  if (embedded !== null) ext.public_key = embedded;

  if (input.public_cert_chain !== undefined) {
    ext.public_cert_chain = [...input.public_cert_chain];
  }
  if (input.cert_url !== undefined) ext.cert_url = input.cert_url;
  if (input.thumbprint !== undefined) ext.thumbprint = input.thumbprint;

  if (input.metadata) {
    for (const [k, v] of Object.entries(input.metadata)) {
      if (k === JSS_HASH_ALGO_KEY || k === JSS_COUNTERSIG_KEY) continue;
      // eslint-disable-next-line security/detect-object-injection -- k is a caller-supplied key checked above for sentinels
      ext[k] = v;
    }
  }

  desc.extensionValues = ext;
  return desc;
}

// -- countersign -------------------------------------------------------------

export async function countersign(
  signedPayload: JsonObject,
  options: JssCountersignOptions,
): Promise<JsonObject> {
  assertObject(signedPayload, 'countersign');
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers
  if (!options || typeof options !== 'object' || !options.signer) {
    throw new JssInputError('JSS countersign requires options.signer');
  }
  validateSignerInput(options.signer);
  const signatureProperty = options.signatureProperty ?? DEFAULT_SIGNATURE_PROPERTY;

  // Strong verify-first defense against CWE-345 / CWE-347. The
  // counter signer's canonical view commits to the target
  // signaturecore's full value (X.590 § 7.2.2), so endorsing a
  // tampered target is exactly the failure this check exists to
  // prevent. Shared shape lives in `core/verify-first.ts`.
  const view = JSS_BINDING.detect(signedPayload, signatureProperty);
  if (!view) {
    throw new JssEnvelopeError(`Payload has no "${signatureProperty}" property`);
  }
  await enforceVerifyFirst<KeyInput>({
    expectedSignerCount: view.signers.length,
    publicKeys: options.publicKeys,
    skipVerifyExisting: options.skipVerifyExisting,
    action: 'countersign',
    raise: (message) => { throw new JssEnvelopeError(message); },
    verify: async (trustedKeys) => {
      const result = await verify(signedPayload, {
        signatureProperty,
        publicKeys: trustedKeys,
      } as JssVerifyOptions);
      if (result.valid) return null;
      const failed = result.signers
        .filter((s) => !s.valid)
        .map((s) => `#${s.index}: ${s.errors.join('; ')}`)
        .join(' | ');
      return failed || result.errors.join('; ');
    },
  });

  const targetIndex = options.targetIndex ?? view.signers.length - 1;
  if (targetIndex < 0 || targetIndex >= view.signers.length) {
    throw new JssInputError(
      `targetIndex ${targetIndex} is out of range (0..${view.signers.length - 1})`,
    );
  }

  // The target must not already carry a counter signature: X.590
  // permits one nested `signature` per signaturecore. Counter-counter
  // signing recurses via the nested core's own `signature` property.
  const targetDesc = view.signers[targetIndex]!;
  if (targetDesc.extensionValues && targetDesc.extensionValues[JSS_COUNTERSIG_KEY] !== undefined) {
    throw new JssInputError(
      'target signaturecore already has a counter signature; ' +
        'remove the existing counter signature, or counter-sign the existing one recursively',
    );
  }

  // Strip OTHER signatures from the array for the canonical form
  // (X.590 § 7.2.2). Only the target plus its new counter signature
  // (without value) appear in the canonical view.
  const counterHashAlgorithm = options.signer.hash_algorithm ?? DEFAULT_HASH_ALGORITHM;
  const counterDesc = signerInputToDescriptor(options.signer, counterHashAlgorithm);
  const targetWithCounter = withCounterSig(targetDesc, counterDesc);
  const state: JssWrapperState = {
    mode: 'multi',
    options: {},
    signers: [targetWithCounter],
    finalized: [true],
  };
  // Strip the signature property from the payload before passing it to
  // the canonical view builder; the binding re-attaches.
  const stripped: JsonObject = { ...signedPayload };
  // eslint-disable-next-line @typescript-eslint/no-dynamic-delete, security/detect-object-injection
  delete stripped[signatureProperty];
  const canonicalView = JSS_BINDING.buildCounterCanonicalView(
    stripped,
    state,
    0,
    signatureProperty,
  );
  const canonicalBytes = canonicalize(canonicalView);
  const digest = hashBytes(counterHashAlgorithm, canonicalBytes);

  let sig: Buffer;
  if (options.signer.signer) {
    sig = Buffer.from(await options.signer.signer.sign(canonicalBytes));
  } else if (options.signer.privateKey) {
    sig = signHash(
      options.signer.algorithm,
      counterHashAlgorithm,
      digest,
      toPrivateKey(options.signer.privateKey),
    );
  } else {
    throw new JssInputError('countersign requires options.signer.privateKey or options.signer.signer');
  }
  counterDesc.value = encodeBase64Url(sig);

  // Re-emit the entire envelope: original signatures preserved, the
  // target gains the nested completed counter signature.
  return reassembleWithCounter(signedPayload, signatureProperty, targetIndex, counterDesc);
}

function stripCounterSig(
  ext: Record<string, JsonValue> | undefined,
): Record<string, JsonValue> | undefined {
  if (!ext) return undefined;
  if (ext[JSS_COUNTERSIG_KEY] === undefined) return ext;
  const out: Record<string, JsonValue> = {};
  for (const k of Object.keys(ext)) {
    if (k === JSS_COUNTERSIG_KEY) continue;
    // eslint-disable-next-line security/detect-object-injection -- k from Object.keys
    out[k] = ext[k] as JsonValue;
  }
  return out;
}

function withCounterSig(target: JssSignerDescriptor, counter: JssSignerDescriptor): JssSignerDescriptor {
  const targetExt = { ...(target.extensionValues ?? {}) };
  targetExt[JSS_COUNTERSIG_KEY] = renderSignaturecore(counter, { stripValue: true }) as unknown as JsonValue;
  return { ...target, extensionValues: targetExt };
}

function reassembleWithCounter(
  payload: JsonObject,
  signatureProperty: string,
  targetIndex: number,
  counter: JssSignerDescriptor,
): JsonObject {
  // eslint-disable-next-line security/detect-object-injection -- caller-controlled
  const arr = (payload[signatureProperty] as JsonObject[]).map((entry, i) => {
    if (i !== targetIndex) return entry;
    return { ...entry, signature: renderSignaturecore(counter, { stripValue: false }) };
  });
  const out: JsonObject = { ...payload };
  // eslint-disable-next-line security/detect-object-injection -- caller-controlled
  out[signatureProperty] = arr as unknown as JsonValue;
  return out;
}

// -- verify ------------------------------------------------------------------

export async function verify(
  payload: JsonObject,
  options: JssVerifyOptions = {},
): Promise<JssVerifyResult> {
  assertObject(payload, 'verify');
  const signatureProperty = options.signatureProperty ?? DEFAULT_SIGNATURE_PROPERTY;
  const view = JSS_BINDING.detect(payload, signatureProperty);
  if (!view) {
    throw new JssEnvelopeError(`Payload has no "${signatureProperty}" property`);
  }

  const stripped: JsonObject = { ...payload };
  // eslint-disable-next-line @typescript-eslint/no-dynamic-delete, security/detect-object-injection
  delete stripped[signatureProperty];

  const outcomes: JssSignerVerifyResult[] = [];
  for (let i = 0; i < view.signers.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection -- counted loop index
    const desc = view.signers[i]!;
    const outcome = await verifyOne(stripped, desc, i, options, signatureProperty);
    outcomes.push(outcome);
  }

  const policy: VerifyPolicy = options.policy ?? 'all';
  const okCount = outcomes.filter((o) => o.valid).length;
  let valid = false;
  if (policy === 'all') valid = okCount === outcomes.length;
  else if (policy === 'any') valid = okCount >= 1;
  else valid = okCount >= policy.atLeast;

  return { valid, signers: outcomes, errors: [] };
}

async function verifyOne(
  strippedPayload: JsonObject,
  desc: JssSignerDescriptor,
  index: number,
  options: JssVerifyOptions,
  signatureProperty: string,
): Promise<JssSignerVerifyResult> {
  const ext = desc.extensionValues ?? {};
  const hashAlgorithm = (ext[JSS_HASH_ALGO_KEY] as string | undefined) ?? DEFAULT_HASH_ALGORITHM;

  const out: JssSignerVerifyResult = {
    index,
    valid: false,
    algorithm: desc.algorithm,
    hash_algorithm: hashAlgorithm,
    errors: [],
  };
  if (typeof ext.public_key === 'string') out.public_key = ext.public_key;
  if (Array.isArray(ext.public_cert_chain)) out.public_cert_chain = ext.public_cert_chain as string[];
  if (typeof ext.cert_url === 'string') out.cert_url = ext.cert_url;
  if (typeof ext.thumbprint === 'string') out.thumbprint = ext.thumbprint;

  // Custom metadata round-trip on the result.
  const metadata: Record<string, JsonValue> = {};
  let anyMeta = false;
  for (const k of Object.keys(ext)) {
    if (
      k === JSS_HASH_ALGO_KEY ||
      k === JSS_COUNTERSIG_KEY ||
      k === 'public_key' ||
      k === 'public_cert_chain' ||
      k === 'cert_url' ||
      k === 'thumbprint'
    ) continue;
    // eslint-disable-next-line security/detect-object-injection -- k from Object.keys(ext)
    metadata[k] = ext[k] as JsonValue;
    anyMeta = true;
  }
  if (anyMeta) out.metadata = metadata;

  if (options.allowedAlgorithms && !options.allowedAlgorithms.includes(desc.algorithm as never)) {
    out.errors.push(`algorithm ${desc.algorithm} is not on the allow-list`);
    return out;
  }
  if (options.allowedHashAlgorithms && !options.allowedHashAlgorithms.includes(hashAlgorithm as never)) {
    out.errors.push(`hash_algorithm ${hashAlgorithm} is not on the allow-list`);
    return out;
  }
  if (!isRegisteredAlgorithm(desc.algorithm)) {
    out.errors.push(`unsupported algorithm ${desc.algorithm}`);
    return out;
  }
  if (!isRegisteredHashAlgorithm(hashAlgorithm)) {
    out.errors.push(`unsupported hash_algorithm ${hashAlgorithm}`);
    return out;
  }
  if (
    options.requireEmbeddedKeyMaterial &&
    out.public_key === undefined &&
    out.public_cert_chain === undefined &&
    out.cert_url === undefined &&
    out.thumbprint === undefined
  ) {
    out.errors.push('signaturecore is missing embedded key material');
    return out;
  }
  if (typeof desc.value !== 'string' || desc.value.length === 0) {
    out.errors.push('signaturecore is missing value');
    return out;
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = decodeBase64Url(desc.value);
  } catch (e) {
    out.errors.push(`malformed signature value: ${(e as Error).message}`);
    return out;
  }

  let publicKey: KeyObject;
  try {
    publicKey = resolveSignerKey(desc, options, index);
  } catch (e) {
    out.errors.push(`could not resolve verifying key: ${(e as Error).message}`);
    return out;
  }

  // Build canonical view: only this signer in the array, value
  // stripped. ALSO strip any nested counter signature: the top-level
  // signer did not commit to the counter signature (the counter sig
  // is added AFTER the top-level signer signed). X.590 § 8.1.2 plus
  // dotnet-jss JssVerifier semantics.
  const descForVerify: JssSignerDescriptor = {
    ...desc,
    value: undefined,
    extensionValues: stripCounterSig(desc.extensionValues),
  };
  const stateForVerify: JssWrapperState = {
    mode: 'single',
    options: {},
    signers: [descForVerify],
    finalized: [false],
  };
  const view = JSS_BINDING.buildCanonicalView(
    strippedPayload,
    stateForVerify,
    0,
    signatureProperty,
  );
  const canonicalBytes = canonicalize(view);
  const digest = hashBytes(hashAlgorithm, canonicalBytes);

  let ok = false;
  try {
    ok = verifyHash(desc.algorithm, hashAlgorithm, digest, Buffer.from(signatureBytes), publicKey);
  } catch (e) {
    out.errors.push(`verifier threw: ${(e as Error).message}`);
  }
  if (!ok) {
    out.errors.push('signature did not verify');
  } else {
    out.valid = true;
  }

  // Optionally verify the nested counter signature.
  if (options.verifyCounterSignatures) {
    const counterWire = ext[JSS_COUNTERSIG_KEY];
    if (counterWire && typeof counterWire === 'object' && !Array.isArray(counterWire)) {
      const counterResult = verifyCounterOne(
        strippedPayload,
        desc,
        counterWire,
        options,
        signatureProperty,
      );
      out.countersignature = counterResult;
      if (!counterResult.valid && out.valid) {
        out.errors.push('countersignature did not verify');
        out.valid = false;
      }
    }
  }

  return out;
}

// Body has no await; the caller (`verifyOne`) does `await
// verifyCounterOne(...)` which is a no-op on a non-promise value.
function verifyCounterOne(
  strippedPayload: JsonObject,
  targetDesc: JssSignerDescriptor,
  counterWire: JsonObject,
  options: JssVerifyOptions,
  signatureProperty: string,
): JssSignerVerifyResult {
  const counterDesc = JSS_BINDING.descriptorFromWire(counterWire, {});
  const ext = counterDesc.extensionValues ?? {};
  const hashAlgorithm = (ext[JSS_HASH_ALGO_KEY] as string | undefined) ?? DEFAULT_HASH_ALGORITHM;

  const out: JssSignerVerifyResult = {
    index: 0,
    valid: false,
    algorithm: counterDesc.algorithm,
    hash_algorithm: hashAlgorithm,
    errors: [],
  };
  if (typeof ext.public_key === 'string') out.public_key = ext.public_key;

  if (typeof counterDesc.value !== 'string' || counterDesc.value.length === 0) {
    out.errors.push('counter signaturecore is missing value');
    return out;
  }
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = decodeBase64Url(counterDesc.value);
  } catch (e) {
    out.errors.push(`malformed counter signature value: ${(e as Error).message}`);
    return out;
  }
  let publicKey: KeyObject;
  try {
    publicKey = resolveSignerKey(counterDesc, options, -1);
  } catch (e) {
    out.errors.push(`could not resolve counter verifying key: ${(e as Error).message}`);
    return out;
  }

  // Build the canonical view used at counter-sign time: target signer
  // intact (with its value), nested counter signaturecore without value.
  const targetWithCounterStripped: JssSignerDescriptor = {
    ...targetDesc,
    extensionValues: {
      ...(targetDesc.extensionValues ?? {}),
      [JSS_COUNTERSIG_KEY]: renderSignaturecore({ ...counterDesc, value: undefined }, { stripValue: true }) as unknown as JsonValue,
    },
  };
  const state: JssWrapperState = {
    mode: 'multi',
    options: {},
    signers: [targetWithCounterStripped],
    finalized: [true],
  };
  const view = JSS_BINDING.buildCounterCanonicalView(
    strippedPayload,
    state,
    0,
    signatureProperty,
  );
  const canonicalBytes = canonicalize(view);
  const digest = hashBytes(hashAlgorithm, canonicalBytes);

  let ok = false;
  try {
    ok = verifyHash(counterDesc.algorithm, hashAlgorithm, digest, Buffer.from(signatureBytes), publicKey);
  } catch (e) {
    out.errors.push(`verifier threw: ${(e as Error).message}`);
  }
  if (!ok) out.errors.push('counter signature did not verify');
  else out.valid = true;
  return out;
}

// -- computeCanonicalInputs --------------------------------------------------

/**
 * Pre-compute the per-signer canonical bytes for two-phase signing
 * flows (HSM, KMS, remote signer). Returns one byte sequence per
 * signer in `state.signers` order; each is the JCS canonical form
 * the corresponding signer would have hashed.
 *
 * Pre-hashing is the caller's responsibility in two-phase mode: the
 * caller hashes with the per-signer `hash_algorithm` and feeds the
 * digest into the asymmetric primitive directly (or, for an HSM that
 * expects the canonical bytes plus an algorithm hint, uses the bytes
 * here as-is). See `docs/specs/jss-implementation-plan.md` § 5.5.
 */
export function computeCanonicalInputs(
  payload: JsonObject,
  state: {
    signers: ReadonlyArray<{
      algorithm: string;
      hash_algorithm?: string;
      keyId?: string;
      public_key?: string;
      public_cert_chain?: readonly string[];
      cert_url?: string;
      thumbprint?: string;
      metadata?: Record<string, JsonValue>;
      // Pre-finalized value, if known. Counter-sign two-phase flows
      // sometimes know prior signer values when computing the next.
      value?: string;
    }>;
    signatureProperty?: string;
  },
): Uint8Array[] {
  if (!Array.isArray(state.signers) || state.signers.length === 0) {
    throw new JssInputError('state.signers must be a non-empty array');
  }
  const signatureProperty = state.signatureProperty ?? DEFAULT_SIGNATURE_PROPERTY;
  const stripped: JsonObject = { ...payload };
  // eslint-disable-next-line @typescript-eslint/no-dynamic-delete, security/detect-object-injection
  delete stripped[signatureProperty];

  const out: Uint8Array[] = [];
  for (const s of state.signers) {
    const hashAlgorithm = s.hash_algorithm ?? DEFAULT_HASH_ALGORITHM;
    const ext: Record<string, JsonValue> = { [JSS_HASH_ALGO_KEY]: hashAlgorithm };
    if (s.public_key !== undefined) ext.public_key = s.public_key;
    if (s.public_cert_chain !== undefined) ext.public_cert_chain = [...s.public_cert_chain];
    if (s.cert_url !== undefined) ext.cert_url = s.cert_url;
    if (s.thumbprint !== undefined) ext.thumbprint = s.thumbprint;
    if (s.metadata) {
      for (const [k, v] of Object.entries(s.metadata) as [string, JsonValue][]) {
        if (k === JSS_HASH_ALGO_KEY || k === JSS_COUNTERSIG_KEY) continue;
        // eslint-disable-next-line security/detect-object-injection -- caller-supplied key checked above for sentinels
        ext[k] = v;
      }
    }
    const desc: JssSignerDescriptor = { algorithm: s.algorithm, extensionValues: ext };
    if (s.value !== undefined) desc.value = s.value;
    const tmpState: JssWrapperState = {
      mode: 'single',
      options: {},
      signers: [desc],
      finalized: [false],
    };
    const view = JSS_BINDING.buildCanonicalView(stripped, tmpState, 0, signatureProperty);
    out.push(canonicalize(view));
  }
  return out;
}

// -- helpers -----------------------------------------------------------------

function assertObject(payload: JsonObject, op: string): void {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new JssInputError(`JSS ${op} requires a JSON object payload`);
  }
}

function collectSigners(options: JssSignOptions): JssSignerInput[] {
  const hasOne = options.signer !== undefined;
  const hasMany = options.signers !== undefined;
  if (hasOne && hasMany) {
    throw new JssInputError('Provide either `signer` or `signers`, not both');
  }
  if (hasOne) return [options.signer!];
  if (!hasMany || !options.signers || options.signers.length === 0) {
    throw new JssInputError('JSS sign requires at least one signer');
  }
  return options.signers;
}

function validateSignerInput(input: JssSignerInput): void {
  if (!isRegisteredAlgorithm(input.algorithm)) {
    // After the guard, TS narrows `input.algorithm` to `never` because
    // `JssAlgorithm` was the only declared type; coerce via `String`
    // so the diagnostic still includes whatever the caller passed.
    throw new JssInputError(`Unsupported JSS algorithm: ${String(input.algorithm)}`);
  }
  const hashAlgorithm = input.hash_algorithm ?? DEFAULT_HASH_ALGORITHM;
  if (!isRegisteredHashAlgorithm(hashAlgorithm)) {
    throw new JssInputError(`Unsupported JSS hash algorithm: ${String(hashAlgorithm)}`);
  }
  // X.590 § 6.2.1: at least one of public_key, public_cert_chain,
  // cert_url, or thumbprint MUST be populated. With public_key:'auto'
  // (default) we'll derive from privateKey; otherwise the caller must
  // explicitly provide one.
  if (
    input.public_key === false &&
    input.public_cert_chain === undefined &&
    input.cert_url === undefined &&
    input.thumbprint === undefined
  ) {
    throw new JssInputError(
      'JSS § 6.2.1: at least one of public_key, public_cert_chain, cert_url, or thumbprint must be populated',
    );
  }
}

function extractExisting(payload: JsonObject, signatureProperty: string): JsonObject[] {
  // eslint-disable-next-line security/detect-object-injection -- caller-controlled
  const slot = payload[signatureProperty];
  if (slot === undefined) return [];
  if (!Array.isArray(slot)) {
    throw new JssEnvelopeError(`"${signatureProperty}" must be an array if present`);
  }
  for (const el of slot) {
    if (!el || typeof el !== 'object' || Array.isArray(el)) {
      throw new JssEnvelopeError(`existing ${signatureProperty} entry is not an object`);
    }
  }
  return [...(slot as JsonObject[])];
}

function resolveSignerKey(
  desc: JssSignerDescriptor,
  options: JssVerifyOptions,
  index: number,
): KeyObject {
  // Caller-supplied per-signer override
  if (options.publicKeys) {
    const k = options.publicKeys.get(index);
    if (k !== undefined) return toPublicKey(k);
  }
  // Caller-supplied global override
  if (options.publicKey !== undefined) return toPublicKey(options.publicKey);

  // Embedded `public_key` (PEM body)
  const ext = desc.extensionValues ?? {};
  if (typeof ext.public_key === 'string' && ext.public_key.length > 0) {
    return publicKeyFromPemBody(ext.public_key);
  }
  // Embedded `public_cert_chain[0]` (base64 DER)
  if (Array.isArray(ext.public_cert_chain) && ext.public_cert_chain.length > 0) {
    const first = ext.public_cert_chain[0];
    if (typeof first === 'string' && first.length > 0) {
      const der = Buffer.from(first, 'base64');
      return new X509Certificate(der).publicKey;
    }
  }
  throw new JssInputError(
    'No verifying key available (no caller key and no embedded public_key / public_cert_chain)',
  );
}

