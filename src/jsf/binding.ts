/**
 * JSF format binding.
 *
 * Implements the format-agnostic `JsfBindingContract` interface for JSF
 * 0.82. Owns:
 *
 *   - mapping `EnvelopeMode` to the JSF wire shapes:
 *       'single' -> bare signaturecore at payload[signatureProperty]
 *       'multi'  -> { signers: [signaturecore, ...] }
 *       'chain'  -> { chain:   [signaturecore, ...] }
 *   - per-signer canonical view per JSF §§ 8 / 9, with the
 *     bracket-and-comma rules expressed by including the right
 *     elements in the array before handing to JCS,
 *   - signaturecore <-> JsfSignerDescriptor mapping including the
 *     spread/collect of extension property values,
 *   - building node-crypto-backed `Signer` / `Verifier` primitives
 *     from key inputs.
 */

import type {
  JsfBindingContract,
  JsfSignerKeyInput,
  JsfVerifierKeyInput,
} from './internal-binding.js';
import type {
  JsfEnvelopeOptions,
  JsfEnvelopeView,
  JsfSignerDescriptor,
  JsfWrapperState,
} from './internal-types.js';
import type { Signer, Verifier } from '../core/signer.js';
import type {
  JsonObject,
  JsonValue,
  JwkPublicKey,
  SignatureFormat,
} from '../types.js';
import {
  exportPublicJwk,
  toPrivateKey,
  toPublicKey,
} from '../jwk.js';
import {
  getAlgorithmSpec,
  isRegisteredAlgorithm,
  signBytes,
  verifyBytes,
} from './algorithms.js';
import { JsfEnvelopeError, JsfInputError } from '../errors.js';
import {
  isJsfReservedWord,
  isJsfSignatureCoreField,
} from './reserved.js';

const FIXED_CORE_FIELDS = new Set([
  'algorithm',
  'value',
  'keyId',
  'publicKey',
  'certificatePath',
]);

/** The single, frozen JSF binding instance. */
export class JsfBinding implements JsfBindingContract {
  readonly format: SignatureFormat = 'jsf';

  // -- detect -----------------------------------------------------------------

  detect(payload: JsonObject, signatureProperty: string): JsfEnvelopeView | null {
    // eslint-disable-next-line security/detect-object-injection -- caller-controlled, defaults to "signature"
    const slot = payload[signatureProperty];
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
    if (slot === undefined) return null;
    if (slot === null || Array.isArray(slot) || typeof slot !== 'object') {
      throw new JsfEnvelopeError(`"${signatureProperty}" property must be an object`);
    }

    const obj = slot as Record<string, unknown>;

    if (Array.isArray(obj.signers)) {
      return this.viewFromWrapper(obj, 'multi');
    }
    if (Array.isArray(obj.chain)) {
      return this.viewFromWrapper(obj, 'chain');
    }

    // Bare signaturecore. The single mode signature object IS the
    // signaturecore, so excludes/extensions live there.
    return this.viewFromBareCore(obj);
  }

  private viewFromWrapper(
    obj: Record<string, unknown>,
    mode: 'multi' | 'chain',
  ): JsfEnvelopeView {
    const arrayKey = mode === 'multi' ? 'signers' : 'chain';
    // eslint-disable-next-line security/detect-object-injection -- key sourced from a static table or Object.keys()/counted loop in the same scope; not an attacker-controlled lookup
    const arr = obj[arrayKey] as unknown;
    if (!Array.isArray(arr) || arr.length === 0) {
      throw new JsfEnvelopeError(`${arrayKey} must be a non-empty array`);
    }
    // Read wrapper-level options first so descriptorFromWire knows
    // which keys count as declared extension properties.
    const options = extractEnvelopeOptions(obj);
    const signers: JsfSignerDescriptor[] = arr.map((el, i) => {
      if (!el || typeof el !== 'object' || Array.isArray(el)) {
        throw new JsfEnvelopeError(`${arrayKey}[${i}] must be a signer object`);
      }
      return this.descriptorFromWire(el as JsonObject, options);
    });
    return { mode, options, signers };
  }

  private viewFromBareCore(obj: Record<string, unknown>): JsfEnvelopeView {
    if (typeof obj.algorithm !== 'string' || obj.algorithm.length === 0) {
      throw new JsfEnvelopeError('signer is missing algorithm');
    }
    const options = extractEnvelopeOptions(obj);
    const desc = this.descriptorFromWire(obj as JsonObject, options);
    return { mode: 'single', options, signers: [desc] };
  }

  // -- descriptor (de)serialization ------------------------------------------

  descriptorFromWire(core: JsonObject, options: JsfEnvelopeOptions): JsfSignerDescriptor {
    if (typeof core.algorithm !== 'string' || core.algorithm.length === 0) {
      throw new JsfEnvelopeError('signer is missing algorithm');
    }
    const desc: JsfSignerDescriptor = { algorithm: core.algorithm };
    if (typeof core.keyId === 'string') desc.keyId = core.keyId;
    if (core.publicKey && typeof core.publicKey === 'object' && !Array.isArray(core.publicKey)) {
      desc.publicKey = core.publicKey as unknown as JwkPublicKey;
    }
    if (Array.isArray(core.certificatePath)) {
      desc.certificatePath = (core.certificatePath as JsonValue[]).map(String);
    }
    if (typeof core.value === 'string') desc.value = core.value;

    // Collect extension property values. JSF § 5 only defines a key
    // as an extension property if the envelope's `extensions` list
    // names it. When the envelope does NOT declare an `extensions`
    // list, no key in the signaturecore qualifies as an extension
    // value; unknown properties are surfaced by the JSF § 6 property
    // check (and would in any case break the signature because the
    // canonical form rebuilt for verify will not include them).
    const declared = options.extensions;
    if (declared && declared.length > 0) {
      const declaredSet = new Set(declared);
      const extensionValues: Record<string, JsonValue> = {};
      let any = false;
      for (const key of Object.keys(core)) {
        if (FIXED_CORE_FIELDS.has(key)) continue;
        if (key === 'excludes' || key === 'extensions') continue;
        if (!declaredSet.has(key)) continue;
        // eslint-disable-next-line security/detect-object-injection -- key from Object.keys
        const v = core[key];
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
        if (v === undefined) continue;
        // eslint-disable-next-line security/detect-object-injection -- key from Object.keys
        extensionValues[key] = v;
        any = true;
      }
      if (any) desc.extensionValues = extensionValues;
    }
    return desc;
  }

  // -- canonical view ---------------------------------------------------------

  buildCanonicalView(
    payload: JsonObject,
    state: JsfWrapperState,
    index: number,
    signatureProperty: string,
  ): JsonObject {
    const view: JsonObject = {};
    const excludeSet = new Set<string>();
    if (state.options.excludes) {
      for (const name of state.options.excludes) excludeSet.add(name);
    }
    for (const key of Object.keys(payload)) {
      if (excludeSet.has(key)) continue;
      if (key === signatureProperty) continue;
      // eslint-disable-next-line security/detect-object-injection -- key from Object.keys(payload)
      view[key] = payload[key] as JsonValue;
    }

    const signers = state.signers;
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion, security/detect-object-injection -- index access bounded by a preceding length check or counted loop; the non-null assertion reflects that runtime invariant; key sourced from a static table or Object.keys()/counted loop in the same scope; not an attacker-controlled lookup
    const targetCore = renderSignaturecore(signers[index]!, { stripValue: true });

    // JSF § 5: "the 'excludes' property itself, must also be excluded
    // from the signature process". We therefore NEVER include excludes
    // in the canonical view (single, multi, or chain). The list is a
    // verifier hint, not signed data. By contrast, `extensions` (the
    // names list) IS part of the signed data — it lives on the JSF
    // signature object that gets canonicalized.
    if (state.mode === 'single') {
      // Single mode: the signaturecore IS the JSF signature object,
      // so extensions lives INSIDE it.
      if (state.options.extensions) {
        targetCore.extensions = [...state.options.extensions];
      }
      // eslint-disable-next-line security/detect-object-injection -- caller-controlled property name
      view[signatureProperty] = targetCore;
      return view;
    }

    if (state.mode === 'multi') {
      // Per JSF § 8: only the target signer is present; brackets are
      // kept (we still emit an array); other signers and their commas
      // vanish naturally.
      const wrapper: JsonObject = { signers: [targetCore] };
      if (state.options.extensions) wrapper.extensions = [...state.options.extensions];
      // eslint-disable-next-line security/detect-object-injection -- caller-controlled property name
      view[signatureProperty] = wrapper;
      return view;
    }

    // chain
    // Per JSF § 9: lower-order signers in full (with `value`),
    // higher-order removed, target with `value` stripped.
    const elements: JsonObject[] = [];
    for (let i = 0; i < index; i++) {
      // eslint-disable-next-line security/detect-object-injection -- index from a counted loop
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- index access bounded by a preceding length check or counted loop; the non-null assertion reflects that runtime invariant
      elements.push(renderSignaturecore(signers[i]!, { stripValue: false }));
    }
    elements.push(targetCore);
    const wrapper: JsonObject = { chain: elements };
    if (state.options.extensions) wrapper.extensions = [...state.options.extensions];
    // eslint-disable-next-line security/detect-object-injection -- caller-controlled property name
    view[signatureProperty] = wrapper;
    return view;
  }

  // -- emit ------------------------------------------------------------------

  emit(payload: JsonObject, state: JsfWrapperState, signatureProperty: string): JsonObject {
    if (signatureProperty in payload) {
      throw new JsfInputError(
        `Payload already has a "${signatureProperty}" property; refusing to overwrite`,
      );
    }
    const out: JsonObject = { ...payload };
    if (state.mode === 'single') {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- index access bounded by a preceding length check or counted loop; the non-null assertion reflects that runtime invariant
      const core = renderSignaturecore(state.signers[0]!, { stripValue: false });
      // Single mode: excludes and extensions live INSIDE the core.
      if (state.options.excludes) core.excludes = [...state.options.excludes];
      if (state.options.extensions) core.extensions = [...state.options.extensions];
      // eslint-disable-next-line security/detect-object-injection -- caller-controlled property name
      out[signatureProperty] = orderSignaturecore(core);
      return out;
    }
    const arr = state.signers.map((s) =>
      orderSignaturecore(renderSignaturecore(s, { stripValue: false })),
    );
    const wrapper: JsonObject = state.mode === 'multi'
      ? { signers: arr }
      : { chain: arr };
    if (state.options.excludes) wrapper.excludes = [...state.options.excludes];
    if (state.options.extensions) wrapper.extensions = [...state.options.extensions];
    // eslint-disable-next-line security/detect-object-injection -- caller-controlled property name
    out[signatureProperty] = wrapper;
    return out;
  }

  // -- key plumbing ----------------------------------------------------------

  toSigner(input: JsfSignerKeyInput): Signer {
    if (input.signer) return input.signer;
    if (!input.privateKey) {
      throw new JsfInputError('Either privateKey or a Signer must be provided');
    }
    if (!isRegisteredAlgorithm(input.algorithm)) {
      throw new JsfInputError(`Unsupported algorithm: ${input.algorithm}`);
    }
    const spec = getAlgorithmSpec(input.algorithm);
    const { keyObject, curve } = toPrivateKey(input.privateKey);
    return {
      sign: (bytes) => Promise.resolve(new Uint8Array(signBytes(spec, bytes, keyObject, curve))),
    };
  }

  toVerifier(input: JsfVerifierKeyInput): Verifier {
    if (!isRegisteredAlgorithm(input.algorithm)) {
      throw new JsfInputError(`Unsupported algorithm: ${input.algorithm}`);
    }
    const spec = getAlgorithmSpec(input.algorithm);
    const keyInput = input.publicKey ?? input.embeddedPublicKey;
    if (keyInput === undefined) {
      throw new JsfInputError(
        'No public key available: provide options.publicKey or include signer.publicKey',
      );
    }
    const { keyObject, curve } = toPublicKey(keyInput);
    return {
      verify: (bytes, signature) =>
        Promise.resolve(verifyBytes(spec, bytes, signature, keyObject, curve)),
    };
  }

  resolveEmbeddedPublicKey(input: JsfSignerKeyInput): JwkPublicKey | null {
    if (!isRegisteredAlgorithm(input.algorithm)) return null;
    const spec = getAlgorithmSpec(input.algorithm);
    if (spec.family === 'hmac') {
      // HMAC: never embed the secret.
      return null;
    }
    if (input.publicKey === false) return null;
    if (input.publicKey === undefined || input.publicKey === 'auto') {
      if (!input.privateKey) return null; // pre-built Signer; caller must supply publicKey explicitly if they want it
      return exportPublicJwk(input.privateKey);
    }
    return exportPublicJwk(input.publicKey);
  }
}

/** Singleton — the binding is stateless. */
export const JSF_BINDING = new JsfBinding();

// -- Helpers -----------------------------------------------------------------

/**
 * Pull the JSF Global Signature Options (`excludes`, `extensions`) off
 * a wire wrapper or bare-core object. Centralized so the wrapper and
 * single-mode detection paths share one implementation.
 */
function extractEnvelopeOptions(obj: Record<string, unknown>): JsfEnvelopeOptions {
  const options: JsfEnvelopeOptions = {};
  if (Array.isArray(obj.excludes)) options.excludes = [...(obj.excludes as string[])];
  if (Array.isArray(obj.extensions)) options.extensions = [...(obj.extensions as string[])];
  return options;
}

function renderSignaturecore(
  d: JsfSignerDescriptor,
  opts: { stripValue: boolean },
): JsonObject {
  const core: JsonObject = { algorithm: d.algorithm };
  if (d.keyId !== undefined) core.keyId = d.keyId;
  if (d.publicKey !== undefined) core.publicKey = d.publicKey as unknown as JsonValue;
  if (d.certificatePath !== undefined) core.certificatePath = [...d.certificatePath];
  if (d.extensionValues) {
    for (const [k, v] of Object.entries(d.extensionValues)) {
      // Reserved-name protection is enforced by validation up front,
      // but defend in depth: refuse to render a colliding extension.
      if (isJsfReservedWord(k) || isJsfSignatureCoreField(k)) {
        throw new JsfInputError(
          `extensionValues key "${k}" collides with a JSF-defined or reserved name`,
        );
      }
      // eslint-disable-next-line security/detect-object-injection -- k from a sanitized extension map
      core[k] = v;
    }
  }
  if (!opts.stripValue && d.value !== undefined) core.value = d.value;
  return core;
}

/**
 * Stable property ordering for emit. JSF does not require any order
 * because consumers re-canonicalize, but a predictable JSON.stringify
 * output is convenient for logs and fixture diffs.
 *
 * Order: algorithm, keyId, publicKey, certificatePath, <extensions in
 * declared insertion order>, value.
 */
function orderSignaturecore(core: JsonObject): JsonObject {
  const out: JsonObject = {};
  // Fixed first.
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
  if (core.algorithm !== undefined) out.algorithm = core.algorithm;
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
  if (core.keyId !== undefined) out.keyId = core.keyId;
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
  if (core.publicKey !== undefined) out.publicKey = core.publicKey;
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
  if (core.certificatePath !== undefined) out.certificatePath = core.certificatePath;
  // Single-mode global options if present (these only appear inside
  // a signaturecore in single mode).
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
  if (core.excludes !== undefined) out.excludes = core.excludes;
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
  if (core.extensions !== undefined) out.extensions = core.extensions;
  // Extension property values, preserving the input map order.
  for (const k of Object.keys(core)) {
    if (k === 'algorithm' || k === 'keyId' || k === 'publicKey' || k === 'certificatePath') continue;
    if (k === 'excludes' || k === 'extensions') continue;
    if (k === 'value') continue;
    // eslint-disable-next-line security/detect-object-injection -- k from Object.keys(core)
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
    if (out[k] !== undefined) continue;
    // eslint-disable-next-line security/detect-object-injection -- k from Object.keys(core)
    const v = core[k];
    if (v === undefined) continue;
    // eslint-disable-next-line security/detect-object-injection -- k from Object.keys(core)
    out[k] = v;
  }
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers (or tampered wire input) whose values violate the TS contract
  if (core.value !== undefined) out.value = core.value;
  return out;
}
