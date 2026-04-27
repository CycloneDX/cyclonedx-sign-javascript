/**
 * JSF envelope and signer validation (JSF 0.82 § 5 and § 6).
 *
 * Two groups:
 *
 *   1. Sign-time invariants (run on every sign, also on verify):
 *      reserved-word collision in `extensions`, duplicate names in
 *      `extensions`, `extensionValues` keys not declared in
 *      `extensions`, and `extensionValues` keys equal to a reserved
 *      word. JSF says "must not", so these are unconditional.
 *
 *   2. Verify-time signature-object property check: no undeclared
 *      properties inside any signaturecore, and no undeclared
 *      properties on the wrapper. JSF § 6: "Note that there must not
 *      be any not here defined properties inside of the signature
 *      object". Normative verifier behavior; the library always runs
 *      it.
 */

import type {
  JsfEnvelopeOptions,
  JsfSignerDescriptor,
  JsfWrapperState,
} from './internal-types.js';
import {
  isJsfReservedWord,
  isJsfSignatureCoreField,
  JSF_RESERVED_WORDS,
  JSF_WRAPPER_FIELDS_CHAIN,
  JSF_WRAPPER_FIELDS_MULTI,
} from './reserved.js';

const RESERVED_LIST = JSF_RESERVED_WORDS.join(', ');

export function validateExtensionsInvariants(
  options: JsfEnvelopeOptions,
  signers: readonly JsfSignerDescriptor[],
  raise: (message: string) => never,
): void {
  const declared = options.extensions;
  if (declared) {
    if (!Array.isArray(declared)) {
      raise('extensions must be an array of property names when provided');
    }
    const seen = new Set<string>();
    for (const name of declared) {
      if (typeof name !== 'string' || name.length === 0) {
        raise('extensions entries must be non-empty strings');
      }
      if (isJsfReservedWord(name)) {
        raise(`extension name "${name}" collides with a JSF reserved word (${RESERVED_LIST})`);
      }
      if (seen.has(name)) {
        raise(`extension name "${name}" appears more than once in extensions`);
      }
      seen.add(name);
    }
  }

  const declaredSet = declared ? new Set<string>(declared) : null;
  for (let i = 0; i < signers.length; i++) {
    // eslint-disable-next-line security/detect-object-injection -- index from a counted loop over a typed array
    const sd = signers[i];
    if (!sd) continue;
    const ev = sd.extensionValues;
    if (!ev) continue;
    for (const key of Object.keys(ev)) {
      if (isJsfReservedWord(key)) {
        raise(
          `signer #${i} extensionValues key "${key}" collides with a JSF reserved word (${RESERVED_LIST})`,
        );
      }
      if (!declaredSet || !declaredSet.has(key)) {
        raise(
          `signer #${i} extensionValues key "${key}" is not declared in the envelope's extensions list`,
        );
      }
    }
  }
}

export function validateExcludesShape(
  excludes: readonly string[] | undefined,
  raise: (message: string) => never,
): void {
  if (excludes === undefined) return;
  if (!Array.isArray(excludes)) {
    raise('excludes must be an array of property names when provided');
  }
  for (const name of excludes) {
    if (typeof name !== 'string' || name.length === 0) {
      raise('excludes entries must be non-empty strings');
    }
  }
}

/**
 * Verifier-side acceptance allowlist for the envelope's `excludes`
 * list (JSF § 5: "must provide options for specifying which
 * properties to accept"). Returns null when accepted, or a
 * descriptive error string when rejected.
 */
export function checkAllowedExcludes(
  excludes: readonly string[] | undefined,
  allowed: readonly string[] | undefined,
): string | null {
  if (!allowed) return null;
  if (!excludes || excludes.length === 0) return null;
  const allowedSet = new Set<string>(allowed);
  for (const name of excludes) {
    if (!allowedSet.has(name)) {
      return `excludes entry "${name}" is not on the allowedExcludes list`;
    }
  }
  return null;
}

/**
 * Verifier-side acceptance allowlist for the envelope's `extensions`
 * list (JSF § 5: "an option to only accept predefined extension
 * property names").
 */
export function checkAllowedExtensions(
  extensions: readonly string[] | undefined,
  allowed: readonly string[] | undefined,
): string | null {
  if (!allowed) return null;
  if (!extensions || extensions.length === 0) return null;
  const allowedSet = new Set<string>(allowed);
  for (const name of extensions) {
    if (!allowedSet.has(name)) {
      return `extensions entry "${name}" is not on the allowedExtensions list`;
    }
  }
  return null;
}

export function checkWrapperProperties(
  wrapper: Record<string, unknown>,
  arrayKey: 'signers' | 'chain',
): string[] {
  const allowed = arrayKey === 'signers' ? JSF_WRAPPER_FIELDS_MULTI : JSF_WRAPPER_FIELDS_CHAIN;
  const allowedSet = new Set<string>(allowed);
  const errors: string[] = [];
  for (const key of Object.keys(wrapper)) {
    if (!allowedSet.has(key)) {
      errors.push(
        `wrapper carries undeclared property "${key}" (JSF § 6; allowed: ${allowed.join(', ')})`,
      );
    }
  }
  return errors;
}

export function checkSignatureCoreProperties(
  core: Record<string, unknown>,
  declaredExtensions: readonly string[] | undefined,
  isSingleMode: boolean,
  signerIndex: number,
): string[] {
  const allowed = new Set<string>();
  for (const k of ['algorithm', 'value', 'keyId', 'publicKey', 'certificatePath']) {
    allowed.add(k);
  }
  if (isSingleMode) {
    allowed.add('excludes');
    allowed.add('extensions');
  }
  if (declaredExtensions) {
    for (const k of declaredExtensions) allowed.add(k);
  }
  const errors: string[] = [];
  for (const key of Object.keys(core)) {
    if (!allowed.has(key)) {
      errors.push(
        `signaturecore #${signerIndex} carries undeclared property "${key}" (JSF § 6; declared extensions: ${(declaredExtensions ?? []).join(', ') || 'none'})`,
      );
    } else if (!isJsfSignatureCoreField(key) && key !== 'excludes' && key !== 'extensions') {
      // Declared extension property; allowed because of the
      // envelope's `extensions` list.
    }
  }
  return errors;
}

export type StateRaiser = (message: string) => never;

export function validateStateAtSign(state: JsfWrapperState, raise: StateRaiser): void {
  validateExcludesShape(state.options.excludes, raise);
  validateExtensionsInvariants(state.options, state.signers, raise);
  if (state.signers.length === 0) {
    raise('At least one signer is required');
  }
  if (state.mode === 'single' && state.signers.length !== 1) {
    raise(`single mode requires exactly one signer, got ${state.signers.length}`);
  }
}
