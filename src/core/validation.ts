/**
 * Format-agnostic envelope and signer validation.
 *
 * These checks come straight from JSF 0.82 § 5 and § 6 and are
 * re-usable for any binding that adopts the JSF reservation list
 * (X.590 may or may not; if it does not, the JSS binding can simply
 * not call these helpers).
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
 *      object". This is normative verifier behavior; the library
 *      always runs it.
 */

import type {
  EnvelopeOptions,
  SignerDescriptor,
  WrapperState,
} from './types.js';
import {
  isJsfReservedWord,
  isJsfSignatureCoreField,
  JSF_RESERVED_WORDS,
  JSF_WRAPPER_FIELDS_CHAIN,
  JSF_WRAPPER_FIELDS_MULTI,
} from './jsf-reserved.js';

const RESERVED_LIST = JSF_RESERVED_WORDS.join(', ');

/**
 * Validate the union of `extensions` plus every signer's
 * `extensionValues`. Throws via the supplied factory on the first
 * problem.
 *
 * Run at sign time before any cryptographic work, and at verify time
 * before any cryptographic work too.
 */
export function validateExtensionsInvariants(
  options: EnvelopeOptions,
  signers: readonly SignerDescriptor[],
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

/**
 * Validate `excludes` is a well-formed array. Always-on; JSF treats
 * malformed `excludes` as a structural error.
 */
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
 * list. Per JSF § 5: "a conforming JSF implementation must provide
 * options for specifying which properties to accept".
 *
 * Returns null when accepted, or a descriptive error string when
 * rejected.
 */
export function checkAllowedExcludes(
  excludes: readonly string[] | undefined,
  allowed: readonly string[] | undefined,
): string | null {
  if (!allowed) return null; // lenient default
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
 * list. Per JSF § 5: "an option to only accept predefined extension
 * property names".
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

/**
 * Reject any property on the JSF wrapper (multi or chain) that is not
 * defined by JSF § 5. The wrapper may carry exactly the array
 * property (`signers` or `chain`) and the two Global Signature
 * Options (`excludes`, `extensions`). JSF § 6: "there must not be
 * any not here defined properties inside of the signature object" —
 * this is mandatory verifier behavior, not an opt-in.
 *
 * Returns one error string per offending property; empty array means
 * accepted.
 */
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

/**
 * Reject any property on a signaturecore that is not defined by JSF
 * § 5: the fixed fields (algorithm, value, keyId, publicKey,
 * certificatePath) plus the application-specific extension names
 * declared by the envelope's `extensions` list.
 *
 * In single mode the signaturecore IS the JSF signature object, so
 * `excludes` and `extensions` are also legitimate at that level. In
 * multi/chain those Global Signature Options live on the wrapper, not
 * on the inner signaturecore.
 */
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
      // envelope's `extensions` list. No action needed.
    }
  }
  return errors;
}

/**
 * Throw-helper to keep a uniform error type at the call site.
 */
export type StateRaiser = (message: string) => never;

/** Convenience: validate a complete `WrapperState` at sign time. */
export function validateStateAtSign(state: WrapperState, raise: StateRaiser): void {
  validateExcludesShape(state.options.excludes, raise);
  validateExtensionsInvariants(state.options, state.signers, raise);
  if (state.signers.length === 0) {
    raise('At least one signer is required');
  }
  if (state.mode === 'single' && state.signers.length !== 1) {
    raise(`single mode requires exactly one signer, got ${state.signers.length}`);
  }
}
