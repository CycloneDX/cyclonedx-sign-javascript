/**
 * JSF 0.82 reserved-word constants used for collision detection.
 *
 * Per JSF 0.82 § 5: "Extension names must not be duplicated or use any
 * of the JSF reserved words 'algorithm', 'certificatePath', 'chain',
 * 'extensions', 'excludes', 'keyId', 'publicKey', 'signers' or
 * 'value'."
 *
 * The set is exported as a frozen tuple plus a helper for fast lookup.
 * It lives in core/ because the format-agnostic validation routines
 * consume it; the JSS binding will reuse the same constant if and
 * when X.590 borrows the reservation list.
 */

export const JSF_RESERVED_WORDS = [
  'algorithm',
  'certificatePath',
  'chain',
  'extensions',
  'excludes',
  'keyId',
  'publicKey',
  'signers',
  'value',
] as const;

export type JsfReservedWord = (typeof JSF_RESERVED_WORDS)[number];

const RESERVED_SET: ReadonlySet<string> = new Set<string>(JSF_RESERVED_WORDS);

/** True if `name` is on the JSF reserved-word list. */
export function isJsfReservedWord(name: string): name is JsfReservedWord {
  return RESERVED_SET.has(name);
}

/**
 * The fixed JSF-defined property names a signaturecore may carry,
 * outside of the application-specific extension properties declared by
 * the envelope's `extensions` Global Signature Option.
 *
 * Used by signature-object property validation (JSF § 6: "there must
 * not be any not here defined properties inside of the signature
 * object") to flag undeclared signaturecore members.
 */
export const JSF_SIGNATURECORE_FIELDS = [
  'algorithm',
  'value',
  'keyId',
  'publicKey',
  'certificatePath',
] as const;

const CORE_FIELD_SET: ReadonlySet<string> = new Set<string>(JSF_SIGNATURECORE_FIELDS);

export function isJsfSignatureCoreField(name: string): boolean {
  return CORE_FIELD_SET.has(name);
}

/**
 * Property names a JSF wrapper (multisignature or signaturechain) may
 * carry: the array property (`signers` or `chain`) plus the two Global
 * Signature Options. JSF § 6 validation rejects anything else.
 */
export const JSF_WRAPPER_FIELDS_MULTI = ['signers', 'excludes', 'extensions'] as const;
export const JSF_WRAPPER_FIELDS_CHAIN = ['chain', 'excludes', 'extensions'] as const;
