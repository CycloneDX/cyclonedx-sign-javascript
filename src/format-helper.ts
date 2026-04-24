/**
 * Format helper for sign / verify / signBom / verifyBom.
 *
 * Goal: give CycloneDX tool authors a single helper for signing and
 * verifying a BOM without caring whether a given BOM happens to use
 * JSF (CycloneDX 1.x) or JSS (CycloneDX 2.x).
 *
 * Routing rules:
 *
 *   sign(payload, options)
 *     - Routes to signJsf when options.format is absent or 'jsf'.
 *     - Routes to signJss when options.format is 'jss'.
 *     - When format is omitted the helper defaults to JSF so that
 *       existing @cyclonedx/jsf callers can upgrade to @cyclonedx/sign
 *       without code changes.
 *
 *   verify(payload, options?)
 *     - Uses options.format when provided.
 *     - Otherwise inspects the envelope via detectFormat(). JSF is the
 *       current fallback because the JSF envelope shape is what ships
 *       today.
 *
 *   signBom(bom, options)
 *     - Inspects bom.specVersion. 1.x routes to JSF, 2.x routes to JSS.
 *     - An explicit options.format overrides the specVersion inference.
 *     - Non-CycloneDX payloads fall through to sign() with its default.
 *
 *   verifyBom(bom, options?)
 *     - Same specVersion inference. An explicit format wins over both
 *       the specVersion and the envelope shape.
 */

import { signJsf, verifyJsf } from './jsf/index.js';
import { signJss, verifyJss } from './jss/index.js';
import { SignatureError } from './errors.js';
import type { JsonObject, SignatureFormat } from './types.js';
import type { JsfSignOptions, JsfVerifyOptions, JsfVerifyResult } from './jsf/types.js';
import type { JssSignOptions, JssVerifyOptions, JssVerifyResult } from './jss/types.js';

const DEFAULT_SIGNATURE_PROPERTY = 'signature';

/**
 * Options accepted by the format helper's sign() function.
 *
 * The discriminated union keeps the JSS-specific and JSF-specific
 * option surfaces distinct while letting callers omit `format` for the
 * JSF default (preserving compatibility with the old @cyclonedx/jsf
 * SignOptions).
 */
export type SignOptions =
  | (JsfSignOptions & { format?: 'jsf' })
  | (JssSignOptions & { format: 'jss' });

/** Options accepted by the format helper's verify() function. */
export type VerifyOptions =
  | (JsfVerifyOptions & { format?: 'jsf' })
  | (JssVerifyOptions & { format: 'jss' });

/**
 * Result returned by the format helper's verify() function.
 *
 * Always carries the `format` field so callers can tell which code
 * path produced it. The remaining fields mirror the format-specific
 * result shapes.
 */
export type VerifyResult =
  | (JsfVerifyResult & { format: 'jsf' })
  | (JssVerifyResult & { format: 'jss' });

/**
 * Sign a JSON payload using the selected signature format.
 *
 * Defaults to JSF when `format` is omitted so that callers upgrading
 * from @cyclonedx/jsf do not need to touch their call sites.
 */
export function sign(payload: JsonObject, options: SignOptions): JsonObject {
  const format = options.format ?? 'jsf';
  switch (format) {
    case 'jsf':
      return signJsf(payload, options as JsfSignOptions);
    case 'jss':
      return signJss(payload, options as JssSignOptions);
    default:
      throw new SignatureError(`Unknown signature format: ${String(format)}`);
  }
}

/**
 * Verify a JSON payload. The format is taken from options.format when
 * provided, otherwise inferred from the envelope shape. When inference
 * cannot decide, JSF is used as the fallback.
 */
export function verify(
  payload: JsonObject,
  options: VerifyOptions = {},
): VerifyResult {
  const format = options.format ?? detectFormat(payload, options.signatureProperty) ?? 'jsf';
  switch (format) {
    case 'jsf': {
      const result = verifyJsf(payload, options as JsfVerifyOptions);
      return { ...result, format: 'jsf' };
    }
    case 'jss': {
      const result = verifyJss(payload, options as JssVerifyOptions);
      return { ...result, format: 'jss' };
    }
    default:
      throw new SignatureError(`Unknown signature format: ${String(format)}`);
  }
}

/**
 * Sign a CycloneDX BOM. The format is picked automatically from
 * bom.specVersion unless the caller overrides it via options.format.
 *
 *   specVersion starts with "1." -> JSF
 *   specVersion starts with "2." or higher -> JSS
 *
 * Callers who pass a non-CycloneDX JSON object get the same behavior
 * as the helper's sign() (JSF by default).
 */
export function signBom(bom: JsonObject, options: SignOptions): JsonObject {
  const inferred = inferFormatFromBom(bom);
  const format = options.format ?? inferred ?? 'jsf';
  return sign(bom, { ...options, format } as SignOptions);
}

/**
 * Verify a CycloneDX BOM. Precedence for choosing the format:
 *
 *   1. options.format when provided.
 *   2. bom.specVersion when present.
 *   3. Envelope shape detection via detectFormat().
 *   4. JSF as the final fallback.
 */
export function verifyBom(
  bom: JsonObject,
  options: VerifyOptions = {},
): VerifyResult {
  const inferred = inferFormatFromBom(bom);
  const format =
    options.format ??
    inferred ??
    detectFormat(bom, options.signatureProperty) ??
    'jsf';
  return verify(bom, { ...options, format } as VerifyOptions);
}

/**
 * Inspect an envelope and guess which signature format produced it.
 *
 * Returns null when the shape is ambiguous. The JSF shape is the only
 * one currently recognized; the JSS detection branch is a placeholder
 * that will grow once the X.590 envelope layout is finalized.
 */
export function detectFormat(
  payload: JsonObject,
  signatureProperty: string = DEFAULT_SIGNATURE_PROPERTY,
): SignatureFormat | null {
  const candidate = payload[signatureProperty];
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return null;
  }
  const signer = candidate as Record<string, unknown>;

  // JSS detection placeholder. When the X.590 envelope specifies a
  // distinctive marker field (for example a $schema hint, a version
  // tag, or a different property layout), return 'jss' here.
  if (typeof signer.format === 'string' && signer.format.toLowerCase() === 'jss') {
    return 'jss';
  }

  // JSF shape: algorithm and value are both required strings.
  if (typeof signer.algorithm === 'string' && typeof signer.value === 'string') {
    return 'jsf';
  }

  return null;
}

/**
 * Infer the signature format from a CycloneDX BOM's specVersion field.
 * Returns null when the payload is not a CycloneDX BOM or specVersion
 * is missing or unparseable.
 */
export function inferFormatFromBom(bom: JsonObject): SignatureFormat | null {
  const specVersion = bom.specVersion;
  if (typeof specVersion !== 'string' || specVersion.length === 0) {
    return null;
  }
  const major = Number.parseInt(specVersion.split('.')[0] ?? '', 10);
  if (!Number.isFinite(major)) return null;
  if (major <= 1) return 'jsf';
  return 'jss';
}
