/**
 * Format helper for sign and verify.
 *
 * Goal: give CycloneDX tool authors a single sign() and verify() that
 * route to the right JSON signing format based on the CycloneDX major
 * version they are targeting:
 *
 *   CycloneDxMajor.V1 -> JSF
 *   CycloneDxMajor.V2 -> JSS
 *
 * The caller hands in the object they want signed (a whole BOM, a
 * declarations block, a single signatory, any JSON object) and the
 * enum value that matches the BOM's spec version. The library never
 * inspects the BOM structure to pick the format, so sub-object signing
 * is just a matter of passing the sub-object as the subject.
 *
 * Routing rules:
 *
 *   sign(subject, options)
 *     - Dispatches to the JSF sign when options.cyclonedxVersion is V1
 *       or absent.
 *     - Dispatches to the JSS sign when options.cyclonedxVersion is V2.
 *     - When cyclonedxVersion is omitted the default is V1 (JSF).
 *
 *   verify(subject, options?)
 *     - Uses options.cyclonedxVersion when provided.
 *     - Otherwise inspects the envelope via detectFormat() and maps
 *       the format back to a CycloneDxMajor value. JSF / V1 is the
 *       final fallback because that is what ships today.
 */

import { sign as signJsf, verify as verifyJsf } from './jsf/sign.js';
import { sign as signJss, verify as verifyJss } from './jss/sign.js';
import { SignatureError } from './errors.js';
import { CycloneDxMajor } from './types.js';
import type { JsonObject, SignatureFormat } from './types.js';
import type { JsfSignOptions, JsfVerifyOptions, JsfVerifyResult } from './jsf/types.js';
import type { JssSignOptions, JssVerifyOptions, JssVerifyResult } from './jss/types.js';

const DEFAULT_SIGNATURE_PROPERTY = 'signature';

/**
 * Options accepted by the top-level sign() function.
 *
 * The discriminated union keeps the JSS and JSF option surfaces
 * distinct while letting callers omit cyclonedxVersion for the JSF
 * default.
 */
export type SignOptions =
  | (JsfSignOptions & { cyclonedxVersion?: CycloneDxMajor.V1 })
  | (JssSignOptions & { cyclonedxVersion: CycloneDxMajor.V2 });

/** Options accepted by the top-level verify() function. */
export type VerifyOptions =
  | (JsfVerifyOptions & { cyclonedxVersion?: CycloneDxMajor.V1 })
  | (JssVerifyOptions & { cyclonedxVersion: CycloneDxMajor.V2 });

/**
 * Result returned by the top-level verify() function.
 *
 * Always carries the cyclonedxVersion field so callers can tell which
 * code path produced the result. The remaining fields mirror the
 * format-specific result shapes.
 */
export type VerifyResult =
  | (JsfVerifyResult & { cyclonedxVersion: CycloneDxMajor.V1 })
  | (JssVerifyResult & { cyclonedxVersion: CycloneDxMajor.V2 });

/**
 * Sign a JSON object for the given CycloneDX major version.
 *
 * The subject can be the whole BOM or any JSON object inside it (a
 * declarations block, a signatory, a formulation entry, and so on).
 * Only the subject is signed; the library does not rewrite anything
 * outside of it.
 *
 * Defaults to CycloneDxMajor.V1 when cyclonedxVersion is omitted.
 */
export function sign(subject: JsonObject, options: SignOptions): JsonObject {
  const version = options.cyclonedxVersion ?? CycloneDxMajor.V1;
  switch (version) {
    case CycloneDxMajor.V1:
      return signJsf(subject, options as JsfSignOptions);
    case CycloneDxMajor.V2:
      return signJss(subject, options as JssSignOptions);
    default:
      throw new SignatureError(`Unknown CycloneDX major version: ${String(version)}`);
  }
}

/**
 * Verify a signed JSON object.
 *
 * The cyclonedxVersion option picks the verifying format. When it is
 * omitted the helper inspects the envelope shape and falls back to V1
 * (JSF) when the shape is ambiguous.
 */
export function verify(
  subject: JsonObject,
  options: VerifyOptions = {},
): VerifyResult {
  const version =
    options.cyclonedxVersion ??
    detectCycloneDxMajor(subject, options.signatureProperty) ??
    CycloneDxMajor.V1;
  switch (version) {
    case CycloneDxMajor.V1: {
      const result = verifyJsf(subject, options as JsfVerifyOptions);
      return { ...result, cyclonedxVersion: CycloneDxMajor.V1 };
    }
    case CycloneDxMajor.V2: {
      const result = verifyJss(subject, options as JssVerifyOptions);
      return { ...result, cyclonedxVersion: CycloneDxMajor.V2 };
    }
    default:
      throw new SignatureError(`Unknown CycloneDX major version: ${String(version)}`);
  }
}

/**
 * Inspect an envelope and guess which signature format produced it.
 *
 * Returns null when the shape is ambiguous. The JSF shape is the only
 * one currently recognized; the JSS detection branch is a placeholder
 * that will grow once the X.590 envelope layout is finalized.
 *
 * This utility is exposed for callers that need format-level
 * introspection (for example a generic viewer). Most callers should
 * prefer passing cyclonedxVersion explicitly.
 */
export function detectFormat(
  subject: JsonObject,
  signatureProperty: string = DEFAULT_SIGNATURE_PROPERTY,
): SignatureFormat | null {
  const candidate = subject[signatureProperty];
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
 * Map a CycloneDxMajor enum value to the internal signature format
 * identifier. Exposed for callers that interoperate with lower-level
 * code that still thinks in format terms.
 */
export function cyclonedxFormat(version: CycloneDxMajor): SignatureFormat {
  return version === CycloneDxMajor.V2 ? 'jss' : 'jsf';
}

// -- Internal helpers --------------------------------------------------------

function detectCycloneDxMajor(
  subject: JsonObject,
  signatureProperty: string | undefined,
): CycloneDxMajor | null {
  const detected = detectFormat(subject, signatureProperty);
  if (detected === 'jss') return CycloneDxMajor.V2;
  if (detected === 'jsf') return CycloneDxMajor.V1;
  return null;
}
