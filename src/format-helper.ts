/**
 * Format helper for sign and verify.
 *
 * Goal: give CycloneDX tool authors a single async sign() and verify()
 * that route to the right JSON signing format based on the CycloneDX
 * major version they target:
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
 *     - Dispatches to JSF when options.cyclonedxVersion is V1 or absent.
 *     - Dispatches to JSS when options.cyclonedxVersion is V2.
 *
 *   verify(subject, options?)
 *     - Uses options.cyclonedxVersion when provided.
 *     - Otherwise inspects the envelope via detectFormat() and maps
 *       the format back to a CycloneDxMajor value. JSF / V1 is the
 *       final fallback.
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
 * Top-level sign options, discriminated by `cyclonedxVersion`.
 */
export type SignOptions =
  | (JsfSignOptions & { cyclonedxVersion?: CycloneDxMajor.V1 })
  | (JssSignOptions & { cyclonedxVersion: CycloneDxMajor.V2 });

export type VerifyOptions =
  | (JsfVerifyOptions & { cyclonedxVersion?: CycloneDxMajor.V1 })
  | (JssVerifyOptions & { cyclonedxVersion: CycloneDxMajor.V2 });

export type VerifyResult =
  | (JsfVerifyResult & { cyclonedxVersion: CycloneDxMajor.V1 })
  | (JssVerifyResult & { cyclonedxVersion: CycloneDxMajor.V2 });

/**
 * Sign a JSON object for the given CycloneDX major version. Async
 * because remote signers (HSM, KMS) are async; the in-process
 * node-crypto path resolves on the same tick.
 */
export async function sign(subject: JsonObject, options: SignOptions): Promise<JsonObject> {
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
 * Verify a signed JSON object. Returns the format-specific result
 * shape with `cyclonedxVersion` attached for caller introspection.
 */
export async function verify(
  subject: JsonObject,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const version =
    options.cyclonedxVersion ??
    detectCycloneDxMajor(subject, options.signatureProperty) ??
    CycloneDxMajor.V1;
  switch (version) {
    case CycloneDxMajor.V1: {
      const result = await verifyJsf(subject, options as JsfVerifyOptions);
      return { ...result, cyclonedxVersion: CycloneDxMajor.V1 };
    }
    case CycloneDxMajor.V2: {
      const result = await verifyJss(subject, options as JssVerifyOptions);
      return { ...result, cyclonedxVersion: CycloneDxMajor.V2 };
    }
    default:
      throw new SignatureError(`Unknown CycloneDX major version: ${String(version)}`);
  }
}

/**
 * Inspect an envelope and guess which signature format produced it.
 * Returns null when the shape is ambiguous. JSF detects on the
 * presence of a signaturecore (algorithm + value), or a wrapper with
 * a `signers` or `chain` array. JSS detection is a placeholder until
 * X.590 specifies a distinctive marker.
 */
export function detectFormat(
  subject: JsonObject,
  signatureProperty: string = DEFAULT_SIGNATURE_PROPERTY,
): SignatureFormat | null {
  // eslint-disable-next-line security/detect-object-injection -- caller-controlled or default
  const candidate = subject[signatureProperty];
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return null;
  }
  const slot = candidate as Record<string, unknown>;

  // JSS detection placeholder.
  if (typeof slot.format === 'string' && slot.format.toLowerCase() === 'jss') {
    return 'jss';
  }

  // JSF: bare signaturecore.
  if (typeof slot.algorithm === 'string' && typeof slot.value === 'string') {
    return 'jsf';
  }

  // JSF: multisignature or signaturechain wrapper.
  if (Array.isArray(slot.signers) || Array.isArray(slot.chain)) {
    return 'jsf';
  }

  return null;
}

export function cyclonedxFormat(version: CycloneDxMajor): SignatureFormat {
  return version === CycloneDxMajor.V2 ? 'jss' : 'jsf';
}

function detectCycloneDxMajor(
  subject: JsonObject,
  signatureProperty: string | undefined,
): CycloneDxMajor | null {
  const detected = detectFormat(subject, signatureProperty);
  if (detected === 'jss') return CycloneDxMajor.V2;
  if (detected === 'jsf') return CycloneDxMajor.V1;
  return null;
}
