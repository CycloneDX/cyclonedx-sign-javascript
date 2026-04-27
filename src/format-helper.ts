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
 *     - Requires options.cyclonedxVersion. Throws if missing or unknown.
 *     - There is no default; the caller must declare which CycloneDX
 *       major version they are producing so the right format is used.
 *
 *   verify(subject, options?)
 *     - Uses options.cyclonedxVersion when provided.
 *     - Otherwise inspects the envelope via detectFormat() and maps
 *       the format back to a CycloneDxMajor value.
 *     - Throws if neither path can determine the format. There is no
 *       silent default to JSF / V1.
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
 * Top-level sign options, discriminated by `cyclonedxVersion`. The
 * version is required: callers must declare whether they are producing
 * a CycloneDX 1.x (JSF) or 2.x (JSS) envelope. There is no default.
 */
export type SignOptions =
  | (JsfSignOptions & { cyclonedxVersion: CycloneDxMajor.V1 })
  | (JssSignOptions & { cyclonedxVersion: CycloneDxMajor.V2 });

/**
 * Top-level verify options. `cyclonedxVersion` is optional because the
 * envelope shape is normally distinctive enough to detect; if detection
 * is ambiguous, verify throws. There is no silent default to V1.
 */
export type VerifyOptions =
  | (JsfVerifyOptions & { cyclonedxVersion?: CycloneDxMajor.V1 })
  | (JssVerifyOptions & { cyclonedxVersion?: CycloneDxMajor.V2 });

export type VerifyResult =
  | (JsfVerifyResult & { cyclonedxVersion: CycloneDxMajor.V1 })
  | (JssVerifyResult & { cyclonedxVersion: CycloneDxMajor.V2 });

/**
 * Sign a JSON object for the given CycloneDX major version. Async
 * because remote signers (HSM, KMS) are async; the in-process
 * node-crypto path resolves on the same tick.
 *
 * `options.cyclonedxVersion` is required. There is no default: the
 * caller must explicitly declare whether the produced envelope targets
 * CycloneDX 1.x (JSF) or 2.x (JSS).
 */
export async function sign(subject: JsonObject, options: SignOptions): Promise<JsonObject> {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard for JS callers; the type system already forbids omitting cyclonedxVersion.
  if (!options || options.cyclonedxVersion === undefined) {
    throw new SignatureError(
      'sign() requires options.cyclonedxVersion. ' +
        'Set it to CycloneDxMajor.V1 (JSF, CycloneDX 1.x) or CycloneDxMajor.V2 (JSS, CycloneDX 2.x).',
    );
  }
  const version = options.cyclonedxVersion as CycloneDxMajor;
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
 *
 * `options.cyclonedxVersion` is optional: when omitted, the format is
 * auto-detected from the envelope shape (JSF vs JSS). If neither the
 * caller nor detection can determine the version, verify throws.
 * There is no silent default to V1.
 */
export async function verify(
  subject: JsonObject,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const version =
    options.cyclonedxVersion ??
    detectCycloneDxMajor(subject, options.signatureProperty);
  // detectCycloneDxMajor returns null on miss; cover both null and undefined.
  if (version === null || version === undefined) {
    throw new SignatureError(
      'verify() could not determine the CycloneDX major version from the envelope shape. ' +
        'Set options.cyclonedxVersion to CycloneDxMajor.V1 (JSF) or CycloneDxMajor.V2 (JSS) explicitly.',
    );
  }
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

/**
 * JSS uses a JSON array under the signature property (default
 * `signatures`, plural). We detect on the array shape with at least
 * one element carrying `algorithm` + `hash_algorithm` + `value`.
 *
 * Detection runs separately from `detectFormat` because JSS uses a
 * different default signature property name. Callers can pass
 * `signatureProperty: 'signatures'` to detectFormat() to find a JSS
 * envelope at the standard location.
 */
function detectJss(payload: JsonObject, signatureProperty: string): boolean {
  // eslint-disable-next-line security/detect-object-injection -- caller-controlled or default
  const slot = payload[signatureProperty];
  if (!Array.isArray(slot) || slot.length === 0) return false;
  const first = slot[0] as Record<string, unknown> | undefined;
  if (!first || typeof first !== 'object' || Array.isArray(first)) return false;
  return (
    typeof first.algorithm === 'string' &&
    typeof first.hash_algorithm === 'string' &&
    typeof first.value === 'string'
  );
}

export function cyclonedxFormat(version: CycloneDxMajor): SignatureFormat {
  return version === CycloneDxMajor.V2 ? 'jss' : 'jsf';
}

function detectCycloneDxMajor(
  subject: JsonObject,
  signatureProperty: string | undefined,
): CycloneDxMajor | null {
  const prop = signatureProperty ?? DEFAULT_SIGNATURE_PROPERTY;
  // JSS shape (array under `signatures` by default) wins ahead of
  // generic JSF detection because the structures are mutually
  // exclusive (JSF wrappers carry `signers`/`chain` properties; JSS
  // uses an array directly).
  if (detectJss(subject, 'signatures')) return CycloneDxMajor.V2;
  if (detectJss(subject, prop)) return CycloneDxMajor.V2;
  const detected = detectFormat(subject, prop);
  if (detected === 'jss') return CycloneDxMajor.V2;
  if (detected === 'jsf') return CycloneDxMajor.V1;
  return null;
}
