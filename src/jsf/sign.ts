/**
 * JSF 0.82 sign and verify orchestration.
 *
 * See https://cyberphone.github.io/doc/security/jsf.html for the
 * authored specification, and the CycloneDX jsf-0.82 subschema for the
 * envelope grammar this module targets. Both versions agree on the
 * canonicalization and sign mechanics this module implements.
 *
 * Signing protocol (simple signatures, `signaturecore`):
 *   1. Build the signer object with algorithm and any optional
 *      metadata (keyId, publicKey, certificatePath, excludes). Do
 *      NOT set `value` yet.
 *   2. Attach the signer under `payload[signatureProperty]` (default
 *      property name: "signature").
 *   3. If the signer specifies an `excludes` array, remove those
 *      top-level properties from the payload before canonicalizing.
 *      Per JSF § 3.4, the `excludes` property name itself is added
 *      to the exclusion set automatically — the excluded data and
 *      the excludes list are both unsigned.
 *   4. Canonicalize the payload plus signer object using JCS.
 *   5. Sign the canonical bytes using the algorithm.
 *   6. Add the base64url-encoded signature under `signer.value`.
 *   7. Return the original payload plus the completed signer.
 *
 * Verification reverses the process:
 *   1. Extract the signer object from `payload[signatureProperty]`.
 *   2. Remove `value` from the signer.
 *   3. Apply the excludes list to strip unsigned top-level fields.
 *   4. Canonicalize.
 *   5. Verify the signature bytes against the canonical payload and
 *      the (embedded or override) public key.
 */

import { canonicalize } from '../jcs.js';
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
import {
  decodeBase64Url,
  encodeBase64Url,
} from '../base64url.js';
import {
  JsfEnvelopeError,
  JsfInputError,
  JsfVerifyError,
} from '../errors.js';
import type {
  JsonObject,
  JsonValue,
  JwkPublicKey,
  KeyInput,
} from '../types.js';
import type {
  JsfSigner,
  JsfSignOptions,
  JsfVerifyOptions,
  JsfVerifyResult,
} from './types.js';

const DEFAULT_SIGNATURE_PROPERTY = 'signature';

/**
 * Produce a JSF-signed object. The returned object is the original
 * payload with `[signatureProperty]` set to the completed signer.
 *
 * The input payload is not mutated.
 */
export function sign(payload: JsonObject, options: JsfSignOptions): JsonObject {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers that bypass the JsonObject declared type.
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new JsfInputError('JSF sign requires a JSON object payload');
  }
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers that pass null or a non-object in place of options.
  if (!options || typeof options !== 'object') {
    throw new JsfInputError('JSF sign requires an options object');
  }
  if (!isRegisteredAlgorithm(options.algorithm)) {
    throw new JsfInputError(`Unsupported algorithm: ${options.algorithm as string}`);
  }

  const signatureProperty = options.signatureProperty ?? DEFAULT_SIGNATURE_PROPERTY;

  if (signatureProperty in payload) {
    throw new JsfInputError(
      `Payload already has a "${signatureProperty}" property; refusing to overwrite`,
    );
  }

  const spec = getAlgorithmSpec(options.algorithm);
  const { keyObject: privateKeyObject, curve: privateCurve } = toPrivateKey(options.privateKey);

  // Construct the signer metadata (without value). Order in this
  // literal is irrelevant because JCS re-sorts keys by code unit.
  const signer: JsfSigner = {
    algorithm: options.algorithm,
    value: '', // placeholder; removed for canonicalization
  };
  if (options.keyId !== undefined) {
    if (typeof options.keyId !== 'string' || options.keyId.length === 0) {
      throw new JsfInputError('keyId must be a non-empty string when provided');
    }
    signer.keyId = options.keyId;
  }
  if (options.certificatePath !== undefined) {
    if (!Array.isArray(options.certificatePath) || options.certificatePath.length === 0) {
      throw new JsfInputError('certificatePath must be a non-empty array when provided');
    }
    signer.certificatePath = [...options.certificatePath];
  }
  if (options.excludes !== undefined) {
    if (!Array.isArray(options.excludes)) {
      throw new JsfInputError('excludes must be an array when provided');
    }
    signer.excludes = [...options.excludes];
  }

  // Decide whether to embed a publicKey. HMAC envelopes never embed.
  const embedPublicKey = resolveEmbeddedPublicKey(options, spec.family);
  if (embedPublicKey) {
    signer.publicKey = embedPublicKey;
  }

  // Compose the view of the payload that will be signed.
  const toSign = buildCanonicalView(payload, signer, signatureProperty);
  const canonicalBytes = canonicalize(toSign);

  const signatureBytes = signBytes(spec, canonicalBytes, privateKeyObject, privateCurve);
  signer.value = encodeBase64Url(signatureBytes);

  // Emit a fresh object so the caller's payload stays untouched.
  const output: JsonObject = { ...payload };
  // eslint-disable-next-line security/detect-object-injection -- `signatureProperty` is the documented target field and defaults to the "signature" literal.
  output[signatureProperty] = orderedSigner(signer) as unknown as JsonValue;
  return output;
}

/**
 * Verify a JSF-signed object.
 *
 * Returns a structured result with valid=false when the signature does
 * not verify or does not match the configured constraints. Throws
 * (JsfEnvelopeError / JsfInputError / JsfVerifyError) only for caller
 * bugs, never for cryptographic failures.
 */
export function verify(payload: JsonObject, options: JsfVerifyOptions = {}): JsfVerifyResult {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- runtime guard against JS callers that bypass the JsonObject declared type.
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new JsfInputError('JSF verify requires a JSON object payload');
  }

  const signatureProperty = options.signatureProperty ?? DEFAULT_SIGNATURE_PROPERTY;
  // eslint-disable-next-line security/detect-object-injection -- `signatureProperty` is the documented signer location and defaults to the "signature" literal.
  const signerAny = payload[signatureProperty];
  if (signerAny === undefined) {
    throw new JsfEnvelopeError(`Payload has no "${signatureProperty}" property`);
  }
  if (signerAny === null || Array.isArray(signerAny) || typeof signerAny !== 'object') {
    throw new JsfEnvelopeError(`"${signatureProperty}" property must be a signer object`);
  }
  const signer = signerAny as unknown as JsfSigner;

  const result: JsfVerifyResult = { valid: false, errors: [] };

  if (typeof signer.algorithm !== 'string' || signer.algorithm.length === 0) {
    throw new JsfEnvelopeError('signer is missing algorithm');
  }
  if (typeof signer.value !== 'string' || signer.value.length === 0) {
    throw new JsfEnvelopeError('signer is missing value');
  }
  result.algorithm = signer.algorithm;
  if (signer.keyId !== undefined) result.keyId = signer.keyId;
  if (signer.publicKey !== undefined) result.publicKey = signer.publicKey;
  if (signer.certificatePath !== undefined) result.certificatePath = [...signer.certificatePath];
  if (signer.excludes !== undefined) result.excludes = [...signer.excludes];

  if (options.allowedAlgorithms && !options.allowedAlgorithms.includes(signer.algorithm)) {
    result.errors.push(`algorithm ${signer.algorithm} is not on the allow-list`);
    return result;
  }

  if (!isRegisteredAlgorithm(signer.algorithm)) {
    result.errors.push(`unsupported algorithm ${signer.algorithm}`);
    return result;
  }
  const spec = getAlgorithmSpec(signer.algorithm);

  if (options.requireEmbeddedPublicKey && !signer.publicKey) {
    result.errors.push('signer is missing an embedded publicKey');
    return result;
  }

  const verifyingKeyInput = resolveVerifyingKey(signer, options, spec.family);
  if (!verifyingKeyInput) {
    throw new JsfVerifyError(
      'No public key available: provide options.publicKey or include signer.publicKey',
    );
  }

  const { keyObject, curve } = toPublicKey(verifyingKeyInput);

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = decodeBase64Url(signer.value);
  } catch (err) {
    result.errors.push(`malformed signature value: ${(err as Error).message}`);
    return result;
  }

  const toVerify = buildCanonicalView(payload, signer, signatureProperty);
  const canonicalBytes = canonicalize(toVerify);

  const valid = verifyBytes(spec, canonicalBytes, signatureBytes, keyObject, curve);
  if (!valid) {
    result.errors.push('signature did not verify');
    return result;
  }

  result.valid = true;
  return result;
}

/**
 * Produce the canonical byte input for a given payload plus signer.
 * Useful when callers need to pre-compute the bytes that will be
 * signed (for example to display a hash, or to support a two-phase
 * signing flow where the private key lives on a client).
 *
 * The signer argument is used to determine `excludes`; the signer
 * object itself is attached under signatureProperty minus `value`.
 */
export function computeCanonicalInput(
  payload: JsonObject,
  signer: Omit<JsfSigner, 'value'> & { value?: string },
  signatureProperty: string = DEFAULT_SIGNATURE_PROPERTY,
): Uint8Array {
  const minus: JsfSigner = { ...signer, value: '' };
  const toCanonicalize = buildCanonicalView(payload, minus, signatureProperty);
  return canonicalize(toCanonicalize);
}

// -- Helpers -----------------------------------------------------------------

function resolveEmbeddedPublicKey(
  options: JsfSignOptions,
  family: 'rsa-pkcs1' | 'rsa-pss' | 'ecdsa' | 'eddsa' | 'hmac',
): JwkPublicKey | null {
  if (family === 'hmac') {
    // HMAC is symmetric. Embedding the key would leak the secret, so
    // we always omit. Callers who want to include a key hint can fall
    // back to `keyId`.
    return null;
  }

  if (options.publicKey === false) {
    return null;
  }

  if (options.publicKey === undefined || options.publicKey === 'auto') {
    return exportPublicJwk(options.privateKey);
  }

  return exportPublicJwk(options.publicKey as KeyInput);
}

function resolveVerifyingKey(
  signer: JsfSigner,
  options: JsfVerifyOptions,
  family: 'rsa-pkcs1' | 'rsa-pss' | 'ecdsa' | 'eddsa' | 'hmac',
): KeyInput | null {
  if (options.publicKey !== undefined) {
    return options.publicKey;
  }
  if (family === 'hmac') {
    // HMAC requires an explicit key input because the envelope never
    // carries one.
    return null;
  }
  if (signer.publicKey) {
    return signer.publicKey;
  }
  return null;
}

/**
 * Build the exact object that JCS sees during sign or verify.
 *
 * Steps:
 *   - Strip the signer.value field.
 *   - Apply the signer's `excludes` list (plus the implicit exclusion
 *     of `excludes` itself).
 *   - Attach the trimmed signer under the configured property.
 */
function buildCanonicalView(
  payload: JsonObject,
  signer: JsfSigner,
  signatureProperty: string,
): JsonObject {
  const baseSigner = stripValue(signer);

  // Build the excludes set: the signer's explicit list plus the
  // implicit entry for the `excludes` property itself.
  const excluded = new Set<string>();
  if (baseSigner.excludes) {
    for (const name of baseSigner.excludes) {
      if (typeof name !== 'string' || name.length === 0) continue;
      excluded.add(name);
    }
  }

  const view: JsonObject = {};
  for (const key of Object.keys(payload)) {
    if (excluded.has(key)) continue;
    if (key === signatureProperty) continue;
    // eslint-disable-next-line security/detect-object-injection -- `key` came from Object.keys(payload) above; copying the payload's own entries into the canonical view.
    view[key] = payload[key] as JsonValue;
  }
  // eslint-disable-next-line security/detect-object-injection -- `signatureProperty` is the documented signer location and defaults to "signature".
  view[signatureProperty] = baseSigner as unknown as JsonValue;
  return view;
}

function stripValue(signer: JsfSigner): Omit<JsfSigner, 'value'> {
  const out: Omit<JsfSigner, 'value'> = { algorithm: signer.algorithm };
  if (signer.keyId !== undefined) out.keyId = signer.keyId;
  if (signer.publicKey !== undefined) out.publicKey = signer.publicKey;
  if (signer.certificatePath !== undefined) out.certificatePath = signer.certificatePath;
  if (signer.excludes !== undefined) out.excludes = signer.excludes;
  return out;
}

/**
 * Return a signer object with stable property ordering for output.
 * JSF does not require any specific order because consumers
 * re-canonicalize, but a predictable JSON.stringify output is
 * convenient for logs and for humans diffing envelopes.
 */
function orderedSigner(signer: JsfSigner): JsfSigner {
  const out: JsfSigner = { algorithm: signer.algorithm, value: signer.value };
  if (signer.keyId !== undefined) out.keyId = signer.keyId;
  if (signer.publicKey !== undefined) out.publicKey = signer.publicKey;
  if (signer.certificatePath !== undefined) out.certificatePath = signer.certificatePath;
  if (signer.excludes !== undefined) out.excludes = signer.excludes;
  return out;
}
