/**
 * Typed error hierarchy for the JSF package.
 *
 * Callers can pattern-match on the class to tell a malformed envelope
 * apart from a cryptographic verify failure. All errors extend the base
 * JsfError so a single catch can trap everything the package throws.
 */

export class JsfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

/** Input did not satisfy the shape required by the current operation. */
export class JsfInputError extends JsfError {}

/** Canonicalization refused the input (for example a NaN number). */
export class JcsError extends JsfError {}

/** JWK conversion or material handling failed. */
export class JsfKeyError extends JsfError {}

/**
 * Envelope parsed but is not a valid JSF envelope (missing signer, value,
 * algorithm, multiple ambiguous forms, and so on).
 */
export class JsfEnvelopeError extends JsfError {}

/**
 * Signing primitive failed. Usually this wraps a Node crypto error such
 * as a mismatched key/algorithm pair.
 */
export class JsfSignError extends JsfError {
  override readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.cause = cause;
  }
}

/**
 * Verification failed for a non-cryptographic reason (for example the
 * algorithm was not on the allow-list). A returning VerifyResult with
 * valid=false is the normal signal for a cryptographic mismatch; this
 * class is reserved for configuration and input errors.
 */
export class JsfVerifyError extends JsfError {}
