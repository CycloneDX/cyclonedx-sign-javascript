/**
 * Typed error hierarchy for the @cyclonedx/sign package.
 *
 * The hierarchy is rooted at SignatureError so callers can trap
 * everything the package throws with a single catch. JSF and JSS each
 * get their own subtree under it, and JCS (shared by both formats)
 * sits beside them rather than inside either.
 *
 *     SignatureError
 *       ├── JsfError
 *       │     ├── JsfInputError
 *       │     ├── JsfKeyError
 *       │     ├── JsfEnvelopeError
 *       │     ├── JsfSignError
 *       │     └── JsfVerifyError
 *       ├── JssError
 *       │     └── JssNotImplementedError
 *       └── JcsError
 */

/** Root of the package error hierarchy. */
export class SignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

/** Canonicalization refused the input (for example a NaN number). */
export class JcsError extends SignatureError {}

// -- JSF ---------------------------------------------------------------------

/** Root of the JSF-specific error subtree. */
export class JsfError extends SignatureError {}

/** Input did not satisfy the shape required by the current operation. */
export class JsfInputError extends JsfError {}

/** JWK conversion or material handling failed. */
export class JsfKeyError extends JsfError {}

/**
 * Envelope parsed but is not a valid JSF envelope (missing signer, value,
 * algorithm, multiple ambiguous forms, and so on).
 */
export class JsfEnvelopeError extends JsfError {}

/**
 * Signing primitive failed. Usually this wraps a Node crypto error such
 * as a mismatched key or algorithm pair.
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

// -- JSS ---------------------------------------------------------------------

/** Root of the JSS-specific error subtree. */
export class JssError extends SignatureError {}

/**
 * Thrown when a JSS code path is invoked but the underlying support is
 * still a stub. This allows callers to start wiring against the API
 * surface today while JSS implementation work continues.
 */
export class JssNotImplementedError extends JssError {
  constructor(message = 'JSS (X.590) support is not yet implemented in this build') {
    super(message);
  }
}

/** Input did not satisfy the shape required for a JSS operation. */
export class JssInputError extends JssError {}

/** JSS envelope could not be parsed or is missing required fields. */
export class JssEnvelopeError extends JssError {}
