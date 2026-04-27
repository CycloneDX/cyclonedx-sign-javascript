/*!
This file is part of CycloneDX Signing Library for Javascript.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
Copyright (c) OWASP Foundation. All Rights Reserved.
*/

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

/**
 * Caller passed a malformed multi or chain signer input — empty
 * `signers` array, both `signer` and `signers` provided, `mode` set
 * with a single signer, or the like.
 */
export class JsfMultiSignerInputError extends JsfInputError {}

/**
 * Append-on-chain refused because the source envelope is not in chain
 * mode (or, for `appendMultiSigner`, not in multi mode). Promoting
 * across modes is not lossless because canonical bytes change with
 * the wrapper shape.
 */
export class JsfChainOrderError extends JsfEnvelopeError {}

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
