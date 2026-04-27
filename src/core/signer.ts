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
 * Cross-format signing primitives.
 *
 * `Signer` and `Verifier` are the contract that HSM, KMS, and any
 * other out-of-process or remote signing implementation satisfies.
 * The contract is intentionally small: bytes in, bytes out, async.
 *
 * The format binding (JSF or JSS) decides what bytes to pass:
 *
 *   - JSF passes the JCS canonical bytes directly. The Signer is
 *     expected to hash and sign per the algorithm name (e.g. RS256
 *     hashes with SHA-256 internally).
 *   - JSS pre-hashes the canonical bytes per the signaturecore's
 *     `hash_algorithm` and passes the digest. The Signer signs the
 *     digest without further hashing.
 *
 * A given HSM adapter typically picks one mode at construction time
 * (e.g., "RSA-PKCS1 with internal SHA-256" vs "RSA raw"). The Signer
 * itself does not need to know which format is invoking it; it just
 * signs the bytes given.
 */

export interface Signer {
  /**
   * Sign the supplied bytes. Returns the raw signature bytes (no
   * base64 / encoding wrapper).
   */
  sign(bytes: Uint8Array): Promise<Uint8Array>;
}

export interface Verifier {
  /** Verify the supplied signature over the supplied bytes. */
  verify(bytes: Uint8Array, signature: Uint8Array): Promise<boolean>;
}
