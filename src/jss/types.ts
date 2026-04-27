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
 * JSS public type surface (ITU-T X.590, 10/2023).
 *
 * Mirrors the JSF types where possible so callers using both formats
 * see a similar shape. Differences from JSF reflect spec differences:
 * `signatures` is always a top-level array; `hash_algorithm` is an
 * explicit field; public keys are PEM bodies (no JWK); custom
 * metadata is allowed on the signaturecore (X.590 § 6.3).
 */

import type { JsonObject, JsonValue, KeyInput } from '../types.js';
import type { Signer } from '../core/signer.js';
import type { VerifyPolicy } from '../core/policy.js';
import type { JssHashAlgorithm } from './hash.js';
import type { JssAlgorithm } from './algorithms.js';

export type { JssAlgorithm } from './algorithms.js';
export type { JssHashAlgorithm } from './hash.js';

/**
 * On-the-wire JSS signaturecore. Per X.590 § 6.2.1 plus § 6.3.1
 * notional metadata fields. Custom metadata properties are allowed
 * and round-trip through the binding.
 */
export interface JssSigner {
  hash_algorithm: JssHashAlgorithm | (string & {});
  algorithm: JssAlgorithm | (string & {});
  public_key?: string;
  public_cert_chain?: string[];
  cert_url?: string;
  thumbprint?: string;
  value: string;
  signature?: JssSigner;
  // Custom metadata properties (X.590 § 6.3) are allowed; not all are
  // listed here. `[k: string]: ...` is intentionally permissive.
  [extension: string]: JsonValue | string | string[] | JssSigner | undefined;
}

/**
 * Per-signer input to `sign`. Either supply a private key (the binding
 * builds an in-process Signer) or a pre-built `Signer` (HSM/KMS).
 */
export interface JssSignerInput {
  algorithm: JssAlgorithm;
  /** Default 'sha-256'. */
  hash_algorithm?: JssHashAlgorithm;
  privateKey?: KeyInput;
  signer?: Signer;
  /**
   * Public-key behaviour for the embedded `public_key` field.
   *   'auto' (default) derives the PEM body from `privateKey`.
   *   `false` omits.
   *   An explicit KeyInput uses that value as the embedded source.
   */
  // eslint-disable-next-line @typescript-eslint/no-redundant-type-constituents -- 'auto' is a documented sentinel string.
  public_key?: KeyInput | false | 'auto';
  public_cert_chain?: string[];
  cert_url?: string;
  thumbprint?: string;
  /** Custom metadata properties to embed alongside JSS-defined fields. */
  metadata?: Record<string, JsonValue>;
}

export interface JssSignOptions {
  /** Sugar for `signers: [signer]`. */
  signer?: JssSignerInput;
  /** One or more signers (X.590 multi-signature is independent per § 7.1). */
  signers?: JssSignerInput[];
  /** Property name where the signatures array is attached. Default 'signatures'. */
  signatureProperty?: string;
}

export interface JssCountersignOptions {
  /** Index of the existing signaturecore to be counter signed. Default: last. */
  targetIndex?: number;
  /** The new signer being added as a nested `signature` property. */
  signer: JssSignerInput;
  signatureProperty?: string;
  /**
   * Per-signer verifying-key overrides used to verify the EXISTING
   * signers in the envelope before counter signing. Required when
   * prior signaturecores omit embedded key material.
   */
  publicKeys?: ReadonlyMap<number, KeyInput>;
  /**
   * Skip the verify-first defense (CWE-345 / CWE-347). By default
   * counter signing refuses to grow an envelope it cannot verify.
   */
  skipVerifyExisting?: boolean;
}

export interface JssVerifyOptions {
  /** Override the embedded key for single-signer envelopes. */
  publicKey?: KeyInput;
  /** Map signer index -> verifying key. */
  publicKeys?: ReadonlyMap<number, KeyInput>;
  signatureProperty?: string;
  allowedAlgorithms?: (JssAlgorithm | (string & {}))[];
  allowedHashAlgorithms?: (JssHashAlgorithm | (string & {}))[];
  /** Reject envelopes whose signers carry no embedded key material. */
  requireEmbeddedKeyMaterial?: boolean;
  /**
   * Aggregation for the top-level `valid`:
   *   'all' (default), 'any', { atLeast: n }.
   */
  policy?: VerifyPolicy;
  /**
   * If true, also verify each nested counter signature recursively.
   * Default false.
   */
  verifyCounterSignatures?: boolean;
}

export interface JssSignerVerifyResult {
  index: number;
  valid: boolean;
  algorithm: JssAlgorithm | (string & {});
  hash_algorithm: JssHashAlgorithm | (string & {});
  public_key?: string;
  public_cert_chain?: string[];
  cert_url?: string;
  thumbprint?: string;
  metadata?: Record<string, JsonValue>;
  countersignature?: JssSignerVerifyResult;
  errors: string[];
}

export interface JssVerifyResult {
  valid: boolean;
  signers: JssSignerVerifyResult[];
  errors: string[];
}

export type { JsonObject };
