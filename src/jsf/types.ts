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
 * JSF-specific type definitions.
 *
 * These cover the JSF 0.82 envelope and the sign / verify option shapes
 * for the JSF format. Shared types (JsonValue, JsonObject, JwkPublicKey,
 * KeyInput) live in ../types.ts and core types live in ../core/types.ts.
 */

import type { JsonObject, JsonValue, JwkPublicKey, KeyInput } from '../types.js';
import type { Signer } from '../core/signer.js';
import type { VerifyPolicy } from '../core/policy.js';
import type { JsfEnvelopeMode as EnvelopeMode } from './internal-types.js';

/**
 * JSF algorithm names. These match the JSF 0.82 specification and the
 * CycloneDX jsf-0.82 subschema enum exactly.
 */
export type JsfAlgorithm =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'Ed25519'
  | 'Ed448'
  | 'HS256'
  | 'HS384'
  | 'HS512';

/**
 * On-the-wire signaturecore object. Per JSF § 5: required `algorithm`
 * and `value`, optional `keyId`, `publicKey`, `certificatePath`, plus
 * (in single mode) the Global Signature Options `excludes` and
 * `extensions`, plus any application-specific extension property
 * values declared by `extensions`.
 */
export interface JsfSigner {
  algorithm: JsfAlgorithm;
  keyId?: string;
  publicKey?: JwkPublicKey;
  certificatePath?: string[];
  /** Single mode only. In multi/chain these live on the wrapper. */
  excludes?: string[];
  /** Single mode only. In multi/chain these live on the wrapper. */
  extensions?: string[];
  value: string;
  /** Application-defined extension properties named by `extensions`. */
  [extension: string]: JsonValue | string[] | JwkPublicKey | undefined;
}

/**
 * Per-signer input to `sign`. Either supply a private key (the library
 * builds a node-crypto-backed `Signer` internally) or a pre-built
 * `Signer` (for HSM / KMS / remote signers).
 */
export interface JsfSignerInput {
  algorithm: JsfAlgorithm;
  privateKey?: KeyInput;
  signer?: Signer;
  keyId?: string;
  /**
   * Public-key behaviour for the embedded `publicKey` field. Pass the
   * sentinel string `'auto'` (default) to derive from `privateKey`,
   * pass `false` to omit, or pass an explicit KeyInput to use that
   * value as the embedded JWK source. `'auto'` is a runtime sentinel,
   * not a separate type constituent (it is already a `string`).
   */
  publicKey?: KeyInput | false;
  certificatePath?: string[];
  /**
   * Per-signer extension property values. Keys must be a subset of
   * `JsfSignOptions.extensions`. Values are arbitrary JSON.
   */
  extensionValues?: Record<string, JsonValue>;
}

export interface JsfSignOptions {
  /** Sugar for `signers: [signer]` and `mode: 'single'`. */
  signer?: JsfSignerInput;
  /** One or more signers. Length 1 is single mode; >1 requires `mode`. */
  signers?: JsfSignerInput[];
  /**
   * Required when `signers.length > 1`. Determines the JSF wrapper.
   *   'multi' -> { signers: [...] }
   *   'chain' -> { chain:   [...] }
   * Must NOT be set when there is exactly one signer.
   */
  mode?: 'multi' | 'chain';

  /** Top-level payload property names to leave unsigned. */
  excludes?: string[];

  /**
   * Extension property names. Optional; if omitted the binding fills
   * it in as the union of every signer's `extensionValues` keys.
   * Names must not duplicate or collide with JSF reserved words.
   */
  extensions?: string[];

  /** Property name where the JSF object is attached. Default 'signature'. */
  signatureProperty?: string;
}

export interface JsfVerifyOptions {
  /**
   * Override the embedded public key for single-signer envelopes. For
   * multi/chain prefer `publicKeys` (per-signer override).
   */
  publicKey?: KeyInput;
  /** Map signer index -> verifying key. Falls back to embedded key. */
  publicKeys?: ReadonlyMap<number, KeyInput>;
  /** Property name where the JSF object lives. Default 'signature'. */
  signatureProperty?: string;
  /** Allow-list. Signers whose algorithm is not on the list fail. */
  allowedAlgorithms?: JsfAlgorithm[];
  /** Reject envelopes whose signers carry no embedded publicKey. */
  requireEmbeddedPublicKey?: boolean;
  /**
   * Aggregation for the top-level `valid`:
   *   'all' (default), 'any', { atLeast: n }.
   */
  policy?: VerifyPolicy;
  /**
   * If provided, reject envelopes whose `excludes` list contains a
   * name not on this allowlist. Spec-mandated by JSF § 5: "a
   * conforming JSF implementation must provide options for specifying
   * which properties to accept". Omit to accept any (lenient default).
   */
  allowedExcludes?: readonly string[];
  /**
   * If provided, reject envelopes whose `extensions` list contains a
   * name not on this allowlist. Spec-mandated by JSF § 5: "an option
   * to only accept predefined extension property names". Omit to
   * accept any (lenient default).
   */
  allowedExtensions?: readonly string[];
}

/**
 * JSF § 6 ("there must not be any not here defined properties inside
 * of the signature object") is enforced unconditionally on every
 * verify. Envelopes whose signaturecore or wrapper carries an
 * undeclared property fail verification with an envelope-level error
 * regardless of caller options.
 */

/** One signer's verification outcome. */
export interface JsfSignerVerifyResult {
  index: number;
  valid: boolean;
  algorithm: JsfAlgorithm | (string & {});
  keyId?: string;
  publicKey?: JwkPublicKey;
  certificatePath?: string[];
  extensionValues?: Record<string, JsonValue>;
  errors: string[];
}

export interface JsfVerifyResult {
  /** True iff per-signer outcomes satisfy `policy` AND no envelope-level error fired. */
  valid: boolean;
  mode: EnvelopeMode;
  /** Per-signer results, length 1 in single mode. */
  signers: JsfSignerVerifyResult[];
  /** Wrapper-level `excludes` if any. */
  excludes?: string[];
  /** Wrapper-level `extensions` if any. */
  extensions?: string[];
  /**
   * Envelope-level errors (allowedExcludes / allowedExtensions
   * violations, JSF § 6 property checks, malformed wrapper).
   * Per-signer cryptographic errors live on `signers[i].errors`.
   */
  errors: string[];
}

/** Append-options for `appendChainSigner` and `appendMultiSigner`. */
export interface JsfAppendOptions {
  signatureProperty?: string;
  /**
   * Per-signer verifying-key overrides used to verify the EXISTING
   * signers in the envelope before appending. Required when prior
   * signaturecore objects do not carry an embedded `publicKey` (e.g.
   * keyId-only envelopes).
   */
  publicKeys?: ReadonlyMap<number, KeyInput>;
  /**
   * Skip the verify-first defense. By default, append refuses to grow
   * an envelope it cannot verify, so a counter-signer never attests to
   * a tampered prior signer (CWE-345 / CWE-347 defense). Set this to
   * `true` only when the caller has already verified the envelope
   * out-of-band, or when the caller is the producer of the prior
   * signers. Default: `false`.
   */
  skipVerifyExisting?: boolean;
}

/** Pre-built state used by `computeCanonicalInputs`. */
export interface JsfCanonicalInputState {
  mode: EnvelopeMode;
  signers: Omit<JsfSigner, 'value'>[];
  excludes?: string[];
  extensions?: string[];
  /** Length must equal signers.length. True means signer i is finalized. */
  finalized: boolean[];
}

/**
 * Helper alias mirrored to `core/types.ts` so JSF callers do not need
 * to import from two places.
 */
export type { JsonObject, JsonValue, JwkPublicKey, KeyInput } from '../types.js';
