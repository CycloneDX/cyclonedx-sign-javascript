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
 * JSF-internal binding seam.
 *
 * The orchestrator (`./orchestrate.ts`) never speaks JSF wire-format
 * directly; it goes through this adapter. Internal to the JSF
 * subpackage; not exported through the public API.
 */

import type { JsonObject, JsonValue, JwkPublicKey, KeyInput } from '../types.js';
import type { Signer, Verifier } from '../core/signer.js';
import type {
  JsfEnvelopeOptions,
  JsfEnvelopeView,
  JsfSignerDescriptor,
  JsfWrapperState,
} from './internal-types.js';

/** Fields the binding needs to construct a `Signer`. */
export interface JsfSignerKeyInput {
  algorithm: string;
  privateKey?: KeyInput;
  /** Pre-built signer (HSM, KMS, remote). Wins over `privateKey`. */
  signer?: Signer;
  publicKey?: KeyInput | false;
  keyId?: string;
  certificatePath?: string[];
  extensionValues?: Record<string, JsonValue>;
}

/** Fields the binding needs to construct a `Verifier`. */
export interface JsfVerifierKeyInput {
  algorithm: string;
  publicKey?: KeyInput;
  embeddedPublicKey?: JwkPublicKey;
  certificatePath?: string[];
}

/**
 * The orchestrator-level seam. The single concrete implementation is
 * `JsfBinding` in `./binding.ts`.
 */
export interface JsfBindingContract {
  detect(payload: JsonObject, signatureProperty: string): JsfEnvelopeView | null;
  buildCanonicalView(
    payload: JsonObject,
    state: JsfWrapperState,
    index: number,
    signatureProperty: string,
  ): JsonObject;
  emit(payload: JsonObject, state: JsfWrapperState, signatureProperty: string): JsonObject;
  toSigner(input: JsfSignerKeyInput): Signer;
  toVerifier(input: JsfVerifierKeyInput): Verifier;
  resolveEmbeddedPublicKey(input: JsfSignerKeyInput): JwkPublicKey | null;
  descriptorFromWire(core: JsonObject, options: JsfEnvelopeOptions): JsfSignerDescriptor;
}
