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
 * JSF public API barrel.
 *
 * Import this module via the ./jsf subpath when you want to target JSF
 * explicitly:
 *
 *     import { sign, verify } from '@cyclonedx/sign/jsf';
 *
 * The top-level API (@cyclonedx/sign) re-exports from this module and
 * adds a CycloneDX-major-aware sign / verify helper on top.
 */

export {
  sign,
  verify,
  appendChainSigner,
  appendMultiSigner,
  computeCanonicalInputs,
} from './sign.js';

export {
  getAlgorithmSpec,
  isRegisteredAlgorithm,
  isAsymmetricAlgorithm,
  signBytes,
  verifyBytes,
  JsfAlgorithms,
  JSF_ASYMMETRIC_ALGORITHMS,
} from './algorithms.js';

export type {
  AlgorithmSpec,
  RsaPkcs1Spec,
  RsaPssSpec,
  EcdsaSpec,
  EddsaSpec,
  HmacSpec,
  JsfAsymmetricAlgorithm,
} from './algorithms.js';

export { JSF_BINDING, JsfBinding } from './binding.js';

export type {
  JsfAlgorithm,
  JsfAppendOptions,
  JsfCanonicalInputState,
  JsfSigner,
  JsfSignerInput,
  JsfSignerVerifyResult,
  JsfSignOptions,
  JsfVerifyOptions,
  JsfVerifyResult,
} from './types.js';
