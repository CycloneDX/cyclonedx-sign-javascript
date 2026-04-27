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
 * JSS public API barrel (ITU-T X.590, 10/2023).
 *
 * Import this module via the ./jss subpath when you want to target
 * JSS explicitly:
 *
 *     import { sign, verify, countersign } from '@cyclonedx/sign/jss';
 *
 * The top-level API (@cyclonedx/sign) routes by `cyclonedxVersion`
 * (V2 -> JSS).
 */

export { sign, verify, countersign, computeCanonicalInputs } from './sign.js';
export { JSS_BINDING, JssBinding } from './binding.js';
export {
  isRegisteredAlgorithm as isRegisteredJssAlgorithm,
  signHash as signJssHash,
  verifyHash as verifyJssHash,
  JssAlgorithms,
} from './algorithms.js';
export {
  isRegisteredHashAlgorithm as isRegisteredJssHashAlgorithm,
  hashBytes as jssHashBytes,
  JssHashAlgorithms,
} from './hash.js';
export {
  publicKeyFromPemBody,
  pemBodyFromPublicKey,
  privateKeyFromPem,
} from './pem.js';

export type {
  JssAlgorithm,
  JssHashAlgorithm,
  JssSigner,
  JssSignerInput,
  JssSignerVerifyResult,
  JssSignOptions,
  JssCountersignOptions,
  JssVerifyOptions,
  JssVerifyResult,
} from './types.js';
