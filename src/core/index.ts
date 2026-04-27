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
 * Format-agnostic core. Exposes the small, cross-format surface that
 * HSM, KMS, and remote-signer adapters target. Everything else
 * (envelope shapes, validation rules, descriptor models, format
 * orchestration) lives next to the format that owns it: see
 * `src/jsf/` and `src/jss/`.
 */

export type { Signer, Verifier } from './signer.js';
export { applyPolicy } from './policy.js';
export type { VerifyPolicy } from './policy.js';
