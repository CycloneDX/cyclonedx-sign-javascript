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
 * Per-signer verify-result aggregation policy.
 *
 * Both JSF (multi, chain) and JSS (multi, counter) produce per-signer
 * outcomes that the caller may want to aggregate to a single
 * top-level boolean. The three policies match common deployment
 * needs:
 *
 *   - 'all' (default): every signer must verify. Safe for chain
 *     envelopes (sequential commitment) and for document-level BOM
 *     signatures where every signatory must be valid.
 *   - 'any': at least one signer must verify.
 *   - { atLeast: n }: at least n signers must verify.
 */

export type VerifyPolicy = 'all' | 'any' | { atLeast: number };

/**
 * Apply a policy to a flat array of per-signer booleans.
 *
 * Format bindings call this after collecting per-signer outcomes;
 * keeping the helper here keeps the aggregation rule consistent
 * across formats.
 */
export function applyPolicy(outcomes: readonly boolean[], policy: VerifyPolicy): boolean {
  const ok = outcomes.filter(Boolean).length;
  if (policy === 'all') return ok === outcomes.length;
  if (policy === 'any') return ok >= 1;
  return ok >= policy.atLeast;
}
