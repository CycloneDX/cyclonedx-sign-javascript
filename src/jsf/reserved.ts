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
 * JSF 0.82 reserved-word constants used for collision detection.
 *
 * Per JSF 0.82 § 5: "Extension names must not be duplicated or use any
 * of the JSF reserved words 'algorithm', 'certificatePath', 'chain',
 * 'extensions', 'excludes', 'keyId', 'publicKey', 'signers' or
 * 'value'."
 */

export const JSF_RESERVED_WORDS = [
  'algorithm',
  'certificatePath',
  'chain',
  'extensions',
  'excludes',
  'keyId',
  'publicKey',
  'signers',
  'value',
] as const;

export type JsfReservedWord = (typeof JSF_RESERVED_WORDS)[number];

const RESERVED_SET: ReadonlySet<string> = new Set<string>(JSF_RESERVED_WORDS);

export function isJsfReservedWord(name: string): name is JsfReservedWord {
  return RESERVED_SET.has(name);
}

/**
 * Fixed JSF-defined property names that may appear on a signaturecore.
 * Application-specific extension property names declared via the
 * envelope's `extensions` Global Signature Option are added on top of
 * this set when present.
 */
export const JSF_SIGNATURECORE_FIELDS = [
  'algorithm',
  'value',
  'keyId',
  'publicKey',
  'certificatePath',
] as const;

const CORE_FIELD_SET: ReadonlySet<string> = new Set<string>(JSF_SIGNATURECORE_FIELDS);

export function isJsfSignatureCoreField(name: string): boolean {
  return CORE_FIELD_SET.has(name);
}

/**
 * Property names a JSF wrapper (multisignature or signaturechain) may
 * carry. JSF § 6 validation rejects anything else.
 */
export const JSF_WRAPPER_FIELDS_MULTI = ['signers', 'excludes', 'extensions'] as const;
export const JSF_WRAPPER_FIELDS_CHAIN = ['chain', 'excludes', 'extensions'] as const;
