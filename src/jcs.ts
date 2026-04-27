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
 * JSON Canonicalization Scheme (JCS) per RFC 8785.
 *
 * Produces a deterministic byte sequence for any JSON value so two
 * correct implementations always yield the same bytes for the same
 * logical value. JSF uses JCS to decide exactly what bytes a signer
 * endorses, which lets any conforming verifier reproduce the input.
 *
 * Key RFC 8785 rules enforced here:
 *   - Object keys sorted by UTF-16 code unit (JavaScript string
 *     comparison is already UTF-16, so a direct < comparison is
 *     spec-compliant).
 *   - No insignificant whitespace. No trailing commas.
 *   - Number serialization per ES2019 NumberToString. JavaScript's
 *     own `String(n)` is that function, so `String` matches exactly
 *     for finite doubles. NaN, +Infinity, and -Infinity are rejected.
 *     Negative zero is normalized to the string "0".
 *   - Strings: UTF-16 surrogate pairs are preserved; U+0000..U+001F,
 *     U+0022 ("), and U+005C (\) are escaped. `\b \f \n \r \t` use
 *     the short forms; all other control codes use `\uXXXX` with
 *     lowercase hex. Non-ASCII characters (including U+2028 and
 *     U+2029) pass through literally as UTF-8 bytes.
 *   - Arrays retain their input order.
 *
 * The output is a UTF-8 byte sequence because JSF signs bytes, not
 * strings. Helpers expose both the Uint8Array form and a string form
 * for callers that want to inspect or log the canonical text.
 */

import type { JsonValue } from './types.js';
import { JcsError } from './errors.js';

const SHORT_ESCAPES: Record<number, string> = {
  0x08: '\\b',
  0x09: '\\t',
  0x0a: '\\n',
  0x0c: '\\f',
  0x0d: '\\r',
  0x22: '\\"',
  0x5c: '\\\\',
};

/**
 * Default maximum nesting depth. Pathologically deep JSON would cause
 * the recursive canonicalizer to overflow Node's default 1 MB stack at
 * roughly 10k levels. The cap is set well below that and well above
 * any realistic JSON envelope (CycloneDX BOMs in the wild stay under
 * a few dozen levels). Callers can override via `MaxDepthOptions`.
 *
 * Defends against CWE-674 / CWE-400: a verifier accepting an
 * attacker-supplied envelope with deeply nested data must not crash.
 */
const DEFAULT_MAX_DEPTH = 1000;

export interface MaxDepthOptions {
  /** Maximum nested JSON depth. Defaults to 1000. */
  maxDepth?: number;
}

/**
 * Canonicalize a JSON value into its UTF-8 byte sequence per RFC 8785.
 *
 * Throws JcsError for values JCS rejects (non-finite numbers,
 * undefined entries, non-string object keys, functions, and so on)
 * and for inputs that exceed `options.maxDepth` (default 1000).
 */
export function canonicalize(value: JsonValue, options?: MaxDepthOptions): Uint8Array {
  const text = canonicalizeToString(value, options);
  return new TextEncoder().encode(text);
}

/**
 * Canonicalize a JSON value and return the JCS text form. The result
 * is identical to passing `canonicalize()` through a UTF-8 decoder.
 */
export function canonicalizeToString(value: JsonValue, options?: MaxDepthOptions): string {
  const out: string[] = [];
  const maxDepth = options?.maxDepth ?? DEFAULT_MAX_DEPTH;
  if (!Number.isInteger(maxDepth) || maxDepth < 1) {
    throw new JcsError(`JCS maxDepth must be a positive integer; got ${String(maxDepth)}`);
  }
  writeValue(value, out, 0, maxDepth);
  return out.join('');
}

function writeValue(value: unknown, out: string[], depth: number, maxDepth: number): void {
  if (value === null) {
    out.push('null');
    return;
  }
  switch (typeof value) {
    case 'boolean':
      out.push(value ? 'true' : 'false');
      return;
    case 'number':
      writeNumber(value, out);
      return;
    case 'string':
      writeString(value, out);
      return;
    case 'object':
      if (depth >= maxDepth) {
        throw new JcsError(
          `JCS rejects input nested deeper than ${maxDepth} levels (DoS protection); ` +
            `pass { maxDepth: N } to canonicalize() to override`,
        );
      }
      if (Array.isArray(value)) {
        writeArray(value, out, depth + 1, maxDepth);
        return;
      }
      writeObject(value as Record<string, unknown>, out, depth + 1, maxDepth);
      return;
    default:
      throw new JcsError(`JCS cannot canonicalize a ${typeof value} value`);
  }
}

/**
 * Emit a JCS number literal using ES2019 NumberToString semantics.
 *
 * - NaN and Infinity are hard errors (RFC 8785 § 3.2.2.3).
 * - Negative zero is emitted as "0" (RFC 8785 § 3.2.2.3).
 * - All other finite values use `String(n)`, which V8 implements per
 *   the ES2019 algorithm used by JCS.
 */
function writeNumber(value: number, out: string[]): void {
  if (!Number.isFinite(value)) {
    throw new JcsError(`JCS rejects non-finite number: ${value}`);
  }
  if (value === 0) {
    // This handles both +0 and -0 deterministically.
    out.push('0');
    return;
  }
  out.push(String(value));
}

function writeString(value: string, out: string[]): void {
  out.push('"');
  // We walk the string code-unit-wise. The body pushes segments into
  // a buffer and flushes when an escape is produced. This keeps the
  // hot path (literal run) allocation-free.
  let runStart = 0;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (!needsEscape(code)) continue;
    if (i > runStart) out.push(value.slice(runStart, i));
    out.push(escapeFor(code));
    runStart = i + 1;
  }
  if (runStart < value.length) {
    out.push(value.slice(runStart));
  }
  out.push('"');
}

/** True if the given code unit must be JSON-escaped per RFC 8785. */
function needsEscape(code: number): boolean {
  return code < 0x20 || code === 0x22 || code === 0x5c;
}

/** Produce the JSON escape sequence for a code unit that needsEscape() flagged. */
function escapeFor(code: number): string {
  // eslint-disable-next-line security/detect-object-injection -- SHORT_ESCAPES is a static constant table; `code` is a numeric char code.
  const short = SHORT_ESCAPES[code];
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- SHORT_ESCAPES covers only a subset of code < 0x20, so a lookup miss is expected and must fall back to the \uXXXX form.
  if (short !== undefined) return short;
  return '\\u' + code.toString(16).padStart(4, '0');
}

function writeArray(value: unknown[], out: string[], depth: number, maxDepth: number): void {
  out.push('[');
  for (let i = 0; i < value.length; i += 1) {
    if (i > 0) {
      out.push(',');
    }
    // eslint-disable-next-line security/detect-object-injection -- `i` is a loop index bound by value.length on the array we were just given.
    const item = value[i];
    if (item === undefined) {
      // Matching JSON.stringify would emit null for a sparse slot,
      // but JCS inputs are not expected to be sparse. Make this an
      // explicit error so a caller's bug does not slip through.
      throw new JcsError(`JCS cannot canonicalize an array slot at index ${i} that is undefined`);
    }
    writeValue(item, out, depth, maxDepth);
  }
  out.push(']');
}

function writeObject(value: Record<string, unknown>, out: string[], depth: number, maxDepth: number): void {
  // RFC 8785 § 3.2.3: object members are sorted by the UTF-16 code
  // unit sequence of the property name. JS string comparison already
  // compares code units, so `localeCompare` would be wrong. Use the
  // default < ordering.
  const keys: string[] = [];
  for (const key of Object.keys(value)) {
    // eslint-disable-next-line security/detect-object-injection -- `key` came from Object.keys() of `value` on the previous line; it is a known own property.
    const v = value[key];
    if (v === undefined) {
      // Matching JSON.stringify would drop undefined values silently;
      // JCS does not define a behavior for them. We drop with no
      // warning to stay compatible with JSON.stringify callers, which
      // is the conventional posture in the reference implementation.
      continue;
    }
    keys.push(key);
  }
  keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  out.push('{');
  let first = true;
  for (const key of keys) {
    if (!first) {
      out.push(',');
    }
    first = false;
    writeString(key, out);
    out.push(':');
    // eslint-disable-next-line security/detect-object-injection -- `key` was sourced from Object.keys(value) above.
    writeValue(value[key], out, depth, maxDepth);
  }
  out.push('}');
}
