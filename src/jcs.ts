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
 * Canonicalize a JSON value into its UTF-8 byte sequence per RFC 8785.
 *
 * Throws JcsError for values JCS rejects (non-finite numbers,
 * undefined entries, non-string object keys, functions, and so on).
 */
export function canonicalize(value: JsonValue): Uint8Array {
  const text = canonicalizeToString(value);
  return new TextEncoder().encode(text);
}

/**
 * Canonicalize a JSON value and return the JCS text form. The result
 * is identical to passing `canonicalize()` through a UTF-8 decoder.
 */
export function canonicalizeToString(value: JsonValue): string {
  const out: string[] = [];
  writeValue(value, out);
  return out.join('');
}

function writeValue(value: unknown, out: string[]): void {
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
      if (Array.isArray(value)) {
        writeArray(value, out);
        return;
      }
      writeObject(value as Record<string, unknown>, out);
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
    if (code < 0x20 || code === 0x22 || code === 0x5c) {
      if (i > runStart) {
        out.push(value.slice(runStart, i));
      }
      // eslint-disable-next-line security/detect-object-injection -- SHORT_ESCAPES is a static constant table; `code` is a char code derived from a string just passed in.
      const short = SHORT_ESCAPES[code];
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- SHORT_ESCAPES covers only a subset of code < 0x20, so a lookup miss is expected and must fall back to the \uXXXX form.
      if (short !== undefined) {
        out.push(short);
      } else {
        out.push('\\u', code.toString(16).padStart(4, '0'));
      }
      runStart = i + 1;
    }
  }
  if (runStart < value.length) {
    out.push(value.slice(runStart));
  }
  out.push('"');
}

function writeArray(value: unknown[], out: string[]): void {
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
    writeValue(item, out);
  }
  out.push(']');
}

function writeObject(value: Record<string, unknown>, out: string[]): void {
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
    writeValue(value[key], out);
  }
  out.push('}');
}
