/**
 * JCS conformance tests. The vectors below mirror the examples given
 * in RFC 8785 § 3.2 and Appendix B, plus a handful of additional
 * cases covering the edges JSF care about most (key sorting, control
 * character escapes, number rendering).
 */

import { describe, it, expect } from 'vitest';
import { canonicalize, canonicalizeToString } from '../src/jcs.js';
import { JcsError } from '../src/errors.js';

function text(value: unknown): string {
  return canonicalizeToString(value as Parameters<typeof canonicalize>[0]);
}

describe('JCS', () => {
  describe('objects', () => {
    it('sorts top-level keys by code unit', () => {
      expect(text({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    });

    it('sorts nested object keys', () => {
      expect(text({ outer: { z: 1, a: 2 } })).toBe('{"outer":{"a":2,"z":1}}');
    });

    it('uses code-unit order, not locale', () => {
      // "a" (U+0061) < "B" (U+0042)? No — U+0042 is less than U+0061.
      // A locale-aware sort would often put "a" before "B".
      expect(text({ a: 1, B: 2 })).toBe('{"B":2,"a":1}');
    });

    it('handles empty objects', () => {
      expect(text({})).toBe('{}');
    });

    it('preserves array order', () => {
      expect(text([3, 1, 2])).toBe('[3,1,2]');
    });

    it('handles empty arrays', () => {
      expect(text([])).toBe('[]');
    });

    it('drops undefined object values silently', () => {
      // Matches JSON.stringify convention.
      const obj: Record<string, unknown> = { a: 1, b: undefined, c: 3 };
      expect(text(obj)).toBe('{"a":1,"c":3}');
    });
  });

  describe('numbers', () => {
    it('emits integers without decimal marks', () => {
      expect(text(3)).toBe('3');
      expect(text(-3)).toBe('-3');
    });

    it('normalizes negative zero to "0"', () => {
      expect(text(-0)).toBe('0');
      expect(text(0)).toBe('0');
    });

    it('uses ES2019 exponent form for very large or small numbers', () => {
      // These are the specific spellings ES2019's NumberToString produces.
      expect(text(1e21)).toBe('1e+21');
      expect(text(1e-7)).toBe('1e-7');
    });

    it('preserves standard fractional rendering', () => {
      expect(text(0.1)).toBe('0.1');
      expect(text(-0.1)).toBe('-0.1');
    });

    it('rejects NaN and Infinity', () => {
      expect(() => canonicalize(Number.NaN)).toThrow(JcsError);
      expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(JcsError);
      expect(() => canonicalize(Number.NEGATIVE_INFINITY)).toThrow(JcsError);
    });
  });

  describe('strings', () => {
    it('applies short escapes for BS/TAB/LF/FF/CR/quote/backslash', () => {
      expect(text('\b\t\n\f\r"\\')).toBe('"\\b\\t\\n\\f\\r\\"\\\\"');
    });

    it('uses \\uXXXX for other controls with lowercase hex', () => {
      expect(text('\u0001')).toBe('"\\u0001"');
      expect(text('\u001f')).toBe('"\\u001f"');
    });

    it('does not escape forward slash', () => {
      expect(text('a/b')).toBe('"a/b"');
    });

    it('does not escape U+2028 / U+2029', () => {
      // JCS does not require these to be escaped; they pass through
      // as their UTF-8 bytes, which a compliant JSON parser accepts.
      expect(text('\u2028')).toBe('"\u2028"');
      expect(text('\u2029')).toBe('"\u2029"');
    });

    it('preserves surrogate pairs untouched', () => {
      // Emoji: U+1F600. UTF-16: D83D DE00.
      const s = '\uD83D\uDE00';
      expect(text(s)).toBe(`"${s}"`);
    });

    it('emits UTF-8 bytes from canonicalize()', () => {
      const bytes = canonicalize('hello');
      expect(Array.from(bytes)).toEqual([0x22, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x22]);
    });

    it('encodes non-ASCII characters as UTF-8 multi-byte sequences', () => {
      // "é" is U+00E9 which is 0xC3 0xA9 in UTF-8.
      const bytes = canonicalize('é');
      expect(Array.from(bytes)).toEqual([0x22, 0xc3, 0xa9, 0x22]);
    });
  });

  describe('RFC 8785 full-object vectors', () => {
    it('matches the spec example with mixed types and sorting', () => {
      // Adapted from RFC 8785 § 3.2.3 test data. The structure exercises
      // nested objects, numeric formats, and key ordering simultaneously.
      const input = {
        numbers: [333333333.33333329, 1e30, 4.5, 0.002, 1e-27],
        string: 'Test',
        literals: [null, true, false],
      };
      const result = text(input);
      expect(result).toBe(
        '{"literals":[null,true,false],' +
          '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
          '"string":"Test"}',
      );
    });

    it('emits identical bytes regardless of input key order', () => {
      const a = { foo: 1, bar: 2, baz: [3, 4] };
      const b = { baz: [3, 4], foo: 1, bar: 2 };
      expect(text(a)).toBe(text(b));
    });
  });

  describe('depth limit (DoS protection)', () => {
    function nest(depth: number): unknown {
      let cur: unknown = 0;
      for (let i = 0; i < depth; i++) cur = { a: cur };
      return cur;
    }

    it('accepts realistic depths', () => {
      // 100 levels is far above any real-world envelope.
      const ok = nest(100);
      expect(() => canonicalize(ok as Parameters<typeof canonicalize>[0])).not.toThrow();
    });

    it('rejects pathologically deep nesting at the default limit', () => {
      const bad = nest(1500);
      expect(() => canonicalize(bad as Parameters<typeof canonicalize>[0])).toThrow(JcsError);
      expect(() => canonicalize(bad as Parameters<typeof canonicalize>[0])).toThrow(/nested deeper/);
    });

    it('honours a custom maxDepth', () => {
      const obj = nest(50);
      expect(() =>
        canonicalize(obj as Parameters<typeof canonicalize>[0], { maxDepth: 10 }),
      ).toThrow(/nested deeper than 10/);
      expect(() =>
        canonicalize(obj as Parameters<typeof canonicalize>[0], { maxDepth: 100 }),
      ).not.toThrow();
    });

    it('rejects invalid maxDepth values', () => {
      expect(() => canonicalize({ a: 1 }, { maxDepth: 0 })).toThrow(JcsError);
      expect(() => canonicalize({ a: 1 }, { maxDepth: -1 })).toThrow(JcsError);
      expect(() => canonicalize({ a: 1 }, { maxDepth: 1.5 })).toThrow(JcsError);
    });

    it('counts arrays as one level of depth', () => {
      // Twenty levels of nested arrays.
      let arr: unknown = 1;
      for (let i = 0; i < 20; i++) arr = [arr];
      expect(() =>
        canonicalize(arr as Parameters<typeof canonicalize>[0], { maxDepth: 19 }),
      ).toThrow(/nested deeper/);
    });
  });
});
