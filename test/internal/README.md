# Internal module tests

These tests cover the modules under `src/internal/`, plus a few
file-level test setups that need to bypass the package's normal
`#crypto-backend` resolution. They exist as a separate directory so
the regular per-format test files (`jsf.test.ts`, `jss-spec.test.ts`,
`fixtures.test.ts`) stay focused on the public API surface.

## Files

| File | Module / surface under test |
|------|------------------------------|
| `shared.test.ts` | `src/internal/crypto/shared.ts` — EMSA-PSS encode/verify, PKCS#1 v1.5 pad/unpad, DigestInfo prefixes pinned to RFC 3447, `constantTimeEqual`, `hashLength`. |
| `bigint-rsa.test.ts` | `src/internal/crypto/bigint-rsa.ts` — pure-JS modular exponentiation, byte/BigInt conversions, JWK base64url decoding, `rsaPrivate` / `rsaPublic`. The Web backend's only path for raw RSA, so its outputs are cross-checked byte-for-byte against `node:crypto.privateEncrypt(RSA_NO_PADDING)`. |
| `x509-parity.test.ts` | `node.parseCertSpkiPublicKey` vs `web.parseCertSpkiPublicKey` against the four committed WebPKI cert chains. Asserts both backends extract identical JWKs from the same DER and that the recovered keys verify the matching `@cer.json` envelopes. |
| `all-fixtures-web.test.ts` | High-level `verify()` exercised against the WebPKI and JSS spec fixtures with `vi.mock('#crypto-backend')` swapping the active backend to `web`. Mirrors `fixtures.test.ts` (which runs on the Node backend by default) so 100 % of the committed envelopes are covered on both runtimes. |

## Why these tests live here

The byte primitives (`shared.ts`, `bigint-rsa.ts`) and the X.509 walker
in `web.ts` are not part of the public API. Their test assertions
reach into specific encodings (DER lengths, JWK fields, modular
exponentiation outputs) that callers of the package should never need
to know about. Keeping these tests adjacent to each other makes it
clear which file is the audit surface for which behaviour.

`all-fixtures-web.test.ts` uses Vitest's `vi.mock` because there is no
public way to override the package's runtime backend selection. The
file exists so the Web backend gets the same fixture coverage the Node
backend already has via `fixtures.test.ts`.

## Adding new tests

A test belongs in this directory if it satisfies any of:

- It targets a module under `src/internal/`.
- It needs `vi.mock('#crypto-backend')` to force a specific runtime.
- It crosses between the two backend implementations (parity, byte
  equivalence).

Tests for the public API surface — `sign`, `verify`, format-specific
helpers — belong in the top-level `test/` directory next to the
existing `*.test.ts` files.
