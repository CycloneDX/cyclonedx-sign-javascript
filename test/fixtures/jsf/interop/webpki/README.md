# Interoperability Fixtures: node-webpki.org

These fixtures were copied verbatim from the JSF reference
implementation `node-webpki.org`:

    https://github.com/cyberphone/node-webpki.org

They are used by `fixtures.test.ts` to prove that this package's
`verify()` accepts envelopes produced by an independent JSF signer.
Until we have these, the JSF test suite can only prove that our sign
and verify agree with each other.

## Source

- Repository: https://github.com/cyberphone/node-webpki.org
- Path in source: `test/`
- Copied: 2026-04-21
- Upstream license: Apache License 2.0 (declared in every lib/*.js
  header; copyright 2017-2020 WebPKI.org)

The upstream repository does not publish a top-level `LICENSE` file.
The license is declared per-source-file. The JSON fixtures and PEM
keys are test data covered by the same Apache 2.0 grant on the
project overall.

## Contents

| File                              | Kind                  | Used for |
|-----------------------------------|-----------------------|----------|
| `rootca.pem`                      | Root trust anchor     | chain tests (informational) |
| `otherca.pem`                     | Sibling root          | negative chain tests (informational) |
| `p256privatekey.pem`              | EC P-256 private      | reference only |
| `p256publickey.pem`               | EC P-256 public       | `@imp` verify |
| `p384privatekey.pem`              | EC P-384 private      | `@imp` verify (derive public) |
| `p521privatekey.pem`              | EC P-521 private      | `@imp` verify (derive public) |
| `r2048privatekey.pem`             | RSA 2048 private      | `@imp` verify (derive public) |
| `p256certpath.pem`                | EC P-256 cert chain   | reference only |
| `p384certpath.pem`                | EC P-384 cert chain   | reference only |
| `p521certpath.pem`                | EC P-521 cert chain   | reference only |
| `r2048certpath.pem`               | RSA 2048 cert chain   | reference only |
| `{alg}#{jws}@jwk.json`            | Envelope with embedded JWK | direct verify |
| `{alg}#{jws}@imp.json`            | Envelope with implicit key | verify with caller-supplied key |
| `{alg}#{jws}@cer.json`            | Envelope with X.509 path   | verify using leaf cert public key |

The `ecdh-es` JSON file (JEF encryption, not JSF signing) was not
copied. If we later add JEF support, bring it across with its matching
key.

## Why these matter

Running `verify()` against envelopes that were produced outside our
codebase is the only way to prove our JCS canonicalization, base64url
handling, and signature assembly match the JSF specification as the
reference implementation interprets it. Compatibility with this set
is not sufficient for full spec compliance (some exotic edge cases
are not covered by the reference fixtures), but a regression that
breaks any of these is a strong signal that something shifted off
spec.

## Regeneration

Do not regenerate. These fixtures are frozen at their upstream
state. If upstream ever updates them, update the copy and record the
new `Copied:` date above.
