[![shield_npm-version]][link_npm]
[![shield_gh-workflow-test]][link_gh-workflow-test]
[![shield_coverage]][link_codacy]
[![shield_license]][license_file]  
[![shield_website]][link_website]
[![shield_slack]][link_slack]
[![shield_groups]][link_discussion]

# @cyclonedx/sign

Standalone TypeScript implementation of the JSON signing formats used by CycloneDX.

* **JSF** (JSON Signature Format, 0.82) for CycloneDX 1.x.
* **JSS** (JSON Signature Schema, X.590) for CycloneDX 2.x. Stub in this release.
* **JCS** (JSON Canonicalization Scheme, RFC 8785) used by both.

One library so tool authors can sign and verify CycloneDX BOMs across specification versions through a single dependency. The top-level `sign` and `verify` accept a `cyclonedxVersion` option (a `CycloneDxMajor` enum value) and route to JSF for 1.x or JSS for 2.x.

The library is self contained. It has no runtime dependencies beyond `node:crypto`.

## Status

| Format | Status |
| ------ | ------ |
| JSF 0.82 | Complete. Interoperable with the reference implementation (node-webpki.org). |
| JSS (X.590) | Stub. The JSS `sign` and `verify` throw `JssNotImplementedError`. The API surface, types, and routing are in place so tool authors can wire up today and upgrade when the implementation lands. |
| JCS (RFC 8785) | Complete. |

## Install

```bash
npm install @cyclonedx/sign
```

Requires Node 20.19 or later.

## Quick start

Sign and verify any JSON object.

```ts
import { sign, verify, CycloneDxMajor } from '@cyclonedx/sign';

const payload = { subject: 'hello world' };

const signed = sign(payload, {
  cyclonedxVersion: CycloneDxMajor.V1,
  algorithm: 'ES256',
  privateKey: ecPem, // PEM, DER, JWK, or Node KeyObject
});

const result = verify(signed);
result.valid;              // true
result.cyclonedxVersion;   // CycloneDxMajor.V1
```

The signed object is `payload` with a `signature` property attached. No fields are mutated. `cyclonedxVersion` defaults to `CycloneDxMajor.V1` when omitted.

## Signing CycloneDX BOMs and parts of BOMs

The top-level `sign` accepts any JSON object as the subject. A BOM can be signed at several levels (the whole BOM, the declarations block, a single signatory, a formulation entry, and so on). The caller picks what to sign by passing exactly that object. The library does not inspect BOM structure; it routes to JSF or JSS purely from the `cyclonedxVersion` option.

```ts
import { sign, CycloneDxMajor } from '@cyclonedx/sign';

// Sign the whole BOM.
const signedBom = sign(bom, {
  cyclonedxVersion: CycloneDxMajor.V1,
  algorithm: 'ES256',
  privateKey,
});

// Sign just the declarations block, keep it in place.
bom.declarations = sign(bom.declarations, {
  cyclonedxVersion: CycloneDxMajor.V1,
  algorithm: 'ES256',
  privateKey,
});

// Sign one signatory.
bom.declarations.affirmation.signatories[0] = sign(
  bom.declarations.affirmation.signatories[0],
  { cyclonedxVersion: CycloneDxMajor.V1, algorithm: 'ES256', privateKey },
);
```

Verify mirrors the same pattern. Pass the exact object that carries the signature you want to check.

```ts
import { verify, CycloneDxMajor } from '@cyclonedx/sign';

const resultBom = verify(signedBom, { cyclonedxVersion: CycloneDxMajor.V1 });
const resultDecl = verify(bom.declarations, { cyclonedxVersion: CycloneDxMajor.V1 });

resultBom.valid;              // true
resultBom.cyclonedxVersion;   // CycloneDxMajor.V1
```

When `cyclonedxVersion` is omitted on verify, the helper inspects the envelope shape via `detectFormat` and falls back to `V1` when the shape is ambiguous.

## Supported algorithms (JSF)

| Family | Identifiers |
| ------ | ----------- |
| RSASSA PKCS#1 v1.5 | `RS256`, `RS384`, `RS512` |
| RSASSA PSS | `PS256`, `PS384`, `PS512` |
| ECDSA (IEEE P1363 encoding) | `ES256` (P-256), `ES384` (P-384), `ES512` (P-521) |
| EdDSA | `Ed25519`, `Ed448` |
| HMAC | `HS256`, `HS384`, `HS512` |

For CycloneDX signatory and document level envelopes the asymmetric algorithms are exported from `@cyclonedx/sign/jsf` as the typed list `JSF_ASYMMETRIC_ALGORITHMS` and the guard `isAsymmetricAlgorithm`. HMAC is deliberately excluded from that list because symmetric keys are not appropriate for tamper evident envelopes where the verifier is distinct from the signer.

JSS algorithm coverage will be documented when the JSS implementation lands.

## JSF

Use the JSF module directly when you want to bypass format routing.

```ts
import { sign, verify } from '@cyclonedx/sign/jsf';
```

Sign options include the JSF envelope knobs:

```ts
const signed = sign(payload, {
  algorithm: 'ES256',
  privateKey,
  keyId: 'signer-01',              // optional
  publicKey: 'auto',                // or false, or an override key
  certificatePath: [cert1, cert2],  // optional, base64 DER X.509 chain
  excludes: ['transient'],          // optional, fields to leave unsigned
  signatureProperty: 'signature',   // optional, default "signature"
});
```

`excludes` follows JSF 0.82 semantics: the listed top level fields are dropped from the canonical form before signing, and the `excludes` property itself is implicitly added to the exclusion set (so both the excluded data and the list of exclusions remain unsigned).

Verify options let you tighten the contract:

```ts
const result = verify(signed, {
  publicKey,                          // override the embedded key
  allowedAlgorithms: ['ES256', 'Ed25519'],
  requireEmbeddedPublicKey: true,     // reject envelopes without publicKey
  signatureProperty: 'signature',
});
```

`verify` returns a structured result rather than throwing on cryptographic mismatch. Thrown errors indicate caller bugs (malformed envelope, missing verifying key, unknown algorithm).

### Two phase signing

`computeCanonicalInput` returns the exact UTF-8 bytes that will be signed. Useful when the private key lives on a remote signer and you want to send only the digest input over the wire.

```ts
import { computeCanonicalInput } from '@cyclonedx/sign/jsf';

const bytes = computeCanonicalInput(payload, {
  algorithm: 'ES256',
  publicKey: embeddedJwk, // optional metadata
});
```

## JSS (stub)

The JSS module is wired up end to end at the type and routing level but `sign` and `verify` currently throw `JssNotImplementedError`. Tool authors can import from `@cyclonedx/sign/jss` today, catch the error gracefully, and have their integrations ready for when the underlying implementation lands.

```ts
import { sign, verify, type JssSignOptions } from '@cyclonedx/sign/jss';
```

`JssNotImplementedError` extends `JssError` which extends `SignatureError`. It does NOT extend `JsfError`, so existing JSF focused catch blocks will not silently swallow it.

## JCS

Canonicalize any JSON value to the RFC 8785 byte sequence:

```ts
import { canonicalize, canonicalizeToString } from '@cyclonedx/sign/jcs';

const bytes = canonicalize({ b: 2, a: 1 });
// UTF-8 bytes of the string:  {"a":1,"b":2}
```

Rejected inputs: `NaN`, `Infinity`, `-Infinity`, sparse array slots, and non-string object keys. `undefined` values inside objects are dropped to match `JSON.stringify` behavior.

## Key input forms

Every sign / verify entry point accepts any of:

* PEM strings (PKCS#1, PKCS#8, SPKI, X.509).
* Raw `Buffer` or `Uint8Array` for symmetric HMAC key material.
* JWK JSON (string or object).
* Node `KeyObject` instances (pass through untouched).

For asymmetric algorithms the embedded `publicKey` in the signed envelope is a sanitized JWK limited to the fields the format defines for each key type. Extraneous JWK parameters such as `alg`, `use`, `key_ops`, `kid` are stripped on export.

## Error hierarchy

```
SignatureError
  ├── JcsError
  ├── JsfError
  │     ├── JsfInputError
  │     ├── JsfKeyError
  │     ├── JsfEnvelopeError
  │     ├── JsfSignError
  │     └── JsfVerifyError
  └── JssError
        ├── JssNotImplementedError
        ├── JssInputError
        └── JssEnvelopeError
```

Catch `SignatureError` to trap everything the package throws. Catch a subtree (`JsfError`, `JssError`) to narrow by format. The format specific subclasses let you tell a malformed envelope apart from a bad input or a cryptographic failure.

## Design notes

* **Single seam for crypto.** `src/jsf/algorithms.ts` owns every call into `node:crypto`. Everything else operates on specs and key objects. Retargeting to WebCrypto or a hardware token only requires touching that one file.
* **Throwing vs returning.** Verify returns a structured result on cryptographic mismatch and throws only for caller bugs (malformed envelope, missing verifying key, unsupported algorithm). This keeps the happy path straight line without try / catch.
* **No hidden mutation.** `sign` does not modify its input payload. The returned envelope is always a fresh object.
* **Deterministic envelopes.** Signer fields are emitted in a stable order, even though JSF does not require it, so envelopes diff cleanly in logs and fixtures.
* **Test fixtures.** `test/fixtures/` contains committed signed envelopes, the PEM keys that produced them, and a set of interop fixtures from the JSF reference implementation (node-webpki.org). The test suite verifies all of them and tamper-detects every positive assertion.

## License

Apache License 2.0. See [LICENSE][license_file].

## Related specifications

* [JSF 0.82](https://cyberphone.github.io/doc/security/jsf.html)
* [JSS (ITU-T X.590, 2023-10)](https://www.itu.int/epublications/publication/itu-t-x-590-2023-10-json-signature-scheme-jss)
* [JCS (RFC 8785)](https://datatracker.ietf.org/doc/html/rfc8785)
* [CycloneDX][link_website]

[shield_gh-workflow-test]: https://img.shields.io/github/actions/workflow/status/CycloneDX/cyclonedx-sign-javascript/ci.yml?branch=main&logo=GitHub&logoColor=white "tests"
[shield_coverage]: https://img.shields.io/codacy/coverage/f0382a1f070941c68c4a18ed05f971cb?logo=Codacy&logoColor=white "test coverage"
[shield_npm-version]: https://img.shields.io/npm/v/%40cyclonedx%2fsign/latest?label=npm&logo=npm&logoColor=white "npm"
[shield_license]: https://img.shields.io/github/license/CycloneDX/cyclonedx-sign-javascript?logo=open%20source%20initiative&logoColor=white "license"
[shield_website]: https://img.shields.io/badge/https://-cyclonedx.org-blue.svg "homepage"
[shield_slack]: https://img.shields.io/badge/slack-join-blue?logo=Slack&logoColor=white "slack join"
[shield_groups]: https://img.shields.io/badge/discussion-groups.io-blue.svg "groups discussion"
[shield_twitter-follow]: https://img.shields.io/badge/Twitter-follow-blue?logo=Twitter&logoColor=white "twitter follow"

[license_file]: LICENSE
[link_website]: https://cyclonedx.org/
[link_gh-workflow-test]: https://github.com/CycloneDX/cyclonedx-sign-javascript/actions/workflows/ci.yml?query=branch%3Amain
[link_codacy]: https://app.codacy.com/gh/CycloneDX/cyclonedx-sign-javascript/dashboard
[link_ossf-best-practices]: https://www.bestpractices.dev/projects?q=cyclonedx-sign-javascript
[link_npm]: https://www.npmjs.com/package/@cyclonedx/sign
[link_slack]: https://cyclonedx.org/slack/invite
[link_discussion]: https://groups.io/g/CycloneDX
