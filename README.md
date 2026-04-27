[![shield_npm-version]][link_npm]
[![shield_gh-workflow-test]][link_gh-workflow-test]
[![shield_coverage]][link_codacy]
[![shield_license]][license_file]  
[![shield_website]][link_website]
[![shield_slack]][link_slack]
[![shield_groups]][link_discussion]

# @cyclonedx/sign

Standalone TypeScript implementation of the JSON signing formats used by CycloneDX.

* **JSF** (JSON Signature Format, 0.82) for CycloneDX 1.x. Full conformance: single, multi-signature, signature-chain, `excludes`, `extensions`, acceptance allowlists, JSF § 6 property validation.
* **JSS** (JSON Signature Schema, X.590) for CycloneDX 2.x. Stub.
* **JCS** (JSON Canonicalization Scheme, RFC 8785) used by both.

One library so tool authors can sign and verify CycloneDX BOMs across specification versions through a single dependency. The top-level `sign` and `verify` are async and accept a `cyclonedxVersion` option (a `CycloneDxMajor` enum value) and route to JSF for 1.x or JSS for 2.x.

The library is self contained. It has no runtime dependencies beyond `node:crypto`.

## Status

| Format | Status |
| ------ | ------ |
| JSF 0.82 | Complete. Verified against the Cyberphone reference test vectors for single, multi-signature, signature-chain, `excludes`, and `extensions`. |
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

const signed = await sign(payload, {
  cyclonedxVersion: CycloneDxMajor.V1,
  signer: { algorithm: 'ES256', privateKey: ecPem }, // PEM, DER, JWK, or KeyObject
});

const result = await verify(signed);
result.valid;              // true
result.cyclonedxVersion;   // CycloneDxMajor.V1
result.mode;               // 'single'
```

The signed object is `payload` with a `signature` property attached. No fields are mutated. `cyclonedxVersion` defaults to `V1` when omitted.

## Multi-signature and signature chains

JSF 0.82 defines two ways to attach more than one signer to an object:

* **Multiple Signatures (`mode: 'multi'`)**: independent signers, each verifying the same payload. Useful when peers attest to the same data without ordering.
* **Signature Chains (`mode: 'chain'`)**: each signer commits to the payload AND every prior signer's complete object. The standard JSF construction for counter-signatures.

```ts
// Multi: two independent signers
const signed = await sign(payload, {
  signers: [
    { algorithm: 'ES256', privateKey: keyA },
    { algorithm: 'RS256', privateKey: keyB },
  ],
  mode: 'multi',
});

// Chain: ordered, sequential commitment
const initial = await sign(payload, {
  signers: [{ algorithm: 'ES256', privateKey: keyA }],
  mode: 'chain',
});

// Counter-sign by appending to the chain
const countersigned = await appendChainSigner(initial, {
  algorithm: 'RS256',
  privateKey: keyB,
});
```

Verifying multi or chain envelopes returns per-signer results plus a top-level `valid` driven by the `policy` option:

```ts
const result = await verify(signed);
result.mode;           // 'multi' | 'chain' | 'single'
result.signers;        // array of { index, valid, algorithm, keyId, ... errors }
result.valid;          // policy: 'all' (default), 'any', or { atLeast: n }
```

The peer counter-signature pattern from JSF Appendix C uses `appendMultiSigner`:

```ts
const initial = await sign(payload, {
  signers: [{ algorithm: 'ES256', privateKey: peerA }],
  mode: 'multi',
});
const both = await appendMultiSigner(initial, {
  algorithm: 'ES256',
  privateKey: peerB,
});
```

If counter-signatures are anticipated, choose `mode: 'multi'` or `'chain'` from the first sign call. A bare-signaturecore (single) envelope is not lossless-promotable into a wrapper because the canonical bytes the original signer covered would change.

## Extensions and excludes

Both JSF Global Signature Options are supported.

```ts
// Per-signer application metadata via `extensions`
const signed = await sign(payload, {
  signer: {
    algorithm: 'ES256',
    privateKey,
    extensionValues: {
      issuedAt: '2026-04-01T00:00:00Z',
      'https://example.com/role': 'lead-assessor',
    },
  },
});
// `extensions` (the names list) is auto-populated from the union
// of every signer's extensionValues keys; pass it explicitly if you
// want to fix the wire-emit order or pre-declare names a future
// appender will use.

// Top-level fields the signer does not commit to
const signed2 = await sign(payload, {
  signer: { algorithm: 'ES256', privateKey },
  excludes: ['transient'],
});
```

JSF reserves nine words against extension property names (`algorithm`, `certificatePath`, `chain`, `extensions`, `excludes`, `keyId`, `publicKey`, `signers`, `value`). Sign-time validation always rejects them.

## Verification options (JSF § 5, § 6)

JSF § 6 requires that "there must not be any not here defined properties inside of the signature object". The library always enforces this at verify time. Envelopes whose signaturecore or wrapper carries an undeclared property fail verification with an envelope-level error. There is no caller knob to switch this off: an opt-in toggle would let different verifiers accept different envelopes, which is exactly the interop hazard the spec rules out.

JSF § 5 separately mandates acceptance allowlists for `excludes` and `extensions`. Those are caller-controlled and lenient by default:

```ts
const result = await verify(envelope, {
  allowedExcludes: ['transient'],
  allowedExtensions: ['issuedAt', 'https://example.com/role'],
  policy: 'all',
});
```

Set both `allowedExcludes` and `allowedExtensions` for envelopes from untrusted producers (BOM signatures from external suppliers, for example).

### Algorithm allowlist (recommended)

`JsfVerifyOptions.allowedAlgorithms` is unset by default; the verifier will accept any registered JSF algorithm in the envelope. For production use, pin the allowlist to the exact algorithms you expect:

```ts
import { JSF_ASYMMETRIC_ALGORITHMS } from '@cyclonedx/sign/jsf';

const result = await verify(envelope, {
  allowedAlgorithms: JSF_ASYMMETRIC_ALGORITHMS, // RS/PS/ES/Ed only, no HMAC
  allowedExcludes: [...],
  allowedExtensions: [...],
});
```

Avoid mixing HMAC (`HS256`/`HS384`/`HS512`) with asymmetric algorithms in the same allowlist. Doing so combined with passing a public key as raw `Buffer` recreates the classic JWS algorithm-confusion attack surface where an attacker substitutes a public key as an HMAC secret. The library blocks this in the common case (asymmetric public keys are rejected by the HMAC primitive's key-type check), but the safest posture is a single-family allowlist per verify call.

### Replay protection

JSF signs the canonical bytes of the payload; it does not include a timestamp, nonce, or audience. If the envelope can be replayed against a different consumer, time, or context, the application MUST add and check those fields itself (typically as application properties inside the payload).

### Counter-signing untrusted envelopes

`appendChainSigner` and `appendMultiSigner` verify every existing signer before adding the new signature. If verification fails, the append refuses; the appender never cryptographically commits to a prior signature it has not authenticated. Pass `publicKeys` if existing signers do not embed their JWKs:

```ts
const next = await appendChainSigner(envelope, signer, {
  publicKeys: new Map([[0, knownPubKeyForSigner0]]),
});
```

`skipVerifyExisting: true` opts out of the verify-first defense and should be used only when the caller has already verified out-of-band, or is the producer of every prior signer.

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

## Signing CycloneDX BOMs and parts of BOMs

The top-level `sign` accepts any JSON object as the subject. A BOM can be signed at several levels (the whole BOM, the declarations block, a single signatory, a formulation entry). The library does not inspect BOM structure.

```ts
import { sign, CycloneDxMajor } from '@cyclonedx/sign';

// Sign the whole BOM.
const signedBom = await sign(bom, {
  cyclonedxVersion: CycloneDxMajor.V1,
  signer: { algorithm: 'ES256', privateKey },
});

// Sign just the declarations block, keep it in place.
bom.declarations = await sign(bom.declarations, {
  cyclonedxVersion: CycloneDxMajor.V1,
  signer: { algorithm: 'ES256', privateKey },
});

// Sign one signatory.
bom.declarations.affirmation.signatories[0] = await sign(
  bom.declarations.affirmation.signatories[0],
  { cyclonedxVersion: CycloneDxMajor.V1, signer: { algorithm: 'ES256', privateKey } },
);
```

## Two-phase signing (HSM, KMS, remote signers)

Every signer input accepts either an inline `privateKey` or a `Signer` interface (`sign(canonicalBytes) -> Promise<Uint8Array>`). The same interface a future HSM or KMS adapter satisfies.

```ts
import { sign } from '@cyclonedx/sign';
import { computeCanonicalInputs } from '@cyclonedx/sign/jsf';

// In-process: pass a private key.
await sign(payload, { signer: { algorithm: 'ES256', privateKey } });

// HSM / KMS: provide your own Signer.
class AwsKmsSigner /* implements Signer */ {
  async sign(canonicalBytes /* Uint8Array */) {
    /* call AWS KMS Sign API, return raw bytes */
  }
}
await sign(payload, {
  signer: { algorithm: 'ES256', signer: new AwsKmsSigner() },
});

// Or compute canonical inputs externally for batch signing flows.
const bytes = computeCanonicalInputs(payload, {
  mode: 'single',
  signers: [{ algorithm: 'ES256', publicKey: jwk }],
  finalized: [false],
});
// bytes[0] = the exact UTF-8 canonical input the signer should sign
```

## Key input forms

Every sign / verify entry point accepts any of:

* PEM strings (PKCS#1, PKCS#8, SPKI, X.509).
* Raw `Buffer` or `Uint8Array` for symmetric HMAC key material.
* JWK JSON (string or object).
* Node `KeyObject` instances (pass through untouched).

For asymmetric algorithms the embedded `publicKey` in the signed envelope is a sanitized JWK limited to the fields the format defines for each key type. Extraneous JWK parameters such as `alg`, `use`, `key_ops`, `kid` are stripped on export.

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

## Error hierarchy

```
SignatureError
  ├── JcsError
  ├── JsfError
  │     ├── JsfInputError
  │     │     └── JsfMultiSignerInputError
  │     ├── JsfKeyError
  │     ├── JsfEnvelopeError
  │     │     └── JsfChainOrderError
  │     ├── JsfSignError
  │     └── JsfVerifyError
  └── JssError
        ├── JssNotImplementedError
        ├── JssInputError
        └── JssEnvelopeError
```

Catch `SignatureError` to trap everything the package throws. Catch a subtree (`JsfError`, `JssError`) to narrow by format. The format specific subclasses let you tell a malformed envelope apart from a bad input or a cryptographic failure.

`verify` returns a structured result with `valid: false` for cryptographic mismatch and envelope-level constraint violations. Errors are thrown only for caller bugs (malformed envelope shape, missing verifying key, unknown algorithm).

## Design notes

* **Format-agnostic core.** `src/core/` defines `EnvelopeMode`, `SignerDescriptor`, `EnvelopeOptions`, `Signer`, `Verifier`, and the orchestrator. JSF and (in the future) JSS each implement a small `FormatBinding` adapter; the orchestrator never speaks JSF or JSS directly. The same model handles single, multi, and chain.
* **Single seam for crypto.** `src/jsf/algorithms.ts` owns every call into `node:crypto`. The orchestrator never imports it. Retargeting to WebCrypto or a hardware token only requires touching that one file or providing a `Signer` adapter.
* **Async by default.** The public API is async so HSM / KMS signers fold in without changing call sites. The in-process node-crypto path resolves on the same tick.
* **Throwing vs returning.** Verify returns a structured result on cryptographic mismatch and on envelope-level constraint violations (allowlists, JSF § 6 property checks). Throws only for caller bugs.
* **No hidden mutation.** `sign` does not modify its input payload. The returned envelope is always a fresh object.
* **Deterministic envelopes.** Signer fields are emitted in a stable order so envelopes diff cleanly in logs and fixtures.
* **Test fixtures.** `test/fixtures/` carries committed envelopes, the PEM keys that produced them, the node-webpki.org reference vectors, and the Cyberphone JSF spec reference vectors for multi-signature, chain, extensions, and excludes (under `test/fixtures/jsf/interop/jsf-spec/`).

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
