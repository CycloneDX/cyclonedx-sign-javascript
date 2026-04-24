# @cyclonedx/sign

Standalone TypeScript implementation of the JSON signing formats used by CycloneDX.

* **JSF** (JSON Signature Format, 0.82) for CycloneDX 1.x.
* **JSS** (JSON Signature Schema, X.590) for CycloneDX 2.x. Stub in this release.
* **JCS** (JSON Canonicalization Scheme, RFC 8785) used by both.

One library so tool authors can sign and verify CycloneDX BOMs across specification versions through a single dependency. The `signBom` / `verifyBom` helpers pick the right format automatically from the BOM's `specVersion`.

The library is self contained. It has no runtime dependencies beyond `node:crypto`.

## Status

| Format | Status |
| ------ | ------ |
| JSF 0.82 | Complete. Interoperable with the reference implementation (node-webpki.org). |
| JSS (X.590) | Stub. `signJss` and `verifyJss` throw `JssNotImplementedError`. The API surface, types, and routing are in place so tool authors can wire up today and upgrade when the implementation lands. |
| JCS (RFC 8785) | Complete. |

## Install

```bash
npm install @cyclonedx/sign
```

Requires Node 18 or later.

## Quick start

Sign and verify any JSON object.

```ts
import { sign, verify } from '@cyclonedx/sign';

const payload = { subject: 'hello world' };

const signed = sign(payload, {
  algorithm: 'ES256',
  privateKey: ecPem, // PEM, DER, JWK, or Node KeyObject
});

const result = verify(signed);
result.valid;   // true
result.format;  // 'jsf'
```

The signed object is `payload` with a `signature` property attached. No fields are mutated. JSF is the default format, so existing `@cyclonedx/jsf` callers keep working without changes.

## CycloneDX BOM helper

Tool authors rarely want to think about which JSON signing format a given CycloneDX BOM uses. The `signBom` and `verifyBom` helpers inspect `specVersion` and route automatically.

```ts
import { signBom, verifyBom } from '@cyclonedx/sign';

// CycloneDX 1.x BOM routes to JSF.
// CycloneDX 2.x BOM routes to JSS (once JSS is implemented).
const signedBom = signBom(bom, { algorithm: 'ES256', privateKey });

const result = verifyBom(signedBom);
result.valid;   // true
result.format;  // 'jsf' for 1.x, 'jss' for 2.x
```

Routing precedence:

1. `options.format` when provided.
2. `bom.specVersion`. Major 1 routes to JSF, major 2 or higher routes to JSS.
3. Envelope shape detection via `detectFormat`.
4. JSF as the final fallback.

## Supported algorithms (JSF)

| Family | Identifiers |
| ------ | ----------- |
| RSASSA PKCS#1 v1.5 | `RS256`, `RS384`, `RS512` |
| RSASSA PSS | `PS256`, `PS384`, `PS512` |
| ECDSA (IEEE P1363 encoding) | `ES256` (P-256), `ES384` (P-384), `ES512` (P-521) |
| EdDSA | `Ed25519`, `Ed448` |
| HMAC | `HS256`, `HS384`, `HS512` |

For CycloneDX signatory and document level envelopes the asymmetric algorithms are exported as the typed list `JSF_ASYMMETRIC_ALGORITHMS` and the guard `isAsymmetricAlgorithm`. HMAC is deliberately excluded from that list because symmetric keys are not appropriate for tamper evident envelopes where the verifier is distinct from the signer.

JSS algorithm coverage will be documented when the JSS implementation lands.

## JSF

Use the JSF module directly when you want to bypass format routing.

```ts
import { signJsf, verifyJsf } from '@cyclonedx/sign/jsf';
```

Sign options include the JSF envelope knobs:

```ts
const signed = signJsf(payload, {
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
const result = verifyJsf(signed, {
  publicKey,                          // override the embedded key
  allowedAlgorithms: ['ES256', 'Ed25519'],
  requireEmbeddedPublicKey: true,     // reject envelopes without publicKey
  signatureProperty: 'signature',
});
```

`verifyJsf` returns a structured result rather than throwing on cryptographic mismatch. Thrown errors indicate caller bugs (malformed envelope, missing verifying key, unknown algorithm).

### Two phase signing

`computeJsfCanonicalInput` returns the exact UTF-8 bytes that will be signed. Useful when the private key lives on a remote signer and you want to send only the digest input over the wire.

```ts
import { computeJsfCanonicalInput } from '@cyclonedx/sign/jsf';

const bytes = computeJsfCanonicalInput(payload, {
  algorithm: 'ES256',
  publicKey: embeddedJwk, // optional metadata
});
```

## JSS (stub)

The JSS module is wired up end to end at the type and routing level but `signJss` and `verifyJss` currently throw `JssNotImplementedError`. Tool authors can import from `@cyclonedx/sign/jss` today, catch the error gracefully, and have their integrations ready for when the underlying implementation lands.

```ts
import { signJss, verifyJss, type JssSignOptions } from '@cyclonedx/sign/jss';
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

## Back compat with `@cyclonedx/jsf`

This package is the successor to `@cyclonedx/jsf`. Existing imports keep working:

```ts
// These still work unchanged.
import { sign, verify, computeCanonicalInput } from '@cyclonedx/sign';
import { canonicalize } from '@cyclonedx/sign/jcs';
import { toPrivateKey, toPublicKey } from '@cyclonedx/sign/jwk';
```

The previous JSF specific type names (`JsfAlgorithm`, `JsfSigner`, `JsfPublicKey`, `JsfJwkKeyType`, `SignOptions`, `VerifyOptions`, `VerifyResult`) are re-exported from the top level.

## Design notes

* **Single seam for crypto.** `src/jsf/algorithms.ts` owns every call into `node:crypto`. Everything else operates on specs and key objects. Retargeting to WebCrypto or a hardware token only requires touching that one file.
* **Throwing vs returning.** Verify returns a structured result on cryptographic mismatch and throws only for caller bugs (malformed envelope, missing verifying key, unsupported algorithm). This keeps the happy path straight line without try / catch.
* **No hidden mutation.** `sign` does not modify its input payload. The returned envelope is always a fresh object.
* **Deterministic envelopes.** Signer fields are emitted in a stable order, even though JSF does not require it, so envelopes diff cleanly in logs and fixtures.
* **Test fixtures.** `test/fixtures/` contains committed signed envelopes, the PEM keys that produced them, and a set of interop fixtures from the JSF reference implementation (node-webpki.org). The test suite verifies all of them and tamper-detects every positive assertion.

## License

Apache License 2.0. See `LICENSE`.

## Related specifications

* JSF 0.82: https://cyberphone.github.io/doc/security/jsf.html
* JCS (RFC 8785): https://datatracker.ietf.org/doc/html/rfc8785
* CycloneDX: https://cyclonedx.org
