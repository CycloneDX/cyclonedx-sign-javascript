[![shield_npm-version]][link_npm]
[![shield_gh-workflow-test]][link_gh-workflow-test]
[![shield_quality]][link_codacy]
[![shield_coverage]][link_codacy]
[![shield_license]][license_file]  
[![shield_website]][link_website]
[![shield_slack]][link_slack]
[![shield_groups]][link_discussion]

# @cyclonedx/sign

Standalone TypeScript implementation of the JSON signing formats used by CycloneDX.

* **JSF** (JSON Signature Format, 0.82) for CycloneDX 1.x.
* **JSS** (JSON Signature Schema, ITU-T X.590, 10/2023) for CycloneDX 2.x.
* **JCS** (JSON Canonicalization Scheme, RFC 8785) used by both.

One library so tool authors can sign and verify CycloneDX BOMs across specification versions through a single dependency. The top-level `sign` and `verify` are async and accept a `cyclonedxVersion` option (a `CycloneDxMajor` enum value) and route to JSF for 1.x or JSS for 2.x.

The only runtime dependency outside `node:crypto` is [`@noble/curves`][link_noble_curves], used solely for the JSS ECDSA pre-hashed signing path that `node:crypto` cannot expose. JSF, JCS, EdDSA, RSA, and RSA-PSS are all served by `node:crypto` directly.

## Status

| Area | Status |
| ---- | ------ |
| JSF 0.82 | Complete. Single, multi-signature, signature chain, `excludes`, `extensions`. |
| JSS (X.590, 10/2023) | Complete for the named-algorithm subset (RS, PS, ES, Ed). XMSS / LMS out of scope. |
| JCS (RFC 8785) | Complete. |

Clause-by-clause compliance tables and known errata are documented inside the [JSF](#jsf-json-signature-format-082) and [JSS](#jss-json-signature-schema-x590-102023) sections below.

## Install

```bash
npm install @cyclonedx/sign
```

Requires Node 20.19 or later.

## Quick start

The top-level `sign` and `verify` route to JSF or JSS based on `cyclonedxVersion`. The signed object is `payload` with a `signature` (JSF) or `signatures` (JSS) property attached. No fields on the input are mutated.

```ts
import { sign, verify, CycloneDxMajor } from '@cyclonedx/sign';
import { JsfAlgorithms } from '@cyclonedx/sign/jsf';
import { JssAlgorithms, JssHashAlgorithms } from '@cyclonedx/sign/jss';

const payload = { subject: 'hello world' };

// JSF (CycloneDX 1.x)
const signedJsf = await sign(payload, {
  cyclonedxVersion: CycloneDxMajor.V1,
  signer: { algorithm: JsfAlgorithms.ES256, privateKey: ecPem },
});
const r1 = await verify(signedJsf);
r1.valid;              // true
r1.cyclonedxVersion;   // CycloneDxMajor.V1

// JSS (CycloneDX 2.x)
const signedJss = await sign(payload, {
  cyclonedxVersion: CycloneDxMajor.V2,
  signer: {
    algorithm: JssAlgorithms.Ed25519,
    hash_algorithm: JssHashAlgorithms.SHA_256,
    privateKey: ed25519Pem,
    public_key: 'auto',
  },
});
const r2 = await verify(signedJss, { cyclonedxVersion: CycloneDxMajor.V2 });
r2.valid;              // true
r2.cyclonedxVersion;   // CycloneDxMajor.V2
```

`cyclonedxVersion` is required on `sign`; there is no default. On `verify`, the format is auto-detected from the envelope shape when the option is omitted, and `verify` throws if neither the caller nor detection can resolve the version.

To target a specific format directly, import from the subpath:

```ts
import * as jsf from '@cyclonedx/sign/jsf';
import * as jss from '@cyclonedx/sign/jss';
```

### Named algorithm constants

Algorithm and hash names are exposed both as TypeScript string literal types and as `as const` runtime objects. Callers can write the raw wire string (`'ES256'`, `'sha-256'`) or the named member (`JsfAlgorithms.ES256`, `JssHashAlgorithms.SHA_256`); both are accepted everywhere because the const objects narrow to the exact same literal types.

```ts
import { JsfAlgorithms } from '@cyclonedx/sign/jsf'; // RS256, PS256, ES256, Ed25519, HS256, ...
import { JssAlgorithms, JssHashAlgorithms } from '@cyclonedx/sign/jss';
//   JssAlgorithms      RS256, PS256, ES256, Ed25519, Ed448, ...
//   JssHashAlgorithms  SHA_256, SHA_384, SHA_512   (values: 'sha-256', 'sha-384', 'sha-512')
```

## Signing CycloneDX BOMs and parts of BOMs

The top-level `sign` accepts any JSON object as the subject. A BOM can be signed at several levels (the whole BOM, the declarations block, a single signatory, a formulation entry). The library does not inspect BOM structure; pick the object you want to sign and pass it in. The same patterns work for both formats; switch `cyclonedxVersion` to control routing.

```ts
import { sign, CycloneDxMajor } from '@cyclonedx/sign';
import { JsfAlgorithms } from '@cyclonedx/sign/jsf';

// Sign the whole BOM (CycloneDX 1.x).
const signedBom = await sign(bom, {
  cyclonedxVersion: CycloneDxMajor.V1,
  signer: { algorithm: JsfAlgorithms.ES256, privateKey },
});

// Sign just the declarations block, keep it in place.
bom.declarations = await sign(bom.declarations, {
  cyclonedxVersion: CycloneDxMajor.V1,
  signer: { algorithm: JsfAlgorithms.ES256, privateKey },
});

// Sign one signatory.
bom.declarations.affirmation.signatories[0] = await sign(
  bom.declarations.affirmation.signatories[0],
  { cyclonedxVersion: CycloneDxMajor.V1, signer: { algorithm: JsfAlgorithms.ES256, privateKey } },
);
```

# JSF (JSON Signature Format, 0.82)

JSF attaches a single `signature` property (default name) to the payload. The property is either a bare signaturecore (single mode) or a wrapper carrying a `signers` array (multi mode) or a `chain` array (chain mode). Public keys are JWKs.

## JSF: single signer

```ts
import { sign, verify, JsfAlgorithms } from '@cyclonedx/sign/jsf';

const signed = await sign(payload, {
  signer: { algorithm: JsfAlgorithms.ES256, privateKey },
});
const result = await verify(signed);
result.valid;       // true
result.mode;        // 'single'
```

## JSF: multi-signature and signature chains

JSF defines two ways to attach more than one signer to an object:

* **Multiple Signatures (`mode: 'multi'`)**: independent signers, each verifying the same payload. Useful when peers attest to the same data without ordering.
* **Signature Chains (`mode: 'chain'`)**: each signer commits to the payload AND every prior signer's complete signaturecore. The standard JSF construction for counter-signatures.

```ts
import {
  sign,
  appendChainSigner,
  appendMultiSigner,
  JsfAlgorithms,
} from '@cyclonedx/sign/jsf';

// Multi: two independent signers
const multi = await sign(payload, {
  signers: [
    { algorithm: JsfAlgorithms.ES256, privateKey: keyA },
    { algorithm: JsfAlgorithms.RS256, privateKey: keyB },
  ],
  mode: 'multi',
});

// Chain: ordered, sequential commitment
const initial = await sign(payload, {
  signers: [{ algorithm: JsfAlgorithms.ES256, privateKey: keyA }],
  mode: 'chain',
});
const countersigned = await appendChainSigner(initial, {
  algorithm: JsfAlgorithms.RS256,
  privateKey: keyB,
});

// Peer counter-signature pattern from JSF Appendix C
const peerInitial = await sign(payload, {
  signers: [{ algorithm: JsfAlgorithms.ES256, privateKey: peerA }],
  mode: 'multi',
});
const both = await appendMultiSigner(peerInitial, {
  algorithm: JsfAlgorithms.ES256,
  privateKey: peerB,
});
```

If counter-signatures are anticipated, choose `mode: 'multi'` or `'chain'` from the first sign call. A bare-signaturecore (single) envelope is not lossless-promotable into a wrapper because the canonical bytes the original signer covered would change.

Verifying multi or chain envelopes returns per-signer results plus a top-level `valid` driven by the `policy` option:

```ts
const r = await verify(signed);
r.mode;           // 'multi' | 'chain' | 'single'
r.signers;        // array of { index, valid, algorithm, keyId, ... errors }
r.valid;          // policy: 'all' (default), 'any', or { atLeast: n }
```

`appendChainSigner` and `appendMultiSigner` verify the existing envelope before adding the new signature (CWE-345 / CWE-347 defense). The defense is strict: the caller MUST pass `publicKeys` covering every existing signer with keys obtained out of band, OR opt out explicitly via `skipVerifyExisting: true`. There is no fallback to embedded keys; that fallback would let an attacker who substitutes both the signature and the embedded `publicKey` slip past the check. Calls that supply neither option throw `JsfChainOrderError`.

```ts
// strong: trusted keys for every existing signer
const grown = await appendChainSigner(
  envelope,
  { algorithm: JsfAlgorithms.RS256, privateKey: keyB },
  { publicKeys: new Map([[0, knownPubKeyForSigner0]]) },
);

// opt out: caller verified the envelope out of band first
const grown2 = await appendChainSigner(
  envelope,
  { algorithm: JsfAlgorithms.RS256, privateKey: keyB },
  { skipVerifyExisting: true },
);
```

## JSF: `extensions` and `excludes`

```ts
import { sign, JsfAlgorithms } from '@cyclonedx/sign/jsf';

// Per-signer application metadata via `extensions`
const signed = await sign(payload, {
  signer: {
    algorithm: JsfAlgorithms.ES256,
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
  signer: { algorithm: JsfAlgorithms.ES256, privateKey },
  excludes: ['transient'],
});
```

JSF reserves nine words against extension property names (`algorithm`, `certificatePath`, `chain`, `extensions`, `excludes`, `keyId`, `publicKey`, `signers`, `value`). Sign-time validation always rejects them.

## JSF: verifier acceptance allowlists (JSF § 5)

JSF § 5 mandates acceptance allowlists for `excludes` and `extensions`. They are caller-controlled and lenient by default:

```ts
const r = await verify(envelope, {
  allowedExcludes: ['transient'],
  allowedExtensions: ['issuedAt', 'https://example.com/role'],
  policy: 'all',
});
```

Set both `allowedExcludes` and `allowedExtensions` for envelopes from untrusted producers (BOM signatures from external suppliers, for example).

JSF § 6's "no undeclared properties inside the signature object" rule is enforced unconditionally on every verify; there is no caller knob to switch this off. An opt-in toggle would let different verifiers accept different envelopes, which is exactly the interop hazard the spec rules out.

## JSF: algorithm allowlist (recommended)

`allowedAlgorithms` is unset by default; the verifier accepts any registered JSF algorithm in the envelope. For production use, pin the allowlist to the exact algorithms you expect:

```ts
import { JSF_ASYMMETRIC_ALGORITHMS } from '@cyclonedx/sign/jsf';

const r = await verify(envelope, {
  cyclonedxVersion: CycloneDxMajor.V1,
  allowedAlgorithms: JSF_ASYMMETRIC_ALGORITHMS, // RS/PS/ES/Ed only, no HMAC
});
```

Avoid mixing HMAC (`HS256` / `HS384` / `HS512`) with asymmetric algorithms in the same allowlist. Doing so combined with passing a public key as raw `Buffer` recreates the classic JWS algorithm-confusion attack surface where an attacker substitutes a public key as an HMAC secret. The library blocks this in the common case (asymmetric public keys are rejected by the HMAC primitive's key-type check), but the safest posture is a single-family allowlist per verify call.

## JSF: two-phase signing (HSM, KMS, remote signers)

Every JSF signer input accepts either an inline `privateKey` or a `Signer` interface (`sign(canonicalBytes) -> Promise<Uint8Array>`). The same interface a future HSM or KMS adapter satisfies.

```ts
import { sign, type Signer } from '@cyclonedx/sign';
import {
  computeCanonicalInputs as jsfCanonicalInputs,
  JsfAlgorithms,
} from '@cyclonedx/sign/jsf';

// In-process: pass a private key.
await sign(payload, {
  cyclonedxVersion: CycloneDxMajor.V1,
  signer: { algorithm: JsfAlgorithms.ES256, privateKey },
});

// HSM / KMS: provide your own Signer.
class AwsKmsSigner implements Signer {
  async sign(canonicalBytes: Uint8Array): Promise<Uint8Array> {
    /* call AWS KMS Sign API, return raw bytes */
  }
}
await sign(payload, {
  cyclonedxVersion: CycloneDxMajor.V1,
  signer: { algorithm: JsfAlgorithms.ES256, signer: new AwsKmsSigner() },
});

// Or compute canonical inputs externally for batch signing flows.
const jsfBytes = jsfCanonicalInputs(payload, {
  mode: 'single',
  signers: [{ algorithm: JsfAlgorithms.ES256, publicKey: jwk }],
  finalized: [false],
});
// jsfBytes[0] = exact UTF-8 canonical input the JSF signer should sign
```

JSF passes JCS canonical bytes directly to the `Signer`. The Signer is expected to hash and sign per the algorithm name (for example, `RS256` hashes with SHA-256 internally as part of `node:crypto`'s sign contract).

## JSF: key input forms

Every JSF sign / verify entry point accepts any of:

* PEM strings (PKCS#1, PKCS#8, SPKI, X.509).
* Raw `Buffer` or `Uint8Array` for symmetric HMAC key material.
* JWK JSON (string or object).
* Node `KeyObject` instances (pass through untouched).

For asymmetric JSF algorithms the embedded `publicKey` in the signed envelope is a sanitized JWK limited to the fields the format defines for each key type. Extraneous JWK parameters such as `alg`, `use`, `key_ops`, `kid` are stripped on export.

## JSF: replay protection

JSF signs the canonical bytes of the payload; it does not include a timestamp, nonce, or audience by itself. If the envelope can be replayed against a different consumer, time, or context, the application MUST add and check those fields itself, typically as application properties inside the payload or as `extensionValues` on the signer.

## JSF: supported algorithms

| Family | Identifiers |
| ------ | ----------- |
| RSASSA PKCS#1 v1.5 | `RS256`, `RS384`, `RS512` |
| RSASSA PSS | `PS256`, `PS384`, `PS512` |
| ECDSA (IEEE P-1363 encoding) | `ES256` (P-256), `ES384` (P-384), `ES512` (P-521) |
| EdDSA | `Ed25519`, `Ed448` |
| HMAC | `HS256`, `HS384`, `HS512` |

For CycloneDX signatory and document-level envelopes the asymmetric subset is exported from `@cyclonedx/sign/jsf` as the typed list `JSF_ASYMMETRIC_ALGORITHMS` and the guard `isAsymmetricAlgorithm`. HMAC is deliberately excluded from that list because symmetric keys are not appropriate for tamper-evident envelopes where the verifier is distinct from the signer.

## JSF compliance

| Clause | Requirement | Status | Notes |
| ------ | ----------- | ------ | ----- |
| § 5 signaturecore | `algorithm` (M), `value` (M), `keyId` (O), `publicKey` (O), `certificatePath` (O) | Implemented | All five fields round-trip; `publicKey` exported as a sanitized JWK. |
| § 5 multisignature | `signers` array of signaturecore | Implemented | `mode: 'multi'`. |
| § 5 signaturechain | `chain` array of signaturecore | Implemented | `mode: 'chain'` and `appendChainSigner`. |
| § 5 publicKey JWK shape | RFC 7517 JWK | Implemented | RSA, EC, OKP, oct supported. Extra JWK fields stripped on export. |
| § 5 Global Option `excludes` | top-level fields excluded from canonical form; `excludes` itself is unsigned | Implemented | The `excludes` property is correctly excluded from the canonical view per § 5; verified against spec reference vectors. |
| § 5 Global Option `extensions` | array of names of extension property values that live inside the signaturecore; reserved-word collision rejected; duplicates rejected | Implemented | Names list signed, values inside the signaturecore signed, optional-per-signer in multi/chain. |
| § 5 acceptance allowlists | "must provide options for specifying which properties to accept" | Implemented | `allowedExcludes` and `allowedExtensions` on `JsfVerifyOptions`. Lenient default; pin in production. |
| § 6 verification procedure | strip `value`, JCS canonicalize, verify | Implemented | |
| § 6 "no undefined properties inside the signature object" | normative verifier rule | Implemented | Always-on; not opt-in. Wrapper and signaturecore property closure enforced. |
| § 6 X.509 path validation | "out of scope" per spec | Deferred to caller | `certificatePath` is exposed; RFC 5280 chain building, revocation, OCSP are the caller's responsibility. |
| § 7 signing procedure | build core without `value`, JCS, sign, add `value` | Implemented | Sign never mutates the input payload. |
| § 8 multiple signatures bracket / comma rules | each signer canonicalizes against ONLY itself in the array | Implemented | Verified against `mult-*` reference vectors. |
| § 9 signature-chain rules | lower-order signers in full, higher-order removed, target stripped | Implemented | Verified against `chai-*` reference vectors. |
| § 10 I-JSON conformance | RFC 7493 / JCS RFC 8785 | Implemented | JCS module enforces RFC 8785 rules. |
| § 6.2.2 algorithm vocabulary (named) | RS256/384/512, PS256/384/512, ES256/384/512, Ed25519, Ed448, HS256/384/512 | Implemented | All 14 named algorithms sign and verify. |
| § 6.2.2 URI-named proprietary algorithms | "must be expressed as URIs" if added | **Not supported (intentional)** | The algorithm registry is closed to the JWA / RFC 8037 named set. CycloneDX use cases are well covered by the named algorithms; URI-named extensibility would add a registration API and increase the security review surface. |
| App. A reference vectors | spec author's worked examples | Implemented | Cyberphone webpki interop fixtures committed under `test/fixtures/jsf/interop/`. |
| App. B ECMAScript / JCS mode | reference to JCS | Implemented | RFC 8785 implementation in `src/jcs.ts`. |
| App. C counter signatures via signaturechain | most straightforward construction | Implemented | `appendChainSigner` with verify-first defense (CWE-345 / CWE-347). |
| App. C counter signatures via multisignature + extensions | peer-based construction | Implemented | `appendMultiSigner` + `extensionValues` per signer for application-specific counter-sign metadata. |

# JSS (JSON Signature Schema, X.590, 10/2023)

JSS attaches a `signatures` property (default name, plural) carrying a JSON array. Each element is a signaturecore object with `algorithm`, `hash_algorithm`, `value`, plus identification (`public_key`, `public_cert_chain`, `cert_url`, `thumbprint`) and optional metadata (X.590 § 6.3) and optional nested counter signature.

JSS differs from JSF in several ways:

* The signature property is always a JSON array.
* Each signaturecore carries an explicit `hash_algorithm` field.
* Public keys are PEM bodies (the base64 of DER SPKI, no headers), not JWKs.
* Multi-signature is **independent**: each signer signs against a canonical form where ONLY their own signaturecore is in the array.
* Counter signing nests a single `signature` property on a signaturecore (linear, one level per X.590 § 6.2.1).
* Custom metadata properties (X.590 § 6.3) are allowed and signed.

## JSS: single signer

```ts
import { sign, verify, JssAlgorithms, JssHashAlgorithms } from '@cyclonedx/sign/jss';

const signed = await sign(payload, {
  signer: {
    algorithm: JssAlgorithms.Ed25519,
    hash_algorithm: JssHashAlgorithms.SHA_256,   // default; explicit shown for clarity
    privateKey: ed25519Pem,
    public_key: 'auto',                          // embed PEM body of the public key
    metadata: {
      type: 'jss',
      signee: 'Alice',
      created: '2026-04-27T12:00:00Z',
    },
  },
});

const result = await verify(signed);
result.valid;                  // true
result.signers[0].metadata;    // { type: 'jss', signee: 'Alice', ... }
```

## JSS: multi-signature

X.590 § 7.1 multi-signature is independent: each signer's canonical view contains ONLY their own signaturecore in the array. No signer commits to any other signer's value.

```ts
import { sign, JssAlgorithms } from '@cyclonedx/sign/jss';

const multi = await sign(payload, {
  signers: [
    { algorithm: JssAlgorithms.Ed25519, privateKey: keyA, public_key: 'auto' },
    { algorithm: JssAlgorithms.ES256,   privateKey: keyB, public_key: 'auto' },
  ],
});
```

Calling `sign` on an already-signed envelope appends a new independent signer per X.590 § 7.1.7; existing signatures are preserved at the start of the array.

## JSS: counter signing

X.590 § 7.2 counter-signing nests a `signature` property on the target signaturecore. The counter signer commits to the target signer's complete value, so a counter signature endorses the target. The verify-first defense (CWE-345 / CWE-347) is strict: the caller MUST pass `publicKeys` covering every existing signer with keys obtained out of band, OR opt out explicitly via `skipVerifyExisting: true`. There is no fallback to embedded keys; that fallback would let an attacker who substitutes both the signature and the embedded `public_key` slip past the check. Calls that supply neither option throw `JssEnvelopeError`.

```ts
import { countersign, verify, JssAlgorithms } from '@cyclonedx/sign/jss';

// strong: trusted keys for every existing signer
const cs = await countersign(signed, {
  signer: { algorithm: JssAlgorithms.Ed25519, privateKey: notaryPem, public_key: 'auto' },
  // targetIndex defaults to the last signaturecore in the array.
  publicKeys: new Map([[0, knownPubKeyForSigner0]]),
});

const both = await verify(cs, { verifyCounterSignatures: true });
both.signers[0].countersignature?.valid; // true

// opt out: caller verified the envelope out of band first
const cs2 = await countersign(signed, {
  signer: { algorithm: JssAlgorithms.Ed25519, privateKey: notaryPem, public_key: 'auto' },
  skipVerifyExisting: true,
});
```

## JSS: custom metadata (X.590 § 6.3)

X.590 § 6.3 lists illustrative metadata properties (`type`, `id`, `related_to`, `related_version`, `created`, `modified`, `revoked`, `signee`, `valid_from`, `valid_until`). The library does not impose any semantics on these names; pass them via `metadata` on the signer input and they are part of the signed canonical form, round-tripping through verify on `result.signers[i].metadata`.

```ts
const signed = await sign(payload, {
  signer: {
    algorithm: JssAlgorithms.Ed25519,
    privateKey,
    public_key: 'auto',
    metadata: { type: 'attestation', signee: 'Bob', valid_until: '2026-12-31T00:00:00Z' },
  },
});
```

## JSS: verifier options

```ts
import { verify, JssAlgorithms, JssHashAlgorithms } from '@cyclonedx/sign/jss';

const r = await verify(envelope, {
  allowedAlgorithms: [JssAlgorithms.Ed25519, JssAlgorithms.ES256, JssAlgorithms.PS256],
  allowedHashAlgorithms: [JssHashAlgorithms.SHA_256, JssHashAlgorithms.SHA_384],
  requireEmbeddedKeyMaterial: true, // reject envelopes lacking public_key/cert_chain/cert_url/thumbprint
  verifyCounterSignatures: true,
  policy: 'all',                     // also: 'any' or { atLeast: n }
});
```

X.509 chain validation is **not** performed by the library. `public_cert_chain` carries the leaf cert's public key for verify; RFC 5280 chain building, expiry, and revocation are the caller's responsibility. The same applies to `cert_url` (the library does not fetch URLs).

## JSS: algorithm allowlist (recommended)

`allowedAlgorithms` is unset by default; the verifier accepts any registered JSS algorithm in the envelope. Every registered JSS algorithm is asymmetric (HMAC is intentionally not supported per X.590 § 6.2.2). For production use, pin the allowlist to the exact algorithms and hashes you expect:

```ts
import { JssAlgorithms, JssHashAlgorithms } from '@cyclonedx/sign/jss';

const r = await verify(envelope, {
  cyclonedxVersion: CycloneDxMajor.V2,
  allowedAlgorithms: [JssAlgorithms.Ed25519, JssAlgorithms.ES256, JssAlgorithms.PS256],
  allowedHashAlgorithms: [JssHashAlgorithms.SHA_256, JssHashAlgorithms.SHA_384],
});
```

## JSS: two-phase signing (HSM, KMS, remote signers)

Every JSS signer input accepts either an inline `privateKey` or a `Signer` interface. JSS pre-hashes the JCS canonical bytes per the signaturecore's `hash_algorithm` and passes the digest into the asymmetric primitive directly (X.590 § 6.2.1's pre-hashed signing contract).

```ts
import { sign, type Signer, CycloneDxMajor } from '@cyclonedx/sign';
import {
  computeCanonicalInputs as jssCanonicalInputs,
  JssAlgorithms,
  JssHashAlgorithms,
} from '@cyclonedx/sign/jss';

// In-process: pass a private key.
await sign(payload, {
  cyclonedxVersion: CycloneDxMajor.V2,
  signer: {
    algorithm: JssAlgorithms.ES256,
    hash_algorithm: JssHashAlgorithms.SHA_256,
    privateKey,
    public_key: 'auto',
  },
});

// HSM / KMS: provide your own Signer that consumes the canonical bytes.
class HsmSigner implements Signer {
  async sign(canonicalBytes: Uint8Array): Promise<Uint8Array> {
    /* hash with the chosen hash_algorithm, then sign the digest on the HSM */
  }
}
await sign(payload, {
  cyclonedxVersion: CycloneDxMajor.V2,
  signer: {
    algorithm: JssAlgorithms.ES256,
    hash_algorithm: JssHashAlgorithms.SHA_256,
    signer: new HsmSigner(),
    public_key: explicitPemBody,
  },
});

// Or compute canonical inputs externally for batch signing flows.
const jssBytes = jssCanonicalInputs(payload, {
  signers: [{ algorithm: JssAlgorithms.Ed25519, hash_algorithm: JssHashAlgorithms.SHA_256 }],
});
// jssBytes[0] = exact UTF-8 canonical input the JSS signer should hash + sign
```

In two-phase mode the caller is responsible for hashing the canonical bytes with the per-signer `hash_algorithm` before invoking the asymmetric primitive.

## JSS: key input forms

Every JSS sign / verify entry point accepts any of:

* PEM strings (PKCS#1, PKCS#8, SPKI, X.509).
* JWK JSON (string or object). Internally converted to a node `KeyObject`.
* Node `KeyObject` instances (pass through untouched).
* For verify only: a PEM body string (no headers / footers) routed via the embedded `public_key` field on a signaturecore.

For asymmetric JSS algorithms the embedded `public_key` is the PEM body (base64 of the DER SPKI, no headers or footers). `public_cert_chain` carries base64 (NOT base64url) DER X.509 certs leaf-first; the library extracts the leaf cert's public key for verification but does not chain-validate.

## JSS: replay protection

JSS signs the canonical bytes of the payload; it does not include a timestamp, nonce, or audience by itself. If the envelope can be replayed against a different consumer, time, or context, the application MUST add and check those fields itself, typically as application properties inside the payload or as `metadata` on the signer (X.590 § 6.3 includes `created`, `valid_from`, `valid_until` and similar names for exactly this purpose).

## JSS: supported algorithms

| Family | Identifiers |
| ------ | ----------- |
| RSASSA PKCS#1 v1.5 | `RS256`, `RS384`, `RS512` |
| RSASSA PSS | `PS256`, `PS384`, `PS512` |
| ECDSA (IEEE P-1363 encoding) | `ES256`, `ES384`, `ES512` (via `@noble/curves`) |
| EdDSA | `Ed25519`, `Ed448` |
| HMAC | Not supported (X.590 § 6.2.2 says "SHOULD NOT be used") |
| XMSS / LMS (quantum-safe) | Out of scope; `node:crypto` does not support these |

JSS hash algorithms: `sha-256`, `sha-384`, `sha-512` (lower-case-with-hyphen names per X.590 § 6.2.1).

## JSS compliance

| Clause | Requirement | Status | Notes |
| ------ | ----------- | ------ | ----- |
| § 6.1 data types | boolean, identifier (UUID), string, timestamp (RFC 3339) | Implemented | Caller supplies timestamp / UUID strings; the library does not validate RFC 3339 / RFC 4122 grammar. |
| § 6.2.1 `hash_algorithm` (M) | IANA hash registry | Implemented | sha-256, sha-384, sha-512. |
| § 6.2.1 `algorithm` (M) | algorithm name from § 6.2.2 vocabulary | Implemented (named subset) | |
| § 6.2.1 `public_key` (O) | PEM body of DER SPKI, no header / footer | Implemented | Round-trip preserves the body; `'auto'` derives it from `privateKey` at sign time. |
| § 6.2.1 `public_cert_chain` (O) | base64 (NOT base64url) DER X.509 chain, leaf first | Implemented | Round-trips; verify falls back to the leaf cert's embedded public key when `public_key` is absent. |
| § 6.2.1 `cert_url` (O) | URI to a PEM cert chain | Round-trip only | Library does NOT fetch the URL; spec requires TLS plus RFC 6125 server identity validation, which is the caller's responsibility. |
| § 6.2.1 `thumbprint` (O) | base64URL SHA-256 of leaf DER cert | Round-trip only | Library does NOT resolve a thumbprint to a certificate; the caller does the lookup. |
| § 6.2.1 `value` (M) | base64URL signature | Implemented | |
| § 6.2.1 nested `signature` (O) | counter signature | Implemented | `countersign()` with verify-first defense (CWE-345 / CWE-347). |
| § 6.2.1 "MUST populate one of public_key / cert_chain / cert_url / thumbprint" | sign-time validation | Implemented | Sign rejects signers with none of the four. |
| § 6.2.2 RS256 / RS384 / RS512 | RSA-PKCS1 v1.5 | Implemented | DigestInfo built per RFC 3447 + `crypto.privateEncrypt(PKCS1)`; pre-hashed input matches dotnet-jss. |
| § 6.2.2 PS256 / PS384 / PS512 | RSA-PSS | Implemented | EMSA-PSS encoded by hand + `crypto.privateEncrypt(NO_PADDING)`. |
| § 6.2.2 Ed25519, Ed448 | EdDSA | Implemented | `crypto.sign(null, hash, edPrivateKey)`. |
| § 6.2.2 ES256 / ES384 / ES512 | ECDSA | Implemented | Uses `@noble/curves` (`p256` / `p384` / `p521`) for the pre-hashed signing path that `node:crypto` cannot expose. IEEE P-1363 (r \|\| s) output per JWA RFC 7518 § 3.4. Cross-implementation interop with node:crypto-produced signatures verified. Sign normalizes to low-S (canonical); verify accepts both forms. |
| § 6.2.2 XMSS-SHA2_* | XMSS quantum-safe | **Out of scope** | `node:crypto` does not support XMSS. Roadmap. |
| § 6.2.2 LMS_SHA256_* | LMS quantum-safe | **Out of scope** | `node:crypto` does not support LMS. Roadmap. |
| § 6.2.2 HS256 / HS384 / HS512 | HMAC | **Not supported (intentional)** | Spec § 6.2.2 says "SHOULD NOT be used". Library follows the spec recommendation; callers needing HMAC use the JSF binding. |
| § 6.3 illustrative metadata properties | type, id, related_to, related_version, created, modified, revoked, signee, valid_from, valid_until | Implemented as caller-supplied | Custom metadata round-trips and is part of the canonical form; the library imposes no semantics on these names. |
| § 7.1 signature creation procedure | seven steps | Implemented | `sign()`. |
| § 7.1.2 / § 7.1.7 existing signatures preserved at start of array | reassembly | Implemented | Calling `sign()` on an already-signed envelope appends a new independent signer; existing signatures stay at the start. |
| § 7.2 counter signing procedure | seven steps | Implemented | `countersign()`. |
| § 7.2.2 other signatures temporarily removed | canonical view | Implemented | Verified against worked example clause 7.2.4 / 7.2.5. |
| § 8.1 verification procedure | six steps | Implemented | `verify()`. Top-level verify strips the nested counter signature so the original signer's canonical view is reproduced exactly (matches dotnet-jss). |
| § 8.1.6 X.509 path validation | "out of scope" per spec | Deferred to caller | `public_cert_chain` is exposed via the verify result; RFC 5280 chain building, revocation, OCSP are the caller's responsibility. |
| § 9 I-JSON conformance | RFC 7493 / RFC 8785 | Implemented | JCS module enforces RFC 8785 rules. |
| App. I open-source impls | non-normative | n/a | |
| App. II Ed25519 reference keys | reference test material | Used by tests | Committed under `test/fixtures/jss/spec/`. |
| App. III countersigned transaction | non-normative | n/a | |
| Erratum: clauses 7.1.6 / 7.2.6 published Ed25519 values | should verify against Appendix II key | **Spec erratum confirmed** | Published values do NOT verify against Appendix II key. Independently verified with Node crypto; same conclusion as `coderpatros/dotnet-jss`. Library commits the published values verbatim and ships an EXPECTED-FAIL test so a future spec revision that fixes the erratum is detected. |

## JSS: spec erratum (clauses 7.1.6 and 7.2.6)

Independently verified during implementation: the published Ed25519 signature values in clauses 7.1.6 (`F1Sj4VcZ...`) and 7.2.6 (`b_7Xu5q...`) do NOT verify against the X.590 Appendix II public key. Ed25519 is deterministic per RFC 8032, so both this library and `coderpatros/dotnet-jss` produce a different, mutually agreeing value. The spec text appears to carry an erratum. The library commits the published values verbatim under `test/fixtures/jss/spec/` and ships an EXPECTED-FAIL verification test so a future spec revision that fixes the erratum is detected automatically.

# Shared utilities

## JCS

Canonicalize any JSON value to the RFC 8785 byte sequence:

```ts
import { canonicalize, canonicalizeToString } from '@cyclonedx/sign/jcs';

const bytes = canonicalize({ b: 2, a: 1 });
// UTF-8 bytes of the string:  {"a":1,"b":2}
```

Rejected inputs: `NaN`, `Infinity`, `-Infinity`, sparse array slots, and non-string object keys. `undefined` values inside objects are dropped to match `JSON.stringify` behavior. A default depth limit of 1000 protects against pathologically deep input; pass `{ maxDepth: N }` to override.

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
        ├── JssInputError
        ├── JssEnvelopeError
        └── JssNotImplementedError
```

Catch `SignatureError` to trap everything the package throws. Catch a subtree (`JsfError`, `JssError`) to narrow by format. The format-specific subclasses let you tell a malformed envelope apart from a bad input or a cryptographic failure.

`verify` returns a structured result with `valid: false` for cryptographic mismatch and envelope-level constraint violations. Errors are thrown only for caller bugs (malformed envelope shape, missing verifying key, unknown algorithm).

## Design notes

* **Format-agnostic plug-in surface.** `src/core/` exposes the `Signer` and `Verifier` interfaces and the `VerifyPolicy` aggregator. JSF and JSS each own their full pipeline (binding, orchestrator, validation) under `src/jsf/` and `src/jss/`; HSM and KMS adapter packages target the core interfaces without depending on either format.
* **Single seam for crypto.** `src/jsf/algorithms.ts` and `src/jss/algorithms.ts` own every call into `node:crypto` (and, for JSS ECDSA, `@noble/curves`). Retargeting to WebCrypto or a hardware token only requires touching those files or providing a `Signer` adapter.
* **Async by default.** The public API is async so HSM / KMS signers fold in without changing call sites. The in-process node-crypto path resolves on the same tick.
* **Throwing vs returning.** Verify returns a structured result on cryptographic mismatch and on envelope-level constraint violations (allowlists, JSF § 6 property checks). Throws only for caller bugs.
* **No hidden mutation.** `sign` does not modify its input payload. The returned envelope is always a fresh object.
* **Deterministic envelopes.** Signer fields are emitted in a stable order so envelopes diff cleanly in logs and fixtures.
* **Test fixtures.** `test/fixtures/` carries committed envelopes, the PEM keys that produced them, the Cyberphone JSF spec reference vectors (`test/fixtures/jsf/interop/jsf-spec/`), and the X.590 Appendix II Ed25519 reference keys plus clause 7.x worked-example bytes (`test/fixtures/jss/spec/`).

## License

Apache License 2.0. See [LICENSE][license_file].

## Related specifications

* [JSF 0.82](https://cyberphone.github.io/doc/security/jsf.html)
* [JSS (ITU-T X.590, 2023-10)](https://www.itu.int/epublications/publication/itu-t-x-590-2023-10-json-signature-scheme-jss)
* [JCS (RFC 8785)](https://datatracker.ietf.org/doc/html/rfc8785)
* [CycloneDX][link_website]

[shield_gh-workflow-test]: https://img.shields.io/github/actions/workflow/status/CycloneDX/cyclonedx-sign-javascript/ci.yml?branch=main&logo=GitHub&logoColor=white "tests"
[shield_quality]: https://img.shields.io/codacy/grade/f0382a1f070941c68c4a18ed05f971cb?logo=Codacy&logoColor=white "code quality"
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
[link_noble_curves]: https://github.com/paulmillr/noble-curves
