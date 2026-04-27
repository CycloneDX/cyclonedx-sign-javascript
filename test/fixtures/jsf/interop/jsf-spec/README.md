# JSF spec reference vectors

These envelopes and JWK private keys were extracted from Appendix A of
the JSF 0.82 specification at
https://cyberphone.github.io/doc/security/jsf.html. They are committed
verbatim so the test suite can verify byte-identical outputs against
the reference and demonstrate interop with the spec author's own
implementation.

The signing keys live alongside the envelopes (`*privatekey.jwk`).
Each `kid` JWK matches the `keyId` referenced inside the corresponding
`*-kid.*` envelopes.

The naming convention mirrors the `webpki/` directory:
`<curve>#<algorithm>(@<variant>)?.json`. Multi-signer and chain
envelopes get the `<curve>#<alg>,<curve>#<alg>@(mult|chai)-<variant>.json`
shape per the JSF spec's own convention.

| File | JSF section | Notes |
| ---- | ----------- | ----- |
| `p256#es256@kid.json` | App. A | Single signer, `keyId` only. |
| `p256#es256@excl-jwk.json` | App. A | Single signer with `excludes`. |
| `p256#es256@exts-jwk.json` | App. A | Single signer with `extensions`. |
| `p256#es256@name-jwk.json` | App. A | Single signer with a custom `signatureProperty`. |
| `r2048#rs256@jwk.json` | App. A | Single RSA-PKCS1 signer with embedded JWK. |
| `r2048#rs256@kid.json` | App. A | Single RSA-PKCS1 signer with `keyId`. |
| `p256#es256,r2048#rs256@mult-jwk.json` | App. A § 8 | Multi-signature, embedded JWKs. |
| `p256#es256,r2048#rs256@mult-exts-kid.json` | App. A § 8 | Multi with `extensions`. The second signer omits one extension property (optional-per-signer per JSF § 5). |
| `p256#es256,r2048#rs256@mult-excl-kid.json` | App. A § 8 | Multi with `excludes`. |
| `p256#es256,r2048#rs256@chai-jwk.json` | App. A § 9 | Signature chain. |
| `p256#es256,r2048#rs256@chai-exts-kid.json` | App. A § 9 | Signature chain with `extensions`. |
