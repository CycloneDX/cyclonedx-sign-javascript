# JSF Test Key Fixtures

These PEM files are static test keys committed to the repository so that
signature fixtures and interoperability tests can run deterministically.

## Keys

| File                     | Algorithm family | Usage            |
|--------------------------|------------------|------------------|
| `rsa2048-private.pem`    | RSA 2048         | RS256/384/512, PS256/384/512 |
| `rsa2048-public.pem`     | RSA 2048 (SPKI)  |                  |
| `p256-private.pem`       | EC P-256         | ES256            |
| `p256-public.pem`        | EC P-256 (SPKI)  |                  |
| `p384-private.pem`       | EC P-384         | ES384            |
| `p384-public.pem`        | EC P-384 (SPKI)  |                  |
| `p521-private.pem`       | EC P-521         | ES512            |
| `p521-public.pem`        | EC P-521 (SPKI)  |                  |
| `ed25519-private.pem`    | Ed25519          | Ed25519          |
| `ed25519-public.pem`     | Ed25519 (SPKI)   |                  |
| `ed448-private.pem`      | Ed448            | Ed448            |
| `ed448-public.pem`       | Ed448 (SPKI)     |                  |

Private keys are PKCS#8 PEM. Public keys are SubjectPublicKeyInfo PEM.

## Regeneration

Keys were generated once using `node:crypto` `generateKeyPairSync`. They
are intentionally committed so that tests can verify fixtures byte for
byte across runs and across CI workers.

HMAC algorithms (HS256/384/512) do not need key files. Their secret is
a plain byte string defined directly in the fixture generator.

## Warning

These keys are in a public repository. They are for testing only. Never
use them to sign anything you care about.
