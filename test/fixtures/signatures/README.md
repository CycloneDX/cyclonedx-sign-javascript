# JSF Signature Fixtures

One file per supported JSF algorithm. Each file is a complete JSF envelope
produced by the package `sign()` function from a canonical test payload
and the matching PEM key in `../keys/` (or the canned HMAC secret for
the HS* files).

The fixtures are consumed by `fixtures.test.ts`:

1. The test reads each envelope and calls `verify()` with the
   corresponding verifying key. This proves the package can verify
   envelopes it produced in a prior run, and catches silent drift in
   canonicalization, base64url encoding, or signature bytes.

2. Tamper checks flip a byte inside the payload and assert `verify()`
   returns `valid: false`. This proves the test actually exercises the
   signature check and is not a tautology.

## Regeneration

RSA-PSS and ECDSA signatures are randomized, so re-running the
generator script will produce different `signature.value` strings for
those algorithms. That is expected. The test only asserts that
`verify()` accepts whatever bytes are on disk.

If the envelope grammar or JCS output ever changes intentionally,
regenerate these files by running the same script the CI uses:

    node test/fixtures/build-signatures.mjs

## Payload

All fixtures sign the same payload so that differences between files
are attributable to algorithm differences alone. The payload is also
used by the ephemeral-key tests in `jsf.test.ts`.

## HMAC note

HS256/384/512 envelopes do not carry an embedded public key because the
symmetric secret cannot be published. The test imports the secret
directly from the fixture builder.
