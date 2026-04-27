# JSS spec reference vectors (ITU-T X.590, 10/2023)

Test material extracted verbatim from the X.590 Recommendation. Each
file traces back to a specific clause in the spec. The `value` strings
in clauses 7.1.6 and 7.2.6 are KNOWN ERRATA: they do not verify
against the Appendix II public key. We commit them anyway so a future
spec revision that fixes the erratum is detected by the test suite.

## Files

| File | Source clause | Notes |
| --- | --- | --- |
| `appendix-ii-public-key.pem` | App. II.1 | Ed25519 SPKI PEM. |
| `appendix-ii-private-key.pem` | App. II.2 | Ed25519 PKCS#8 PEM. |
| `clause-7.1.1-input.json` | 7.1.1 | Starting envelope with placeholder existing signature. |
| `clause-7.1.3-prepared.json` | 7.1.3 | Envelope after temporarily removing the prior signature and adding the new (no-value) signaturecore. |
| `clause-7.1.4-canonical.txt` | 7.1.4 | Exact canonical bytes of clause 7.1.3. |
| `clause-7.1.5-hash.hex` | 7.1.5 | SHA-256 hex of `clause-7.1.4-canonical.txt`. |
| `clause-7.1.6-spec-value.txt` | 7.1.6 | The published Ed25519 signature. KNOWN ERRATUM: does NOT verify against the Appendix II public key. |
| `clause-7.1.7-output.json` | 7.1.7 | Final envelope with prior signature restored at the start of the array. |
| `clause-7.2.4-canonical.txt` | 7.2.4 | Counter-sign canonical bytes. |
| `clause-7.2.5-hash.hex` | 7.2.5 | SHA-256 hex of clause 7.2.4. |
| `clause-7.2.6-spec-value.txt` | 7.2.6 | The published Ed25519 counter signature. KNOWN ERRATUM: does NOT verify. |
| `clause-7.2.7-output.json` | 7.2.7 | Counter-signed envelope. |
| `clause-8.1.1-signed.json` | 8.1.1 | Single-signer envelope used to demonstrate verification. |
| `appendix-iii-real-estate.json` | App. III | Notional countersigned real estate transaction. |

## Erratum confirmation

Independently verified on 2026-04-27 with Node `crypto`:

- SHA-256 of clause 7.1.4 canonical form == `e005ae762a01723f3b58fa8edb2b2cc3b126ca087077189072cfd9a27e6079d5` (matches spec § 7.1.5).
- SHA-256 of clause 7.2.4 canonical form == `d77acfa79aa675f22d4517f534df7919f2fdf9821b73f03e97140067abce9ab9` (matches spec § 7.2.5).
- Ed25519 signature of the SHA-256 hash with the Appendix II private key, verifying against the Appendix II public key:
  - For 7.1.x: `WY32HIXJb4EpdUVkQKLpmoz-XoSeMmPpsptZaiW4zLl33ikDuLXvh1J93K1Y5YLE_MYDGkKZFeRBoM9A0yHNBQ`. Verifies.
  - For 7.2.x: `4-5dehO3_851IlrVNag6vTZCXf6HAt3lLOQpKIiF4Yj_yovwbaxza5OkYCtsRTKC05SDXDx9PUrQqWqnE07KAA`. Verifies.
- The spec's published values (`F1Sj...`, `b_7Xu...`) DO NOT verify against the Appendix II public key. Both this library and `coderpatros/dotnet-jss` reach the same conclusion. Ed25519 is deterministic per RFC 8032, so the discrepancy is unambiguous: the spec text has the wrong values.

The error is in **the X.590 spec text**, not in any implementation. Likely cause: the example signatures were generated with a different key, or the canonical form used to generate them differs from clause 7.1.4 (e.g., the example was prepared before the canonical form was finalized).
