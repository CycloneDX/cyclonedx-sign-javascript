# Cross-implementation interop tests

These tests prove this library produces and consumes wire-compatible
output with independent reference implementations of JSF and JSS. They
shell out to the dotnet CLIs published by [`coderpatros/dotnet-jss`][dotnet-jss]
and [`coderpatros/dotnet-jsf`][dotnet-jsf] and compare bidirectionally
on both crypto backends.

A failure here flags a real interop drift: a signature produced by
this library that the reference cannot verify, or vice versa. That is
what these tests are for.

[dotnet-jss]: https://github.com/coderpatros/dotnet-jss
[dotnet-jsf]: https://github.com/coderpatros/dotnet-jsf

## Files

| File | What it covers |
|------|------------------|
| `dotnet-helpers.ts` | Shared utilities: dotnet CLI discovery, child-process spawning, key-file path conventions, the algorithm matrix. |
| `dotnet-jss-node.test.ts` | JSS, this library on the Node backend ↔ `jss-cli`. Both directions, all 11 algorithms (RS, PS, ES, Ed). |
| `dotnet-jss-web.test.ts`  | JSS, this library on the Web backend (forced via `vi.mock('#crypto-backend')`) ↔ `jss-cli`. |
| `dotnet-jsf-node.test.ts` | JSF, Node backend ↔ `jsf-cli`. Both directions, all 11 asymmetric algorithms. |
| `dotnet-jsf-web.test.ts`  | JSF, Web backend ↔ `jsf-cli`. |

JSF HMAC (`HS256/384/512`) is excluded from the matrix because
cross-implementation HMAC requires sharing a secret out of band, which
is not a meaningful interop test.

## Test directions

For every algorithm, each file runs both directions:

1. This library signs a payload, the dotnet CLI verifies. Catches
   drift in our canonical bytes, base64url, and signature assembly.
2. The dotnet CLI signs a payload, this library verifies. Catches
   strict-parsing bugs and silent rejection of inputs the reference
   considers valid.

## Enabling the suite

The tests skip cleanly when the dotnet CLIs are not found, so the
regular `npm test` stays green on machines without .NET.

To enable, install .NET 8.0 SDK or later and build the two CLIs:

```sh
git clone https://github.com/coderpatros/dotnet-jss /tmp/refs/dotnet-jss
git clone https://github.com/coderpatros/dotnet-jsf /tmp/refs/dotnet-jsf
dotnet build /tmp/refs/dotnet-jss/src/CoderPatros.Jss.Cli -c Release -o /tmp/build-jss
dotnet build /tmp/refs/dotnet-jsf/src/CoderPatros.Jsf.Cli -c Release -o /tmp/build-jsf
```

The discovery helper looks for `dotnet` on `$PATH` (or at
`/tmp/dotnet/dotnet` for the sandbox path), and for the two `*-cli.dll`
files at `/tmp/build-jss/jss-cli.dll` and `/tmp/build-jsf/jsf-cli.dll`.

Override any of the defaults with environment variables:

| Variable | Default |
|----------|---------|
| `DOTNET_BIN` | `dotnet` from `$PATH`, falling back to `/tmp/dotnet/dotnet` |
| `JSS_CLI_DLL` | `/tmp/build-jss/jss-cli.dll` |
| `JSF_CLI_DLL` | `/tmp/build-jsf/jsf-cli.dll` |

Then run just the interop suite:

```sh
npx vitest run test/interop
```

## Caveats

- `dotnet-jss` defaults to emitting EC SubjectPublicKeyInfo with
  explicit curve parameters rather than a named-curve OID. The Web
  backend handles both; the test suite exercises the explicit form.
- The dotnet CLIs use JWK files for JSF and PEM files for JSS,
  matching their respective specs. The helpers know which.
- Each test file generates a fresh key per algorithm at startup via
  `beforeAll`. Keys live in a temp directory and are not committed.

## Adding new interop targets

If a future reference implementation lands (Java, Go, Python, etc.),
mirror the existing pattern: a discovery helper for the binary, a
shared algorithm matrix, and one Vitest file per (format × backend)
pair so `vi.mock` cleanly swaps the crypto backend.
