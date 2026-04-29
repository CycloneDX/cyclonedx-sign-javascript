/*!
This file is part of CycloneDX Signing Library for Javascript.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
Copyright (c) OWASP Foundation. All Rights Reserved.
*/

/**
 * Shared utilities for the dotnet-jss / dotnet-jsf interop suites.
 *
 * These tests shell out to the dotnet CLI tools published by
 * `coderpatros/dotnet-jss` and `coderpatros/dotnet-jsf` and compare
 * their behaviour against this library, with both crypto backends.
 *
 * Discovery rules:
 *
 *   - `DOTNET_BIN` may point at a custom dotnet executable.
 *     Defaults to `dotnet` on `$PATH`, or `/tmp/dotnet/dotnet` if
 *     that exists (the sandbox path).
 *   - `JSS_CLI_DLL` and `JSF_CLI_DLL` may point at the matching
 *     `*-cli.dll`. Defaults to `/tmp/build-jss/jss-cli.dll` and
 *     `/tmp/build-jsf/jsf-cli.dll`.
 *
 * If any of these are missing the test files call `it.skip` on every
 * case so the regular suite stays green when dotnet is unavailable.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function findDotnet(): string | null {
  if (process.env.DOTNET_BIN && existsSync(process.env.DOTNET_BIN)) {
    return process.env.DOTNET_BIN;
  }
  if (existsSync('/tmp/dotnet/dotnet')) return '/tmp/dotnet/dotnet';
  // Try `which dotnet`.
  const which = spawnSync('sh', ['-c', 'command -v dotnet']);
  if (which.status === 0) {
    const out = which.stdout.toString().trim();
    if (out) return out;
  }
  return null;
}

export function findCli(envName: 'JSS_CLI_DLL' | 'JSF_CLI_DLL', defaultPath: string): string | null {
  // eslint-disable-next-line security/detect-object-injection -- envName narrowed to a literal union.
  const fromEnv = process.env[envName];
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  if (existsSync(defaultPath)) return defaultPath;
  return null;
}

export interface DotnetCli {
  dotnet: string;
  jssDll: string | null;
  jsfDll: string | null;
}

export function discoverDotnetCli(): DotnetCli | null {
  const dotnet = findDotnet();
  if (!dotnet) return null;
  return {
    dotnet,
    jssDll: findCli('JSS_CLI_DLL', '/tmp/build-jss/jss-cli.dll'),
    jsfDll: findCli('JSF_CLI_DLL', '/tmp/build-jsf/jsf-cli.dll'),
  };
}

/** Spawn the dotnet CLI and return stdout/stderr/exit. */
export function runCli(
  cli: DotnetCli,
  dll: string,
  args: string[],
  options: { input?: string } = {},
): { status: number; stdout: string; stderr: string } {
  const r = spawnSync(cli.dotnet, [dll, ...args], {
    input: options.input,
    encoding: 'utf8',
    timeout: 30_000,
    env: {
      ...process.env,
      DOTNET_CLI_HOME: process.env.DOTNET_CLI_HOME ?? '/tmp/.dotnet-cli',
      DOTNET_NOLOGO: '1',
      // Suppress dotnet's startup banner; the JSS CLI prints an ASCII
      // banner to stdout on `--help`, but the verb subcommands don't.
    },
  });
  return {
    status: r.status ?? -1,
    stdout: r.stdout?.toString() ?? '',
    stderr: r.stderr?.toString() ?? '',
  };
}

/** Make a fresh temporary directory for one test run's keys / payloads. */
export function makeTempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

export function writeTextFile(dir: string, name: string, content: string): string {
  const p = join(dir, name);
  writeFileSync(p, content, 'utf8');
  return p;
}

export function readTextFile(path: string): string {
  return readFileSync(path, 'utf8');
}

/** A canonical payload for round-trip tests. */
export const SAMPLE_PAYLOAD = {
  statement: 'cyclonedx-sign-javascript interop',
  number: 1234,
  array: ['alpha', 'beta', 'gamma'],
  nested: { key: 'value', flag: true },
};

/** Lookup table for dotnet-jss generated key file names per algorithm. */
export function jssKeyFiles(dir: string, algorithm: string): { priv: string; pub: string } {
  // dotnet-jss writes "{algorithm}-private.pem" and "{algorithm}-public.pem".
  return {
    priv: join(dir, `${algorithm}-private.pem`),
    pub: join(dir, `${algorithm}-public.pem`),
  };
}

/** Lookup table for dotnet-jsf generated key file names per algorithm. */
export function jsfKeyFiles(dir: string, algorithm: string): { priv: string; pub: string } {
  return {
    priv: join(dir, `${algorithm}-private.pem`),
    pub: join(dir, `${algorithm}-public.pem`),
  };
}

/**
 * Algorithm matrix.
 *
 * dotnet-jss supports 11 algorithms (no HMAC, since JSS is a strictly
 * asymmetric scheme). dotnet-jsf supports those 11 plus HMAC variants.
 * We exclude HMAC from the cross-implementation interop because it
 * requires sharing a secret out of band.
 */
export const JSS_ALGORITHMS = [
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'Ed448',
] as const;

export const JSF_ALGORITHMS = [
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519', 'Ed448',
] as const;

export type JssAlg = typeof JSS_ALGORITHMS[number];
export type JsfAlg = typeof JSF_ALGORITHMS[number];
