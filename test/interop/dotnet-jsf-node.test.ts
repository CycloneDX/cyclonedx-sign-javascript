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
 * Cross-implementation interop: this library (Node backend) ↔
 * coderpatros/dotnet-jsf CLI.
 *
 * dotnet-jsf uses JWK files, not PEM. Algorithms covered: the
 * 11 asymmetric JSF algorithms (RS, PS, ES, Ed). HMAC requires a
 * shared secret out of band — exercised via JWK-oct in a separate
 * case at the bottom of this file.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { sign, verify } from '../../src/jsf/index.js';
import {
  discoverDotnetCli,
  runCli,
  makeTempDir,
  jsfKeyFiles,
  JSF_ALGORITHMS,
  SAMPLE_PAYLOAD,
  type DotnetCli,
} from './dotnet-helpers.js';

const cli = discoverDotnetCli();
const dotnetReady = !!(cli && cli.jsfDll);

let SHARED_DIR: string;
const KEY_PATHS: Record<string, { priv: string; pub: string }> = {};

function jsfJwkPaths(dir: string, algorithm: string): { priv: string; pub: string } {
  return {
    priv: join(dir, `${algorithm}-private.jwk`),
    pub: join(dir, `${algorithm}-public.jwk`),
  };
}

beforeAll(() => {
  if (!dotnetReady) return;
  SHARED_DIR = makeTempDir('jsf-interop-node-');
  for (const algorithm of JSF_ALGORITHMS) {
    const r = runCli(cli!, cli!.jsfDll!, ['generate-key', '-a', algorithm, '-o', SHARED_DIR, '-f']);
    if (r.status !== 0) {
      throw new Error(`generate-key ${algorithm} failed: ${r.stderr || r.stdout}`);
    }
    KEY_PATHS[algorithm] = jsfJwkPaths(SHARED_DIR, algorithm);
  }
});

describe('dotnet-jsf interop (Node backend)', () => {
  if (!dotnetReady) {
    it.skip('dotnet CLI not found — set DOTNET_BIN and JSF_CLI_DLL to enable', () => {});
    return;
  }

  describe.each(JSF_ALGORITHMS)('%s', (algorithm) => {
    it('this library signs → dotnet-jsf verifies', async () => {
      const { priv, pub } = KEY_PATHS[algorithm]!;
      const privJwk = JSON.parse(readFileSync(priv, 'utf8'));
      const signed = await sign(SAMPLE_PAYLOAD as never, {
        signer: { algorithm, privateKey: privJwk, publicKey: 'auto' },
      });
      const path = join(SHARED_DIR, `signed-by-us-${algorithm}.json`);
      writeFileSync(path, JSON.stringify(signed));
      const r = runCli(cli!, cli!.jsfDll!, ['verify', '-k', pub, '-i', path]);
      expect(r.status).toBe(0);
    });

    it('dotnet-jsf signs → this library verifies', async () => {
      const { priv, pub } = KEY_PATHS[algorithm]!;
      const inPath = join(SHARED_DIR, `payload-${algorithm}.json`);
      writeFileSync(inPath, JSON.stringify(SAMPLE_PAYLOAD));
      const r = runCli(cli!, cli!.jsfDll!, [
        'sign', '-a', algorithm, '-k', priv, '-i', inPath, '--embed-public-key',
      ]);
      expect(r.status).toBe(0);
      const signed = JSON.parse(r.stdout) as Record<string, unknown>;
      const pubJwk = JSON.parse(readFileSync(pub, 'utf8'));
      const result = await verify(signed as never, { publicKey: pubJwk });
      expect(result.valid).toBe(true);
    });
  });
});
