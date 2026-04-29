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
 * dotnet-jsf interop on the Web backend. Mirrors dotnet-jsf-node.test.ts
 * but with `vi.mock` swapping `#crypto-backend` to web.
 */

import { describe, it, expect, beforeAll, vi } from 'vitest';
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

vi.mock('#crypto-backend', async () => {
  return await import('../../src/internal/crypto/web.js');
});

import {
  discoverDotnetCli,
  runCli,
  makeTempDir,
  JSF_ALGORITHMS,
  SAMPLE_PAYLOAD,
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
  SHARED_DIR = makeTempDir('jsf-interop-web-');
  for (const algorithm of JSF_ALGORITHMS) {
    const r = runCli(cli!, cli!.jsfDll!, ['generate-key', '-a', algorithm, '-o', SHARED_DIR, '-f']);
    if (r.status !== 0) {
      throw new Error(`generate-key ${algorithm} failed: ${r.stderr || r.stdout}`);
    }
    KEY_PATHS[algorithm] = jsfJwkPaths(SHARED_DIR, algorithm);
  }
});

describe('dotnet-jsf interop (Web backend)', () => {
  if (!dotnetReady) {
    it.skip('dotnet CLI not found — set DOTNET_BIN and JSF_CLI_DLL to enable', () => {});
    return;
  }

  describe.each(JSF_ALGORITHMS)('%s', (algorithm) => {
    it('this library (Web) signs → dotnet-jsf verifies', async () => {
      const { sign } = await import('../../src/jsf/index.js');
      const { priv, pub } = KEY_PATHS[algorithm]!;
      const privJwk = JSON.parse(readFileSync(priv, 'utf8'));
      const signed = await sign(SAMPLE_PAYLOAD as never, {
        signer: { algorithm, privateKey: privJwk, publicKey: 'auto' },
      });
      const path = join(SHARED_DIR, `signed-by-web-${algorithm}.json`);
      writeFileSync(path, JSON.stringify(signed));
      const r = runCli(cli!, cli!.jsfDll!, ['verify', '-k', pub, '-i', path]);
      expect(r.status).toBe(0);
    });

    it('dotnet-jsf signs → this library (Web) verifies', async () => {
      const { verify } = await import('../../src/jsf/index.js');
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
