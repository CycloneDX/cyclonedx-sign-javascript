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
 * Cross-implementation interop on the Web crypto backend: this library
 * (forced to use crypto.subtle + @noble/curves) ↔ coderpatros/dotnet-jss
 * CLI.
 *
 * Mirrors dotnet-jss-node.test.ts but with `vi.mock` swapping the
 * `#crypto-backend` resolution to the Web backend so every sign / verify
 * call goes through Subtle, the BigInt RSA path, and the @noble/curves
 * ECDSA primitives.
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
  jssKeyFiles,
  JSS_ALGORITHMS,
  SAMPLE_PAYLOAD,
  type JssAlg,
} from './dotnet-helpers.js';

const cli = discoverDotnetCli();
const dotnetReady = !!(cli && cli.jssDll);

let SHARED_DIR: string;
const KEY_PATHS: Record<string, { priv: string; pub: string }> = {};

beforeAll(() => {
  if (!dotnetReady) return;
  SHARED_DIR = makeTempDir('jss-interop-web-');
  for (const algorithm of JSS_ALGORITHMS) {
    const args = ['generate-key', '-a', algorithm, '-o', SHARED_DIR, '-f'];
    const r = runCli(cli!, cli!.jssDll!, args);
    if (r.status !== 0) {
      throw new Error(`generate-key ${algorithm} failed: ${r.stderr || r.stdout}`);
    }
    KEY_PATHS[algorithm] = jssKeyFiles(SHARED_DIR, algorithm);
  }
});

describe('dotnet-jss interop (Web backend)', () => {
  if (!dotnetReady) {
    it.skip('dotnet CLI not found — set DOTNET_BIN and JSS_CLI_DLL to enable', () => {});
    return;
  }

  describe.each(JSS_ALGORITHMS)('%s', (algorithm) => {
    it('this library (Web) signs → dotnet-jss verifies', async () => {
      const { sign } = await import('../../src/jss/index.js');
      const { priv, pub } = KEY_PATHS[algorithm]!;
      const privatePem = readFileSync(priv, 'utf8');
      const signed = await sign(SAMPLE_PAYLOAD as never, {
        signer: { algorithm, privateKey: privatePem, public_key: 'auto' },
      });
      const path = join(SHARED_DIR, `signed-by-web-${algorithm}.json`);
      writeFileSync(path, JSON.stringify(signed));
      const r = runCli(cli!, cli!.jssDll!, ['verify', '-k', pub, '-i', path]);
      expect(r.status).toBe(0);
    });

    it('dotnet-jss signs → this library (Web) verifies', async () => {
      const { verify } = await import('../../src/jss/index.js');
      const { priv, pub } = KEY_PATHS[algorithm]!;
      const inPath = join(SHARED_DIR, `payload-${algorithm}.json`);
      writeFileSync(inPath, JSON.stringify(SAMPLE_PAYLOAD));
      const r = runCli(cli!, cli!.jssDll!, [
        'sign',
        '-a', algorithm,
        '-h', defaultHash(algorithm),
        '-k', priv,
        '-i', inPath,
      ]);
      expect(r.status).toBe(0);
      const signed = JSON.parse(r.stdout) as Record<string, unknown>;
      const result = await verify(signed as never, {
        publicKey: readFileSync(pub, 'utf8'),
      });
      expect(result.valid).toBe(true);
    });
  });
});

function defaultHash(algorithm: JssAlg): string {
  if (algorithm.endsWith('384')) return 'sha-384';
  if (algorithm.endsWith('512')) return 'sha-512';
  return 'sha-256';
}
