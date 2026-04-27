/**
 * JSS (JSON Signature Schema, X.590) sign and verify stubs.
 *
 * Status: INCOMPLETE STUB.
 *
 * Both entry points throw `JssNotImplementedError`. They are exported
 * today so the format helper in `../format-helper.ts` can route to
 * JSS when callers pass `CycloneDxMajor.V2`, and so tool authors can
 * build against the call signatures before the underlying X.590
 * implementation lands.
 *
 * The shapes mirror the JSF entry points (async, unified options) so
 * the JSS binding will fold into the format-agnostic `core/`
 * orchestrator without changing the public API.
 */

import { JssNotImplementedError } from '../errors.js';
import type { JsonObject } from '../types.js';
import type {
  JssSignOptions,
  JssVerifyOptions,
  JssVerifyResult,
} from './types.js';

// eslint-disable-next-line @typescript-eslint/require-await -- async on purpose so the throw becomes a rejected promise to match the public Promise<...> contract.
export async function sign(
  // eslint-disable-next-line @typescript-eslint/no-unused-vars, no-unused-vars -- Parameters lock the public API; the body throws until X.590 lands.
  _payload: JsonObject,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars, no-unused-vars
  _options: JssSignOptions,
): Promise<JsonObject> {
  throw new JssNotImplementedError(
    'JSS sign is a stub. JSS (X.590) signing will land in a future release. ' +
      'For CycloneDX 1.x use the JSF format (the default).',
  );
}

// eslint-disable-next-line @typescript-eslint/require-await -- see sign() above.
export async function verify(
  // eslint-disable-next-line @typescript-eslint/no-unused-vars, no-unused-vars
  _payload: JsonObject,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars, no-unused-vars
  _options: JssVerifyOptions = {},
): Promise<JssVerifyResult> {
  throw new JssNotImplementedError(
    'JSS verify is a stub. JSS (X.590) verification will land in a future release. ' +
      'For CycloneDX 1.x use the JSF format (the default).',
  );
}
