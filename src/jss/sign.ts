/**
 * JSS (JSON Signature Schema, X.590) sign and verify stubs.
 *
 * Status: INCOMPLETE STUB.
 *
 * Both entry points throw JssNotImplementedError. They are exported
 * today so the format helper in ../format-helper.ts can route to JSS
 * when callers pass CycloneDxMajor.V2, and so tool authors can start
 * building against the call signatures before the underlying
 * implementation lands.
 *
 * When JSS support is implemented, this file is the drop-in target:
 *   - sign will produce an X.590-conformant envelope.
 *   - verify will return a JssVerifyResult analogous to JsfVerifyResult.
 *   - The call signatures defined here should remain stable as far as
 *     practical so callers do not need to rewrite their integrations.
 */

import { JssNotImplementedError } from '../errors.js';
import type { JsonObject } from '../types.js';
import type {
  JssSignOptions,
  JssVerifyOptions,
  JssVerifyResult,
} from './types.js';

/**
 * Produce a JSS-signed object.
 *
 * Currently throws JssNotImplementedError. See module docstring.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars, no-unused-vars -- Parameters are declared to lock the public API; the body throws a JssNotImplementedError until the X.590 implementation lands.
export function sign(_payload: JsonObject, _options: JssSignOptions): JsonObject {
  throw new JssNotImplementedError(
    'JSS sign is a stub. JSS (X.590) signing will land in a future release. ' +
      'For CycloneDX 1.x use the JSF format (the default).',
  );
}

/**
 * Verify a JSS-signed object.
 *
 * Currently throws JssNotImplementedError. See module docstring.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars, no-unused-vars -- Parameters are declared to lock the public API; the body throws a JssNotImplementedError until the X.590 implementation lands.
export function verify(_payload: JsonObject, _options: JssVerifyOptions = {}): JssVerifyResult {
  throw new JssNotImplementedError(
    'JSS verify is a stub. JSS (X.590) verification will land in a future release. ' +
      'For CycloneDX 1.x use the JSF format (the default).',
  );
}
