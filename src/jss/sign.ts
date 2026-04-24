/**
 * JSS (JSON Signature Schema, X.590) sign and verify stubs.
 *
 * Status: INCOMPLETE STUB.
 *
 * Both entry points throw JssNotImplementedError. They are exported
 * today so the format helper in ../format-helper.ts can route to JSS
 * when callers request it (or when signBom detects a CycloneDX 2.x
 * document), and so tool authors can start building against the call
 * signatures before the underlying implementation lands.
 *
 * When JSS support is implemented, this file is the drop-in target:
 *   - signJss will produce an X.590-conformant envelope.
 *   - verifyJss will return a JssVerifyResult analogous to JsfVerifyResult.
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
export function signJss(_payload: JsonObject, _options: JssSignOptions): JsonObject {
  throw new JssNotImplementedError(
    'signJss is a stub. JSS (X.590) signing will land in a future release. ' +
      'For CycloneDX 1.x use the JSF format (the default).',
  );
}

/**
 * Verify a JSS-signed object.
 *
 * Currently throws JssNotImplementedError. See module docstring.
 */
export function verifyJss(_payload: JsonObject, _options: JssVerifyOptions = {}): JssVerifyResult {
  throw new JssNotImplementedError(
    'verifyJss is a stub. JSS (X.590) verification will land in a future release. ' +
      'For CycloneDX 1.x use the JSF format (the default).',
  );
}
