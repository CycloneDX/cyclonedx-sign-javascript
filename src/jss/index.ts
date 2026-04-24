/**
 * JSS (JSON Signature Schema, X.590) public API barrel.
 *
 * Status: INCOMPLETE STUB. The exported functions throw
 * JssNotImplementedError. Types are provisional.
 *
 * Import this module via the ./jss subpath when you want to target JSS
 * explicitly:
 *
 *     import { signJss, verifyJss } from '@cyclonedx/sign/jss';
 */

export { signJss, verifyJss } from './sign.js';

export type {
  JssAlgorithm,
  JssSigner,
  JssSignOptions,
  JssVerifyOptions,
  JssVerifyResult,
} from './types.js';
