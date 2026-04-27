/**
 * JSS (JSON Signature Schema, X.590) public API barrel.
 *
 * Status: INCOMPLETE STUB. The exported functions throw
 * JssNotImplementedError. Types are provisional.
 *
 * Import this module via the ./jss subpath when you want to target JSS
 * explicitly:
 *
 *     import { sign, verify } from '@cyclonedx/sign/jss';
 */

export { sign, verify } from './sign.js';

export type {
  JssAlgorithm,
  JssSigner,
  JssSignerInput,
  JssSignerVerifyResult,
  JssSignOptions,
  JssVerifyOptions,
  JssVerifyResult,
} from './types.js';
