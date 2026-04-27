/**
 * Format-agnostic core. Exposes the small, cross-format surface that
 * HSM, KMS, and remote-signer adapters target. Everything else
 * (envelope shapes, validation rules, descriptor models, format
 * orchestration) lives next to the format that owns it: see
 * `src/jsf/` and `src/jss/`.
 */

export type { Signer, Verifier } from './signer.js';
export { applyPolicy } from './policy.js';
export type { VerifyPolicy } from './policy.js';
