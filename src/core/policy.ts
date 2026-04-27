/**
 * Per-signer verify-result aggregation policy.
 *
 * Both JSF (multi, chain) and JSS (multi, counter) produce per-signer
 * outcomes that the caller may want to aggregate to a single
 * top-level boolean. The three policies match common deployment
 * needs:
 *
 *   - 'all' (default): every signer must verify. Safe for chain
 *     envelopes (sequential commitment) and for document-level BOM
 *     signatures where every signatory must be valid.
 *   - 'any': at least one signer must verify.
 *   - { atLeast: n }: at least n signers must verify.
 */

export type VerifyPolicy = 'all' | 'any' | { atLeast: number };

/**
 * Apply a policy to a flat array of per-signer booleans.
 *
 * Format bindings call this after collecting per-signer outcomes;
 * keeping the helper here keeps the aggregation rule consistent
 * across formats.
 */
export function applyPolicy(outcomes: readonly boolean[], policy: VerifyPolicy): boolean {
  const ok = outcomes.filter(Boolean).length;
  if (policy === 'all') return ok === outcomes.length;
  if (policy === 'any') return ok >= 1;
  return ok >= policy.atLeast;
}
