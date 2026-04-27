/**
 * Strict verify-first defense (CWE-345 / CWE-347) shared between
 * JSF append and JSS counter-sign.
 *
 * Both helpers (`appendChainSigner` / `appendMultiSigner` in JSF and
 * `countersign` in JSS) need to authenticate every existing signer
 * before attaching a new signature, because the new signature can
 * commit to prior signaturecores in full (chain canonical view in
 * JSF § 9; counter-sign canonical view in X.590 § 7.2.2).
 *
 * The contract is the same in both formats:
 *
 *   - The caller MUST pass `publicKeys` covering every existing
 *     signer index (0..N-1) with keys obtained out of band, OR
 *   - pass `skipVerifyExisting: true` to opt out (the caller has
 *     verified the envelope out of band).
 *
 * A missing or incomplete `publicKeys` map throws via the format's
 * own error class. Embedded-key fallback is intentionally NOT
 * supported here: an attacker who controls the envelope also
 * controls the embedded keys, and a permissive default would silently
 * weaken the defense to a sanity check.
 */

export interface VerifyFirstOptions<TKey> {
  /** Number of existing signers; publicKeys must cover indices 0..N-1. */
  expectedSignerCount: number;
  /** Caller-supplied trusted keys, one per existing signer index. */
  publicKeys?: ReadonlyMap<number, TKey>;
  /** Opt-out flag. When true, all checks below are skipped. */
  skipVerifyExisting?: boolean;
  /**
   * Run the format's verify with the supplied trusted keys.
   * Returns the diagnostic string when verification fails, or
   * `null` when it passes.
   */
  verify: (trustedKeys: ReadonlyMap<number, TKey>) => Promise<string | null>;
  /**
   * Action verb embedded in error messages (for example `'append'`
   * for JSF or `'countersign'` for JSS).
   */
  action: string;
  /** Format-specific error factory. */
  raise: (message: string) => never;
}

/**
 * Enforce the strict verify-first contract. Returns when all checks
 * pass; throws via `opts.raise` otherwise. Has no return value because
 * the helper is a guard, not a transformer.
 */
export async function enforceVerifyFirst<TKey>(
  opts: VerifyFirstOptions<TKey>,
): Promise<void> {
  if (opts.skipVerifyExisting) return;
  const range = `0..${opts.expectedSignerCount - 1}`;
  if (opts.publicKeys === undefined) {
    opts.raise(
      `refusing to ${opts.action} without trusted keys: pass options.publicKeys ` +
        `covering every existing signer (${range}) so the verify-first defense uses ` +
        `keys you control, or pass options.skipVerifyExisting: true to bypass the ` +
        `check entirely (you must then verify the envelope out of band).`,
    );
  }
  for (let i = 0; i < opts.expectedSignerCount; i += 1) {
    if (!opts.publicKeys.has(i)) {
      opts.raise(
        `refusing to ${opts.action}: options.publicKeys is missing an entry for ` +
          `existing signer #${i}. Provide a trusted key for every signer ${range}, ` +
          `or pass options.skipVerifyExisting: true to bypass the check.`,
      );
    }
  }
  const failure = await opts.verify(opts.publicKeys);
  if (failure !== null) {
    opts.raise(
      `refusing to ${opts.action}: existing envelope did not verify (${failure}).`,
    );
  }
}
