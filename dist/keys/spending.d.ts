/**
 * MACHINA Vault — Spending Limit Enforcement
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Enforces per-transaction, daily, and monthly spending limits per token.
 * All amounts use bigint for precision (no floating point).
 */
import type { VaultKey } from "./types.js";
export interface SpendCheckResult {
    allowed: boolean;
    reason?: string;
}
/**
 * Check whether a proposed spend is within the key's spending limits.
 *
 * Checks in order:
 * 1. Key status is "active"
 * 2. Key has not expired
 * 3. Per-transaction limit
 * 4. Daily limit (after resetting if day changed)
 * 5. Monthly limit (after resetting if month changed)
 *
 * If the key has no spending limits for the given token, the spend is allowed.
 */
export declare function checkSpendingLimit(key: VaultKey, tokenAddress: string, amount: bigint): SpendCheckResult;
/**
 * Record a spend against a key's tracking state.
 * Returns a new VaultKey with updated spend tracking (immutable update).
 *
 * IMPORTANT: Call checkSpendingLimit() BEFORE calling this function.
 */
export declare function recordSpend(key: VaultKey, tokenAddress: string, amount: bigint): VaultKey;
/**
 * Reset daily spend tracking if the day has changed.
 * Returns a new VaultKey (immutable).
 */
export declare function resetDailySpend(key: VaultKey): VaultKey;
/**
 * Reset monthly spend tracking if the month has changed.
 * Returns a new VaultKey (immutable).
 */
export declare function resetMonthlySpend(key: VaultKey): VaultKey;
