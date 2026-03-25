/**
 * MACHINA Vault — Spending Limit Enforcement
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Enforces per-transaction, daily, and monthly spending limits per token.
 * All amounts use bigint for precision (no floating point).
 */

import type { SpendingLimit, VaultKey } from "./types.js";

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
export function checkSpendingLimit(
  key: VaultKey,
  tokenAddress: string,
  amount: bigint,
): SpendCheckResult {
  // Validate key status
  if (key.status !== "active") {
    return { allowed: false, reason: `Key is ${key.status}` };
  }

  // Check expiry
  if (key.expiresAt !== null) {
    const expiresAt = new Date(key.expiresAt).getTime();
    if (Date.now() >= expiresAt) {
      return { allowed: false, reason: "Key has expired" };
    }
  }

  // Find spending limit for this token
  const limit = findSpendingLimit(key.scope.spendingLimits, tokenAddress);
  if (limit === null) {
    // No limit defined for this token — allowed (root and operator keys
    // typically have no limits; agent keys should always have limits set)
    return { allowed: true };
  }

  // Check per-transaction limit
  if (amount > limit.perTx) {
    return {
      allowed: false,
      reason: `Amount ${amount} exceeds per-transaction limit of ${limit.perTx} for ${tokenAddress}`,
    };
  }

  // Get current spend totals (after resetting if period changed)
  const today = new Date().toISOString().slice(0, 10);
  const month = new Date().toISOString().slice(0, 7);

  const spentToday =
    key.lastResetDay === today ? (key.spentToday[tokenAddress] ?? 0n) : 0n;

  const spentThisMonth =
    key.lastResetMonth === month
      ? (key.spentThisMonth[tokenAddress] ?? 0n)
      : 0n;

  // Check daily limit
  if (spentToday + amount > limit.daily) {
    return {
      allowed: false,
      reason: `Daily spend would be ${spentToday + amount}, exceeding daily limit of ${limit.daily} for ${tokenAddress}`,
    };
  }

  // Check monthly limit
  if (spentThisMonth + amount > limit.monthly) {
    return {
      allowed: false,
      reason: `Monthly spend would be ${spentThisMonth + amount}, exceeding monthly limit of ${limit.monthly} for ${tokenAddress}`,
    };
  }

  return { allowed: true };
}

/**
 * Record a spend against a key's tracking state.
 * Returns a new VaultKey with updated spend tracking (immutable update).
 *
 * IMPORTANT: Call checkSpendingLimit() BEFORE calling this function.
 */
export function recordSpend(
  key: VaultKey,
  tokenAddress: string,
  amount: bigint,
): VaultKey {
  // Reset periods if needed before recording
  let updated = resetDailySpend(key);
  updated = resetMonthlySpend(updated);

  const newSpentToday = { ...updated.spentToday };
  newSpentToday[tokenAddress] = (newSpentToday[tokenAddress] ?? 0n) + amount;

  const newSpentThisMonth = { ...updated.spentThisMonth };
  newSpentThisMonth[tokenAddress] =
    (newSpentThisMonth[tokenAddress] ?? 0n) + amount;

  return {
    ...updated,
    spentToday: newSpentToday,
    spentThisMonth: newSpentThisMonth,
    signCount: updated.signCount + 1,
    lastUsedAt: new Date().toISOString(),
  };
}

/**
 * Reset daily spend tracking if the day has changed.
 * Returns a new VaultKey (immutable).
 */
export function resetDailySpend(key: VaultKey): VaultKey {
  const today = new Date().toISOString().slice(0, 10);
  if (key.lastResetDay === today) {
    return key;
  }
  return {
    ...key,
    spentToday: {},
    lastResetDay: today,
  };
}

/**
 * Reset monthly spend tracking if the month has changed.
 * Returns a new VaultKey (immutable).
 */
export function resetMonthlySpend(key: VaultKey): VaultKey {
  const month = new Date().toISOString().slice(0, 7);
  if (key.lastResetMonth === month) {
    return key;
  }
  return {
    ...key,
    spentThisMonth: {},
    lastResetMonth: month,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Find the spending limit for a given token address.
 * Returns null if no limit is defined for this token.
 */
function findSpendingLimit(
  limits: SpendingLimit[],
  tokenAddress: string,
): SpendingLimit | null {
  // Exact match first
  const exact = limits.find(
    (l) => l.tokenAddress.toLowerCase() === tokenAddress.toLowerCase(),
  );
  if (exact) return exact;

  // No match
  return null;
}
