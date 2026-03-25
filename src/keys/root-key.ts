/**
 * MACHINA Vault — Root Key Operations
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Root keys are created from passkey-derived credentials.
 * They have full permissions, no expiry, and no spending limits.
 * Root is the ONLY tier that can create Operator keys.
 */

import type { VaultKey } from "./types.js";
import { ROOT_PERMISSIONS } from "./permissions.js";

/**
 * Create a root key record from a passkey-derived public key.
 *
 * Root keys are the apex of the key hierarchy:
 * - All permissions enabled (256-bit mask fully set)
 * - No expiry
 * - No spending limits
 * - No parent key (parentKeyId = null)
 */
export function createRootKey(
  vaultId: string,
  publicKey: Uint8Array,
  address: string,
): VaultKey {
  const now = new Date().toISOString();
  const today = now.slice(0, 10); // YYYY-MM-DD
  const month = now.slice(0, 7); // YYYY-MM

  return {
    id: `key_root_${vaultId}`,
    vaultId,
    tier: "root",
    name: "Root Key",
    publicKey,
    address,
    parentKeyId: null,
    permissions: ROOT_PERMISSIONS,
    scope: {
      allowedChains: [], // empty = all chains allowed
      allowedContracts: [], // empty = all contracts allowed
      allowedFunctions: [], // empty = all functions allowed
      spendingLimits: [], // no spending limits for root
      expiry: null, // no expiry
      autoRotateInterval: null,
    },
    status: "active",
    signCount: 0,
    createdAt: now,
    expiresAt: null,
    revokedAt: null,
    lastUsedAt: null,
    spentToday: {},
    spentThisMonth: {},
    lastResetDay: today,
    lastResetMonth: month,
  };
}
