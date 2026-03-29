/**
 * MACHINA Vault — Root Key Operations
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Root keys are created from passkey-derived credentials.
 * They have full permissions, no expiry, and no spending limits.
 * Root is the ONLY tier that can create Operator keys.
 */
import type { VaultKey } from "./types.js";
/**
 * Create a root key record from a passkey-derived public key.
 *
 * Root keys are the apex of the key hierarchy:
 * - All permissions enabled (256-bit mask fully set)
 * - No expiry
 * - No spending limits
 * - No parent key (parentKeyId = null)
 */
export declare function createRootKey(vaultId: string, publicKey: Uint8Array, address: string): VaultKey;
//# sourceMappingURL=root-key.d.ts.map