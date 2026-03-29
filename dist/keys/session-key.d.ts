/**
 * MACHINA Vault — Session Key CRUD
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Session keys are ephemeral, NOT derived from the master seed.
 * They are generated from fresh random bytes and have short TTLs.
 * Session keys cannot create any other keys.
 */
import type { KeyPermissions, KeyScope, KeyTier, VaultKey } from "./types.js";
export interface CreateSessionKeyParams {
    vaultId: string;
    name: string;
    /** ID of the parent key (root, operator, or agent) */
    parentKeyId: string;
    /** Tier of the parent key — used for hierarchy validation */
    parentTier: KeyTier;
    /** Parent key's permissions — used to constrain child */
    parentPermissions: KeyPermissions;
    /** Scope constraints (required for session keys) */
    scope: Partial<KeyScope>;
    /** Time-to-live in seconds (default: 3600 = 1 hour, max: 86400 = 24 hours) */
    ttlSeconds?: number;
}
/**
 * Create a new ephemeral session key.
 *
 * Validates:
 * - Parent must be root, operator, or agent
 * - Parent must have CREATE_SESSION_KEY permission
 *
 * Session keys:
 * - Are generated from cryptographically secure random bytes (NOT derived)
 * - Have a short TTL (default 1 hour)
 * - Cannot create any other keys
 * - Permissions are constrained to DEFAULT_SESSION_PERMISSIONS intersected with parent
 */
export declare function createSessionKey(params: CreateSessionKeyParams): {
    key: VaultKey;
    privateKey: Uint8Array;
};
//# sourceMappingURL=session-key.d.ts.map