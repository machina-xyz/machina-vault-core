/**
 * MACHINA Vault — Agent Key CRUD
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Agent keys are created by root or operator keys.
 * They can sign transactions and create session keys, subject to spending limits
 * and contract allowlists.
 */
import type { KeyPermissions, KeyScope, KeyTier, SpendingLimit, VaultKey } from "./types.js";
export interface CreateAgentKeyParams {
    vaultId: string;
    name: string;
    /** ID of the parent key (must be root or operator) */
    parentKeyId: string;
    /** Tier of the parent key — used for hierarchy validation */
    parentTier: KeyTier;
    /** Parent key's permissions — used to constrain child */
    parentPermissions: KeyPermissions;
    /** Master seed for BIP-32 derivation */
    masterSeed: Uint8Array;
    /** Derivation index for this agent key */
    index: number;
    /** Custom permissions (will be constrained to parent's permissions) */
    permissions?: KeyPermissions;
    /** Scope constraints */
    scope?: Partial<KeyScope>;
    /** Spending limits per token */
    spendingLimits?: SpendingLimit[];
}
/**
 * Create a new agent key derived from the master seed.
 *
 * Validates:
 * - Parent must be root or operator
 * - Parent must have CREATE_AGENT_KEY permission
 *
 * Agent keys always have spending limits and contract allowlists applied.
 * Permissions are constrained to the intersection of the parent's permissions
 * and the requested permissions.
 */
export declare function createAgentKey(params: CreateAgentKeyParams): {
    key: VaultKey;
    privateKey: Uint8Array;
};
//# sourceMappingURL=agent-key.d.ts.map