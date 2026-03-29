/**
 * MACHINA Vault — Operator Key CRUD
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Operator keys are created by root keys only.
 * They can create agent and session keys, manage policies, and sign transactions.
 */
import type { KeyPermissions, KeyScope, VaultKey } from "./types.js";
export interface CreateOperatorKeyParams {
    vaultId: string;
    name: string;
    /** ID of the parent key (must be a root key) */
    parentKeyId: string;
    /** Master seed for BIP-32 derivation */
    masterSeed: Uint8Array;
    /** Derivation index for this operator key */
    index: number;
    /** Custom permissions (will be constrained to parent's permissions) */
    permissions?: KeyPermissions;
    /** Scope constraints */
    scope?: Partial<KeyScope>;
}
/**
 * Create a new operator key derived from the master seed.
 *
 * Validates:
 * - Parent must be a root key
 * - Parent must have CREATE_OPERATOR_KEY permission
 *
 * Permissions are constrained to the intersection of the parent's permissions
 * and the requested permissions (defaults to DEFAULT_OPERATOR_PERMISSIONS).
 */
export declare function createOperatorKey(params: CreateOperatorKeyParams): {
    key: VaultKey;
    privateKey: Uint8Array;
};
//# sourceMappingURL=operator-key.d.ts.map