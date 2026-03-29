/**
 * MACHINA Vault — Operator Key CRUD
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Operator keys are created by root keys only.
 * They can create agent and session keys, manage policies, and sign transactions.
 */
import { DEFAULT_OPERATOR_PERMISSIONS, constrainPermissions, validateKeyCreation, } from "./permissions.js";
import { deriveOperatorKey } from "./derivation.js";
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
export function createOperatorKey(params) {
    const { vaultId, name, parentKeyId, masterSeed, index, permissions, scope, } = params;
    // Hierarchy enforcement: only root can create operator keys
    validateKeyCreation("root", { mask: (1n << 256n) - 1n }, "operator");
    // Derive the key pair
    const derived = deriveOperatorKey(masterSeed, index);
    // Constrain permissions: operator can never exceed what root allows
    const effectivePermissions = permissions
        ? constrainPermissions({ mask: (1n << 256n) - 1n }, permissions)
        : DEFAULT_OPERATOR_PERMISSIONS;
    const now = new Date().toISOString();
    const today = now.slice(0, 10);
    const month = now.slice(0, 7);
    const key = {
        id: `key_op_${vaultId}_${index}`,
        vaultId,
        tier: "operator",
        name,
        publicKey: derived.publicKey,
        address: derived.address,
        parentKeyId,
        permissions: effectivePermissions,
        scope: {
            allowedChains: scope?.allowedChains ?? [],
            allowedContracts: scope?.allowedContracts ?? [],
            allowedFunctions: scope?.allowedFunctions ?? [],
            spendingLimits: scope?.spendingLimits ?? [],
            expiry: scope?.expiry ?? null,
            autoRotateInterval: scope?.autoRotateInterval ?? null,
        },
        status: "active",
        signCount: 0,
        createdAt: now,
        expiresAt: scope?.expiry ?? null,
        revokedAt: null,
        lastUsedAt: null,
        spentToday: {},
        spentThisMonth: {},
        lastResetDay: today,
        lastResetMonth: month,
    };
    return { key, privateKey: derived.privateKey };
}
//# sourceMappingURL=operator-key.js.map