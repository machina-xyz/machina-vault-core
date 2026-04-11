/**
 * MACHINA Vault — Agent Key CRUD
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Agent keys are created by root or operator keys.
 * They can sign transactions and create session keys, subject to spending limits
 * and contract allowlists.
 */
import { DEFAULT_AGENT_PERMISSIONS, constrainPermissions, validateKeyCreation, } from "./permissions.js";
import { deriveAgentKey } from "./derivation.js";
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
export function createAgentKey(params) {
    const { vaultId, name, parentKeyId, parentTier, parentPermissions, masterSeed, index, permissions, scope, spendingLimits, } = params;
    // Hierarchy enforcement: root or operator can create agent keys
    validateKeyCreation(parentTier, parentPermissions, "agent");
    // Derive the key pair
    const derived = deriveAgentKey(masterSeed, index);
    // Constrain permissions to parent's permissions
    const requestedPerms = permissions ?? DEFAULT_AGENT_PERMISSIONS;
    const effectivePermissions = constrainPermissions(parentPermissions, requestedPerms);
    const mergedSpendingLimits = spendingLimits ?? scope?.spendingLimits ?? [];
    const now = new Date().toISOString();
    const today = now.slice(0, 10);
    const month = now.slice(0, 7);
    const key = {
        id: `key_agent_${vaultId}_${index}`,
        vaultId,
        tier: "agent",
        name,
        publicKey: derived.publicKey,
        address: derived.address,
        parentKeyId,
        permissions: effectivePermissions,
        scope: {
            allowedChains: scope?.allowedChains ?? [],
            allowedContracts: scope?.allowedContracts ?? [],
            allowedFunctions: scope?.allowedFunctions ?? [],
            spendingLimits: mergedSpendingLimits,
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
