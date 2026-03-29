/**
 * MACHINA Vault — Permission Bitfield Operations
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Permissions are represented as a 256-bit bitfield stored as a bigint.
 * Each bit position corresponds to a specific permission (see PERM in types.ts).
 */
import { PERM } from "./types.js";
// ---------------------------------------------------------------------------
// Core bitfield operations
// ---------------------------------------------------------------------------
/** Create a KeyPermissions mask with the given bit positions set. */
export function createPermissions(...bits) {
    let mask = 0n;
    for (const bit of bits) {
        mask |= 1n << bit;
    }
    return { mask };
}
/** Check whether a single permission bit is set. */
export function hasPermission(perms, bit) {
    return (perms.mask & (1n << bit)) !== 0n;
}
/** Check whether ALL of the given permission bits are set. */
export function hasAllPermissions(perms, bits) {
    for (const bit of bits) {
        if ((perms.mask & (1n << bit)) === 0n)
            return false;
    }
    return true;
}
/** Check whether ANY of the given permission bits are set. */
export function hasAnyPermission(perms, bits) {
    for (const bit of bits) {
        if ((perms.mask & (1n << bit)) !== 0n)
            return true;
    }
    return false;
}
/** Merge two permission sets (union). */
export function mergePermissions(a, b) {
    return { mask: a.mask | b.mask };
}
/** Intersect two permission sets. */
export function intersectPermissions(a, b) {
    return { mask: a.mask & b.mask };
}
/**
 * Constrain child permissions to be a subset of parent permissions.
 * The child can never have more permissions than the parent.
 */
export function constrainPermissions(parent, requested) {
    return { mask: parent.mask & requested.mask };
}
// ---------------------------------------------------------------------------
// Default permission sets per tier
// ---------------------------------------------------------------------------
/** Root keys have all 256 bits set — full authority over the vault. */
export const ROOT_PERMISSIONS = {
    mask: (1n << 256n) - 1n,
};
/** Operator keys: create/revoke agent + session keys, sign, manage policy, view. */
export const DEFAULT_OPERATOR_PERMISSIONS = createPermissions(PERM.CREATE_AGENT_KEY, PERM.REVOKE_AGENT_KEY, PERM.CREATE_SESSION_KEY, PERM.REVOKE_SESSION_KEY, PERM.SIGN_TRANSACTION, PERM.MANAGE_POLICY, PERM.VIEW_BALANCES, PERM.APPROVE_TRANSACTION, PERM.MANAGE_ALLOWLIST, PERM.ROTATE_KEYS, PERM.VIEW_AUDIT_LOG, PERM.MANAGE_WEBHOOKS);
/** Agent keys: sign transactions + view balances only. */
export const DEFAULT_AGENT_PERMISSIONS = createPermissions(PERM.CREATE_SESSION_KEY, PERM.REVOKE_SESSION_KEY, PERM.SIGN_TRANSACTION, PERM.VIEW_BALANCES);
/** Session keys: sign only, single-purpose ephemeral key. */
export const DEFAULT_SESSION_PERMISSIONS = createPermissions(PERM.SIGN_TRANSACTION);
// ---------------------------------------------------------------------------
// Hierarchy enforcement
// ---------------------------------------------------------------------------
/**
 * Tier depth: root (0) → operator (1) → agent (2) → session (3).
 * A key can only create keys at a STRICTLY lower tier (higher depth).
 */
const TIER_DEPTH = {
    root: 0,
    operator: 1,
    agent: 2,
    session: 3,
};
/**
 * Check whether a parent tier is allowed to create a child tier.
 * Rules:
 *  - root → operator, agent, session  (can create any lower tier)
 *  - operator → agent, session
 *  - agent → session
 *  - session → NOTHING
 */
export function canCreateKeyOfTier(parentTier, childTier) {
    return TIER_DEPTH[parentTier] < TIER_DEPTH[childTier];
}
/**
 * Get the required permission bit for creating a key of the given tier.
 */
export function requiredPermissionForTier(childTier) {
    switch (childTier) {
        case "operator":
            return PERM.CREATE_OPERATOR_KEY;
        case "agent":
            return PERM.CREATE_AGENT_KEY;
        case "session":
            return PERM.CREATE_SESSION_KEY;
        default:
            throw new Error(`Cannot create a key of tier "${childTier}"`);
    }
}
/**
 * Validate that a parent key has authority to create a child of the given tier.
 * Throws if the hierarchy or permission check fails.
 */
export function validateKeyCreation(parentTier, parentPermissions, childTier) {
    if (!canCreateKeyOfTier(parentTier, childTier)) {
        throw new Error(`Hierarchy violation: "${parentTier}" key cannot create "${childTier}" key`);
    }
    const required = requiredPermissionForTier(childTier);
    if (!hasPermission(parentPermissions, required)) {
        throw new Error(`Permission denied: parent key lacks CREATE_${childTier.toUpperCase()}_KEY permission`);
    }
}
//# sourceMappingURL=permissions.js.map