/**
 * MACHINA Vault — Permission Bitfield Operations
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Permissions are represented as a 256-bit bitfield stored as a bigint.
 * Each bit position corresponds to a specific permission (see PERM in types.ts).
 */
import type { KeyPermissions, KeyTier } from "./types.js";
/** Create a KeyPermissions mask with the given bit positions set. */
export declare function createPermissions(...bits: bigint[]): KeyPermissions;
/** Check whether a single permission bit is set. */
export declare function hasPermission(perms: KeyPermissions, bit: bigint): boolean;
/** Check whether ALL of the given permission bits are set. */
export declare function hasAllPermissions(perms: KeyPermissions, bits: bigint[]): boolean;
/** Check whether ANY of the given permission bits are set. */
export declare function hasAnyPermission(perms: KeyPermissions, bits: bigint[]): boolean;
/** Merge two permission sets (union). */
export declare function mergePermissions(a: KeyPermissions, b: KeyPermissions): KeyPermissions;
/** Intersect two permission sets. */
export declare function intersectPermissions(a: KeyPermissions, b: KeyPermissions): KeyPermissions;
/**
 * Constrain child permissions to be a subset of parent permissions.
 * The child can never have more permissions than the parent.
 */
export declare function constrainPermissions(parent: KeyPermissions, requested: KeyPermissions): KeyPermissions;
/** Root keys have all 256 bits set — full authority over the vault. */
export declare const ROOT_PERMISSIONS: KeyPermissions;
/** Operator keys: create/revoke agent + session keys, sign, manage policy, view. */
export declare const DEFAULT_OPERATOR_PERMISSIONS: KeyPermissions;
/** Agent keys: sign transactions + view balances only. */
export declare const DEFAULT_AGENT_PERMISSIONS: KeyPermissions;
/** Session keys: sign only, single-purpose ephemeral key. */
export declare const DEFAULT_SESSION_PERMISSIONS: KeyPermissions;
/**
 * Check whether a parent tier is allowed to create a child tier.
 * Rules:
 *  - root → operator, agent, session  (can create any lower tier)
 *  - operator → agent, session
 *  - agent → session
 *  - session → NOTHING
 */
export declare function canCreateKeyOfTier(parentTier: KeyTier, childTier: KeyTier): boolean;
/**
 * Get the required permission bit for creating a key of the given tier.
 */
export declare function requiredPermissionForTier(childTier: KeyTier): bigint;
/**
 * Validate that a parent key has authority to create a child of the given tier.
 * Throws if the hierarchy or permission check fails.
 */
export declare function validateKeyCreation(parentTier: KeyTier, parentPermissions: KeyPermissions, childTier: KeyTier): void;
//# sourceMappingURL=permissions.d.ts.map