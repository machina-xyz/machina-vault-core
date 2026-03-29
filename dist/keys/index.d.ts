/**
 * MACHINA Vault — Key Hierarchy Module
 * MAC-897: 4-Tier Key Hierarchy (Root → Operator → Agent → Session Keys)
 *
 * @packageDocumentation
 */
export type { KeyTier, KeyStatus, KeyPermissions, SpendingLimit, KeyScope, VaultKey, } from "./types.js";
export { PERM } from "./types.js";
export { createPermissions, hasPermission, hasAllPermissions, hasAnyPermission, mergePermissions, intersectPermissions, constrainPermissions, canCreateKeyOfTier, requiredPermissionForTier, validateKeyCreation, ROOT_PERMISSIONS, DEFAULT_OPERATOR_PERMISSIONS, DEFAULT_AGENT_PERMISSIONS, DEFAULT_SESSION_PERMISSIONS, } from "./permissions.js";
export { deriveMasterSeed, deriveKeyAtPath, publicKeyToEvmAddress, deriveOperatorKey, deriveAgentKey, generateSessionKey, COIN_TYPE, DERIVATION_PATHS, OPERATOR_PATH, AGENT_PATH, } from "./derivation.js";
export { createRootKey } from "./root-key.js";
export { createOperatorKey } from "./operator-key.js";
export type { CreateOperatorKeyParams } from "./operator-key.js";
export { createAgentKey } from "./agent-key.js";
export type { CreateAgentKeyParams } from "./agent-key.js";
export { createSessionKey } from "./session-key.js";
export type { CreateSessionKeyParams } from "./session-key.js";
export { checkSpendingLimit, recordSpend, resetDailySpend, resetMonthlySpend, } from "./spending.js";
export type { SpendCheckResult } from "./spending.js";
export { shouldRotate, rotateKey } from "./rotation.js";
export type { RotateKeyParams, RotateKeyResult } from "./rotation.js";
//# sourceMappingURL=index.d.ts.map