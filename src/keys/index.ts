/**
 * MACHINA Vault — Key Hierarchy Module
 * MAC-897: 4-Tier Key Hierarchy (Root → Operator → Agent → Session Keys)
 *
 * @packageDocumentation
 */

// Types
export type {
  KeyTier,
  KeyStatus,
  KeyPermissions,
  SpendingLimit,
  KeyScope,
  VaultKey,
} from "./types.js";
export { PERM } from "./types.js";

// Permissions
export {
  createPermissions,
  hasPermission,
  hasAllPermissions,
  hasAnyPermission,
  mergePermissions,
  intersectPermissions,
  constrainPermissions,
  canCreateKeyOfTier,
  requiredPermissionForTier,
  validateKeyCreation,
  ROOT_PERMISSIONS,
  DEFAULT_OPERATOR_PERMISSIONS,
  DEFAULT_AGENT_PERMISSIONS,
  DEFAULT_SESSION_PERMISSIONS,
} from "./permissions.js";

// Derivation
export {
  deriveMasterSeed,
  deriveKeyAtPath,
  publicKeyToEvmAddress,
  deriveOperatorKey,
  deriveAgentKey,
  generateSessionKey,
  COIN_TYPE,
  DERIVATION_PATHS,
  OPERATOR_PATH,
  AGENT_PATH,
} from "./derivation.js";

// Root key
export { createRootKey } from "./root-key.js";

// Operator key
export { createOperatorKey } from "./operator-key.js";
export type { CreateOperatorKeyParams } from "./operator-key.js";

// Agent key
export { createAgentKey } from "./agent-key.js";
export type { CreateAgentKeyParams } from "./agent-key.js";

// Session key
export { createSessionKey } from "./session-key.js";
export type { CreateSessionKeyParams } from "./session-key.js";

// Spending limits
export {
  checkSpendingLimit,
  recordSpend,
  resetDailySpend,
  resetMonthlySpend,
} from "./spending.js";
export type { SpendCheckResult } from "./spending.js";

// Key rotation
export { shouldRotate, rotateKey } from "./rotation.js";
export type { RotateKeyParams, RotateKeyResult } from "./rotation.js";
