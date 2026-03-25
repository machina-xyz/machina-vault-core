/**
 * MACHINA Vault — Session Key CRUD
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Session keys are ephemeral, NOT derived from the master seed.
 * They are generated from fresh random bytes and have short TTLs.
 * Session keys cannot create any other keys.
 */

import type {
  KeyPermissions,
  KeyScope,
  KeyTier,
  VaultKey,
} from "./types.js";
import {
  DEFAULT_SESSION_PERMISSIONS,
  constrainPermissions,
  validateKeyCreation,
} from "./permissions.js";
import { generateSessionKey as generateEphemeralKey } from "./derivation.js";

/** Default TTL for session keys: 1 hour (3600 seconds) */
const DEFAULT_SESSION_TTL_SECONDS = 3600;

/** Maximum TTL for session keys: 24 hours */
const MAX_SESSION_TTL_SECONDS = 86400;

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
export function createSessionKey(params: CreateSessionKeyParams): {
  key: VaultKey;
  privateKey: Uint8Array;
} {
  const {
    vaultId,
    name,
    parentKeyId,
    parentTier,
    parentPermissions,
    scope,
    ttlSeconds,
  } = params;

  // Hierarchy enforcement: root, operator, or agent can create session keys
  validateKeyCreation(parentTier, parentPermissions, "session");

  // Clamp TTL
  const ttl = Math.min(
    Math.max(ttlSeconds ?? DEFAULT_SESSION_TTL_SECONDS, 1),
    MAX_SESSION_TTL_SECONDS,
  );

  // Generate ephemeral key pair (NOT derived from master seed)
  const ephemeral = generateEphemeralKey();

  // Session keys get the most restricted permission set
  const effectivePermissions = constrainPermissions(
    parentPermissions,
    DEFAULT_SESSION_PERMISSIONS,
  );

  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + ttl * 1000).toISOString();
  const today = createdAt.slice(0, 10);
  const month = createdAt.slice(0, 7);

  // Generate a unique ID using timestamp + random suffix
  const idSuffix = bytesToHex(ephemeral.publicKey.slice(1, 5));

  const key: VaultKey = {
    id: `key_session_${vaultId}_${idSuffix}`,
    vaultId,
    tier: "session",
    name,
    publicKey: ephemeral.publicKey,
    address: ephemeral.address,
    parentKeyId,
    permissions: effectivePermissions,
    scope: {
      allowedChains: scope.allowedChains ?? [],
      allowedContracts: scope.allowedContracts ?? [],
      allowedFunctions: scope.allowedFunctions ?? [],
      spendingLimits: scope.spendingLimits ?? [],
      expiry: expiresAt,
      autoRotateInterval: null, // session keys don't auto-rotate
    },
    status: "active",
    signCount: 0,
    createdAt,
    expiresAt,
    revokedAt: null,
    lastUsedAt: null,
    spentToday: {},
    spentThisMonth: {},
    lastResetDay: today,
    lastResetMonth: month,
  };

  return { key, privateKey: ephemeral.privateKey };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}
