/**
 * MACHINA Vault — Vault Lifecycle Comprehensive Tests
 *
 * Tests the full vault lifecycle: key hierarchy creation (root, operator,
 * agent, session), spending limit enforcement, key rotation, and storage
 * backend operations. Validates that the 4-tier key hierarchy enforces
 * proper permission delegation, scope constraints, and immutable state updates.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";

import {
  deriveMasterSeed,
  deriveKeyAtPath,
  deriveOperatorKey,
  deriveAgentKey,
  generateSessionKey,
  publicKeyToEvmAddress,
  DERIVATION_PATHS,
} from "../src/keys/derivation.js";

import { createRootKey } from "../src/keys/root-key.js";
import { createOperatorKey } from "../src/keys/operator-key.js";
import type { CreateOperatorKeyParams } from "../src/keys/operator-key.js";
import { createAgentKey } from "../src/keys/agent-key.js";
import type { CreateAgentKeyParams } from "../src/keys/agent-key.js";
import { createSessionKey } from "../src/keys/session-key.js";
import type { CreateSessionKeyParams } from "../src/keys/session-key.js";

import {
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
} from "../src/keys/permissions.js";

import { PERM } from "../src/keys/types.js";
import type { VaultKey, KeyTier } from "../src/keys/types.js";

import {
  checkSpendingLimit,
  recordSpend,
  resetDailySpend,
  resetMonthlySpend,
} from "../src/keys/spending.js";

import { shouldRotate, rotateKey } from "../src/keys/rotation.js";
import type { RotateKeyParams } from "../src/keys/rotation.js";

import { MemoryVaultStore } from "../src/storage/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

const TEST_ENTROPY = new Uint8Array(32);
for (let i = 0; i < 32; i++) TEST_ENTROPY[i] = i + 1;
const TEST_MASTER_SEED = deriveMasterSeed(TEST_ENTROPY);

function makeBaseKey(overrides: Partial<VaultKey> = {}): VaultKey {
  const today = new Date().toISOString().slice(0, 10);
  const month = new Date().toISOString().slice(0, 7);
  return {
    id: "key_agent_vault-001_0",
    vaultId: "vault-001",
    tier: "agent",
    name: "Test Agent Key",
    publicKey: new Uint8Array(33),
    address: "0x0000000000000000000000000000000000000001",
    parentKeyId: "key_op_vault-001_0",
    permissions: DEFAULT_AGENT_PERMISSIONS,
    scope: {
      allowedChains: [],
      allowedContracts: [],
      allowedFunctions: [],
      spendingLimits: [],
      expiry: null,
      autoRotateInterval: null,
    },
    status: "active",
    signCount: 0,
    createdAt: new Date().toISOString(),
    expiresAt: null,
    revokedAt: null,
    lastUsedAt: null,
    spentToday: {},
    spentThisMonth: {},
    lastResetDay: today,
    lastResetMonth: month,
    ...overrides,
  };
}

// ===========================================================================
// ROOT KEY CREATION
// ===========================================================================

describe("Root Key Creation", () => {
  it("should create a root key with all permissions", () => {
    const { publicKey } = deriveKeyAtPath(TEST_MASTER_SEED, DERIVATION_PATHS.evm(0));
    const address = publicKeyToEvmAddress(publicKey);
    const rootKey = createRootKey("vault-001", publicKey, address);

    expect(rootKey.id).toBe("key_root_vault-001");
    expect(rootKey.vaultId).toBe("vault-001");
    expect(rootKey.tier).toBe("root");
    expect(rootKey.name).toBe("Root Key");
    expect(rootKey.parentKeyId).toBeNull();
    expect(rootKey.status).toBe("active");
    expect(rootKey.permissions.mask).toBe(ROOT_PERMISSIONS.mask);
  });

  it("should have no expiry and no spending limits", () => {
    const { publicKey } = deriveKeyAtPath(TEST_MASTER_SEED, DERIVATION_PATHS.evm(0));
    const address = publicKeyToEvmAddress(publicKey);
    const rootKey = createRootKey("vault-001", publicKey, address);

    expect(rootKey.expiresAt).toBeNull();
    expect(rootKey.scope.expiry).toBeNull();
    expect(rootKey.scope.spendingLimits).toEqual([]);
    expect(rootKey.scope.allowedChains).toEqual([]);
  });

  it("should have zero sign count and fresh timestamps", () => {
    const { publicKey } = deriveKeyAtPath(TEST_MASTER_SEED, DERIVATION_PATHS.evm(0));
    const address = publicKeyToEvmAddress(publicKey);
    const rootKey = createRootKey("vault-001", publicKey, address);

    expect(rootKey.signCount).toBe(0);
    expect(rootKey.lastUsedAt).toBeNull();
    expect(rootKey.revokedAt).toBeNull();
    expect(rootKey.createdAt).toBeDefined();
  });

  it("should store the correct public key and address", () => {
    const { publicKey } = deriveKeyAtPath(TEST_MASTER_SEED, DERIVATION_PATHS.evm(0));
    const address = publicKeyToEvmAddress(publicKey);
    const rootKey = createRootKey("vault-001", publicKey, address);

    expect(bytesToHex(rootKey.publicKey)).toBe(bytesToHex(publicKey));
    expect(rootKey.address).toBe(address);
  });
});

// ===========================================================================
// OPERATOR KEY CREATION
// ===========================================================================

describe("Operator Key Creation", () => {
  it("should create an operator key derived from master seed", () => {
    const params: CreateOperatorKeyParams = {
      vaultId: "vault-001",
      name: "Primary Operator",
      parentKeyId: "key_root_vault-001",
      masterSeed: TEST_MASTER_SEED,
      index: 0,
    };

    const { key, privateKey } = createOperatorKey(params);

    expect(key.tier).toBe("operator");
    expect(key.name).toBe("Primary Operator");
    expect(key.parentKeyId).toBe("key_root_vault-001");
    expect(key.id).toBe("key_op_vault-001_0");
    expect(privateKey.length).toBe(32);
    expect(key.publicKey.length).toBe(33);
  });

  it("should produce deterministic keys for the same index", () => {
    const params: CreateOperatorKeyParams = {
      vaultId: "vault-001",
      name: "Op 1",
      parentKeyId: "key_root_vault-001",
      masterSeed: TEST_MASTER_SEED,
      index: 0,
    };

    const first = createOperatorKey(params);
    const second = createOperatorKey(params);

    expect(bytesToHex(first.privateKey)).toBe(bytesToHex(second.privateKey));
    expect(first.key.address).toBe(second.key.address);
  });

  it("should produce different keys for different indices", () => {
    const base = {
      vaultId: "vault-001",
      name: "Op",
      parentKeyId: "key_root_vault-001",
      masterSeed: TEST_MASTER_SEED,
    };

    const k0 = createOperatorKey({ ...base, index: 0 });
    const k1 = createOperatorKey({ ...base, index: 1 });

    expect(k0.key.address).not.toBe(k1.key.address);
    expect(bytesToHex(k0.privateKey)).not.toBe(bytesToHex(k1.privateKey));
  });

  it("should apply default operator permissions", () => {
    const { key } = createOperatorKey({
      vaultId: "vault-001",
      name: "Op",
      parentKeyId: "key_root_vault-001",
      masterSeed: TEST_MASTER_SEED,
      index: 0,
    });

    expect(key.permissions.mask).toBe(DEFAULT_OPERATOR_PERMISSIONS.mask);
    expect(hasPermission(key.permissions, PERM.CREATE_AGENT_KEY)).toBe(true);
    expect(hasPermission(key.permissions, PERM.SIGN_TRANSACTION)).toBe(true);
    // Operators should NOT have CREATE_OPERATOR_KEY (only root can)
    expect(hasPermission(key.permissions, PERM.CREATE_OPERATOR_KEY)).toBe(false);
  });

  it("should apply custom permissions constrained by root", () => {
    const customPerms = createPermissions(PERM.SIGN_TRANSACTION, PERM.VIEW_BALANCES);
    const { key } = createOperatorKey({
      vaultId: "vault-001",
      name: "Limited Op",
      parentKeyId: "key_root_vault-001",
      masterSeed: TEST_MASTER_SEED,
      index: 0,
      permissions: customPerms,
    });

    expect(hasPermission(key.permissions, PERM.SIGN_TRANSACTION)).toBe(true);
    expect(hasPermission(key.permissions, PERM.VIEW_BALANCES)).toBe(true);
    // Should not have permissions not in the custom set
    expect(hasPermission(key.permissions, PERM.MANAGE_POLICY)).toBe(false);
  });

  it("should apply scope constraints", () => {
    const { key } = createOperatorKey({
      vaultId: "vault-001",
      name: "Scoped Op",
      parentKeyId: "key_root_vault-001",
      masterSeed: TEST_MASTER_SEED,
      index: 0,
      scope: {
        allowedChains: ["1", "8453"],
        expiry: "2027-01-01T00:00:00.000Z",
        autoRotateInterval: "P7D",
      },
    });

    expect(key.scope.allowedChains).toEqual(["1", "8453"]);
    expect(key.scope.expiry).toBe("2027-01-01T00:00:00.000Z");
    expect(key.scope.autoRotateInterval).toBe("P7D");
    expect(key.expiresAt).toBe("2027-01-01T00:00:00.000Z");
  });
});

// ===========================================================================
// AGENT KEY CREATION
// ===========================================================================

describe("Agent Key Creation", () => {
  it("should create an agent key from an operator parent", () => {
    const params: CreateAgentKeyParams = {
      vaultId: "vault-001",
      name: "DeFi Agent",
      parentKeyId: "key_op_vault-001_0",
      parentTier: "operator",
      parentPermissions: DEFAULT_OPERATOR_PERMISSIONS,
      masterSeed: TEST_MASTER_SEED,
      index: 0,
    };

    const { key, privateKey } = createAgentKey(params);

    expect(key.tier).toBe("agent");
    expect(key.id).toBe("key_agent_vault-001_0");
    expect(key.parentKeyId).toBe("key_op_vault-001_0");
    expect(privateKey.length).toBe(32);
  });

  it("should create an agent key from a root parent", () => {
    const { key } = createAgentKey({
      vaultId: "vault-001",
      name: "Root-created Agent",
      parentKeyId: "key_root_vault-001",
      parentTier: "root",
      parentPermissions: ROOT_PERMISSIONS,
      masterSeed: TEST_MASTER_SEED,
      index: 0,
    });

    expect(key.tier).toBe("agent");
    expect(key.parentKeyId).toBe("key_root_vault-001");
  });

  it("should constrain agent permissions to parent permissions", () => {
    // Operator without SIGN_TRANSACTION
    const limitedOp = createPermissions(PERM.CREATE_AGENT_KEY, PERM.VIEW_BALANCES);

    const { key } = createAgentKey({
      vaultId: "vault-001",
      name: "Limited Agent",
      parentKeyId: "key_op_vault-001_0",
      parentTier: "operator",
      parentPermissions: limitedOp,
      masterSeed: TEST_MASTER_SEED,
      index: 0,
    });

    // Agent requests SIGN_TRANSACTION by default, but parent doesn't have it
    expect(hasPermission(key.permissions, PERM.SIGN_TRANSACTION)).toBe(false);
    expect(hasPermission(key.permissions, PERM.VIEW_BALANCES)).toBe(true);
  });

  it("should reject agent creation from session tier", () => {
    expect(() =>
      createAgentKey({
        vaultId: "vault-001",
        name: "Bad Agent",
        parentKeyId: "key_session_vault-001_x",
        parentTier: "session",
        parentPermissions: DEFAULT_SESSION_PERMISSIONS,
        masterSeed: TEST_MASTER_SEED,
        index: 0,
      }),
    ).toThrow(/hierarchy/i);
  });

  it("should reject agent creation from agent tier", () => {
    expect(() =>
      createAgentKey({
        vaultId: "vault-001",
        name: "Bad Agent",
        parentKeyId: "key_agent_vault-001_0",
        parentTier: "agent",
        parentPermissions: DEFAULT_AGENT_PERMISSIONS,
        masterSeed: TEST_MASTER_SEED,
        index: 0,
      }),
    ).toThrow(/hierarchy/i);
  });

  it("should apply spending limits", () => {
    const limits = [
      {
        tokenAddress: "native",
        perTx: 1_000_000_000_000_000_000n, // 1 ETH
        daily: 5_000_000_000_000_000_000n,
        monthly: 50_000_000_000_000_000_000n,
      },
    ];

    const { key } = createAgentKey({
      vaultId: "vault-001",
      name: "Limited Agent",
      parentKeyId: "key_op_vault-001_0",
      parentTier: "operator",
      parentPermissions: DEFAULT_OPERATOR_PERMISSIONS,
      masterSeed: TEST_MASTER_SEED,
      index: 0,
      spendingLimits: limits,
    });

    expect(key.scope.spendingLimits.length).toBe(1);
    expect(key.scope.spendingLimits[0].tokenAddress).toBe("native");
    expect(key.scope.spendingLimits[0].perTx).toBe(1_000_000_000_000_000_000n);
  });
});

// ===========================================================================
// SESSION KEY CREATION
// ===========================================================================

describe("Session Key Creation", () => {
  it("should create a session key with default TTL", () => {
    const params: CreateSessionKeyParams = {
      vaultId: "vault-001",
      name: "Swap Session",
      parentKeyId: "key_agent_vault-001_0",
      parentTier: "agent",
      parentPermissions: DEFAULT_AGENT_PERMISSIONS,
      scope: { allowedChains: ["1"] },
    };

    const { key, privateKey } = createSessionKey(params);

    expect(key.tier).toBe("session");
    expect(key.parentKeyId).toBe("key_agent_vault-001_0");
    expect(privateKey.length).toBe(32);
    expect(key.publicKey.length).toBe(33);
    expect(key.expiresAt).not.toBeNull();

    // Default TTL is 1 hour
    const created = new Date(key.createdAt).getTime();
    const expires = new Date(key.expiresAt!).getTime();
    const diffSeconds = (expires - created) / 1000;
    expect(diffSeconds).toBeCloseTo(3600, -1);
  });

  it("should create session keys from root, operator, and agent", () => {
    const tiers: Array<{ tier: KeyTier; perms: typeof ROOT_PERMISSIONS }> = [
      { tier: "root", perms: ROOT_PERMISSIONS },
      { tier: "operator", perms: DEFAULT_OPERATOR_PERMISSIONS },
      { tier: "agent", perms: DEFAULT_AGENT_PERMISSIONS },
    ];

    for (const { tier, perms } of tiers) {
      const { key } = createSessionKey({
        vaultId: "vault-001",
        name: `Session from ${tier}`,
        parentKeyId: `key_${tier}_vault-001_0`,
        parentTier: tier,
        parentPermissions: perms,
        scope: {},
      });
      expect(key.tier).toBe("session");
    }
  });

  it("should reject session key creation from session tier", () => {
    expect(() =>
      createSessionKey({
        vaultId: "vault-001",
        name: "Bad Session",
        parentKeyId: "key_session_vault-001_x",
        parentTier: "session",
        parentPermissions: DEFAULT_SESSION_PERMISSIONS,
        scope: {},
      }),
    ).toThrow(/hierarchy/i);
  });

  it("should clamp TTL to maximum 24 hours", () => {
    const { key } = createSessionKey({
      vaultId: "vault-001",
      name: "Long Session",
      parentKeyId: "key_agent_vault-001_0",
      parentTier: "agent",
      parentPermissions: DEFAULT_AGENT_PERMISSIONS,
      scope: {},
      ttlSeconds: 999999, // way over 24h
    });

    const created = new Date(key.createdAt).getTime();
    const expires = new Date(key.expiresAt!).getTime();
    const diffSeconds = (expires - created) / 1000;
    expect(diffSeconds).toBeLessThanOrEqual(86400 + 1); // 24h + 1s tolerance
  });

  it("should clamp TTL minimum to 1 second", () => {
    const { key } = createSessionKey({
      vaultId: "vault-001",
      name: "Tiny Session",
      parentKeyId: "key_agent_vault-001_0",
      parentTier: "agent",
      parentPermissions: DEFAULT_AGENT_PERMISSIONS,
      scope: {},
      ttlSeconds: 0,
    });

    const created = new Date(key.createdAt).getTime();
    const expires = new Date(key.expiresAt!).getTime();
    const diffSeconds = (expires - created) / 1000;
    expect(diffSeconds).toBeGreaterThanOrEqual(1);
  });

  it("should produce unique session keys (random, not deterministic)", () => {
    const keys = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const { key } = createSessionKey({
        vaultId: "vault-001",
        name: `Session ${i}`,
        parentKeyId: "key_agent_vault-001_0",
        parentTier: "agent",
        parentPermissions: DEFAULT_AGENT_PERMISSIONS,
        scope: {},
      });
      keys.add(key.address);
    }
    expect(keys.size).toBe(10);
  });

  it("should only have SIGN_TRANSACTION permission", () => {
    const { key } = createSessionKey({
      vaultId: "vault-001",
      name: "Session",
      parentKeyId: "key_agent_vault-001_0",
      parentTier: "agent",
      parentPermissions: DEFAULT_AGENT_PERMISSIONS,
      scope: {},
    });

    expect(hasPermission(key.permissions, PERM.SIGN_TRANSACTION)).toBe(true);
    expect(hasPermission(key.permissions, PERM.CREATE_AGENT_KEY)).toBe(false);
    expect(hasPermission(key.permissions, PERM.MANAGE_POLICY)).toBe(false);
  });
});

// ===========================================================================
// PERMISSION BITFIELD OPERATIONS
// ===========================================================================

describe("Permission Bitfield Operations", () => {
  it("should create permission masks from bit positions", () => {
    const perms = createPermissions(PERM.SIGN_TRANSACTION, PERM.VIEW_BALANCES);
    expect(hasPermission(perms, PERM.SIGN_TRANSACTION)).toBe(true);
    expect(hasPermission(perms, PERM.VIEW_BALANCES)).toBe(true);
    expect(hasPermission(perms, PERM.MANAGE_POLICY)).toBe(false);
  });

  it("should check all permissions", () => {
    const perms = createPermissions(PERM.SIGN_TRANSACTION, PERM.VIEW_BALANCES);
    expect(hasAllPermissions(perms, [PERM.SIGN_TRANSACTION, PERM.VIEW_BALANCES])).toBe(true);
    expect(hasAllPermissions(perms, [PERM.SIGN_TRANSACTION, PERM.MANAGE_POLICY])).toBe(false);
  });

  it("should check any permission", () => {
    const perms = createPermissions(PERM.SIGN_TRANSACTION);
    expect(hasAnyPermission(perms, [PERM.SIGN_TRANSACTION, PERM.MANAGE_POLICY])).toBe(true);
    expect(hasAnyPermission(perms, [PERM.MANAGE_POLICY, PERM.INITIATE_RECOVERY])).toBe(false);
  });

  it("should merge permission sets (union)", () => {
    const a = createPermissions(PERM.SIGN_TRANSACTION);
    const b = createPermissions(PERM.VIEW_BALANCES);
    const merged = mergePermissions(a, b);
    expect(hasPermission(merged, PERM.SIGN_TRANSACTION)).toBe(true);
    expect(hasPermission(merged, PERM.VIEW_BALANCES)).toBe(true);
  });

  it("should intersect permission sets", () => {
    const a = createPermissions(PERM.SIGN_TRANSACTION, PERM.VIEW_BALANCES);
    const b = createPermissions(PERM.SIGN_TRANSACTION, PERM.MANAGE_POLICY);
    const intersected = intersectPermissions(a, b);
    expect(hasPermission(intersected, PERM.SIGN_TRANSACTION)).toBe(true);
    expect(hasPermission(intersected, PERM.VIEW_BALANCES)).toBe(false);
    expect(hasPermission(intersected, PERM.MANAGE_POLICY)).toBe(false);
  });

  it("should constrain child permissions to parent", () => {
    const parent = createPermissions(PERM.SIGN_TRANSACTION, PERM.VIEW_BALANCES);
    const requested = createPermissions(
      PERM.SIGN_TRANSACTION,
      PERM.VIEW_BALANCES,
      PERM.MANAGE_POLICY,
    );
    const constrained = constrainPermissions(parent, requested);

    expect(hasPermission(constrained, PERM.SIGN_TRANSACTION)).toBe(true);
    expect(hasPermission(constrained, PERM.VIEW_BALANCES)).toBe(true);
    expect(hasPermission(constrained, PERM.MANAGE_POLICY)).toBe(false);
  });

  it("should have all 256 bits set in ROOT_PERMISSIONS", () => {
    expect(ROOT_PERMISSIONS.mask).toBe((1n << 256n) - 1n);
    for (const bit of Object.values(PERM)) {
      expect(hasPermission(ROOT_PERMISSIONS, bit)).toBe(true);
    }
  });
});

// ===========================================================================
// TIER HIERARCHY ENFORCEMENT
// ===========================================================================

describe("Tier Hierarchy Enforcement", () => {
  it("should allow root to create operator, agent, session", () => {
    expect(canCreateKeyOfTier("root", "operator")).toBe(true);
    expect(canCreateKeyOfTier("root", "agent")).toBe(true);
    expect(canCreateKeyOfTier("root", "session")).toBe(true);
  });

  it("should allow operator to create agent and session", () => {
    expect(canCreateKeyOfTier("operator", "agent")).toBe(true);
    expect(canCreateKeyOfTier("operator", "session")).toBe(true);
    expect(canCreateKeyOfTier("operator", "operator")).toBe(false);
    expect(canCreateKeyOfTier("operator", "root")).toBe(false);
  });

  it("should allow agent to create session only", () => {
    expect(canCreateKeyOfTier("agent", "session")).toBe(true);
    expect(canCreateKeyOfTier("agent", "agent")).toBe(false);
    expect(canCreateKeyOfTier("agent", "operator")).toBe(false);
    expect(canCreateKeyOfTier("agent", "root")).toBe(false);
  });

  it("should not allow session to create anything", () => {
    expect(canCreateKeyOfTier("session", "session")).toBe(false);
    expect(canCreateKeyOfTier("session", "agent")).toBe(false);
    expect(canCreateKeyOfTier("session", "operator")).toBe(false);
    expect(canCreateKeyOfTier("session", "root")).toBe(false);
  });

  it("should return correct required permission for each tier", () => {
    expect(requiredPermissionForTier("operator")).toBe(PERM.CREATE_OPERATOR_KEY);
    expect(requiredPermissionForTier("agent")).toBe(PERM.CREATE_AGENT_KEY);
    expect(requiredPermissionForTier("session")).toBe(PERM.CREATE_SESSION_KEY);
  });

  it("should throw for root tier in requiredPermissionForTier", () => {
    expect(() => requiredPermissionForTier("root")).toThrow();
  });

  it("should validate key creation with proper hierarchy and permissions", () => {
    expect(() =>
      validateKeyCreation("root", ROOT_PERMISSIONS, "operator"),
    ).not.toThrow();

    expect(() =>
      validateKeyCreation("operator", DEFAULT_OPERATOR_PERMISSIONS, "agent"),
    ).not.toThrow();
  });

  it("should reject key creation with wrong hierarchy", () => {
    expect(() =>
      validateKeyCreation("agent", DEFAULT_AGENT_PERMISSIONS, "operator"),
    ).toThrow(/hierarchy/i);
  });

  it("should reject key creation with missing permission", () => {
    const noCreateOp = createPermissions(PERM.SIGN_TRANSACTION);
    expect(() =>
      validateKeyCreation("root", noCreateOp, "operator"),
    ).toThrow(/permission/i);
  });
});

// ===========================================================================
// SPENDING LIMIT ENFORCEMENT
// ===========================================================================

describe("Spending Limit Enforcement", () => {
  const ONE_ETH = 1_000_000_000_000_000_000n;

  function makeKeyWithLimits(overrides: Partial<VaultKey> = {}): VaultKey {
    return makeBaseKey({
      scope: {
        allowedChains: [],
        allowedContracts: [],
        allowedFunctions: [],
        spendingLimits: [
          {
            tokenAddress: "native",
            perTx: ONE_ETH,
            daily: 5n * ONE_ETH,
            monthly: 50n * ONE_ETH,
          },
        ],
        expiry: null,
        autoRotateInterval: null,
      },
      ...overrides,
    });
  }

  it("should allow spending within per-tx limit", () => {
    const key = makeKeyWithLimits();
    const result = checkSpendingLimit(key, "native", ONE_ETH / 2n);
    expect(result.allowed).toBe(true);
  });

  it("should reject spending exceeding per-tx limit", () => {
    const key = makeKeyWithLimits();
    const result = checkSpendingLimit(key, "native", ONE_ETH + 1n);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("per-transaction");
  });

  it("should allow spending at exact per-tx limit", () => {
    const key = makeKeyWithLimits();
    const result = checkSpendingLimit(key, "native", ONE_ETH);
    expect(result.allowed).toBe(true);
  });

  it("should reject spending exceeding daily limit", () => {
    const key = makeKeyWithLimits({
      spentToday: { native: 4n * ONE_ETH + ONE_ETH / 2n },
    });
    // Amount is within per-tx limit but would push daily over
    const result = checkSpendingLimit(key, "native", ONE_ETH);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Daily");
  });

  it("should reject spending exceeding monthly limit", () => {
    const key = makeKeyWithLimits({
      spentThisMonth: { native: 49n * ONE_ETH + ONE_ETH / 2n },
    });
    const result = checkSpendingLimit(key, "native", ONE_ETH);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Monthly");
  });

  it("should reject spending from revoked key", () => {
    const key = makeKeyWithLimits({ status: "revoked" });
    const result = checkSpendingLimit(key, "native", 1n);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("revoked");
  });

  it("should reject spending from expired key", () => {
    const key = makeKeyWithLimits({
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    const result = checkSpendingLimit(key, "native", 1n);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("expired");
  });

  it("should allow spending for token with no limits defined", () => {
    const key = makeKeyWithLimits();
    const result = checkSpendingLimit(key, "0xusdc", ONE_ETH * 1000n);
    expect(result.allowed).toBe(true);
  });

  it("should record spend and update tracking immutably", () => {
    const key = makeKeyWithLimits();
    const updated = recordSpend(key, "native", ONE_ETH);

    // Original should be unchanged
    expect(key.spentToday).toEqual({});
    expect(key.signCount).toBe(0);

    // Updated should reflect spend
    expect(updated.spentToday.native).toBe(ONE_ETH);
    expect(updated.spentThisMonth.native).toBe(ONE_ETH);
    expect(updated.signCount).toBe(1);
    expect(updated.lastUsedAt).not.toBeNull();
  });

  it("should accumulate multiple spends", () => {
    const key = makeKeyWithLimits();
    let updated = recordSpend(key, "native", ONE_ETH);
    updated = recordSpend(updated, "native", ONE_ETH);

    expect(updated.spentToday.native).toBe(2n * ONE_ETH);
    expect(updated.spentThisMonth.native).toBe(2n * ONE_ETH);
    expect(updated.signCount).toBe(2);
  });

  it("should reset daily spend when day changes", () => {
    const yesterday = new Date(Date.now() - 86400 * 1000).toISOString().slice(0, 10);
    const key = makeKeyWithLimits({
      spentToday: { native: ONE_ETH * 4n },
      lastResetDay: yesterday,
    });

    const reset = resetDailySpend(key);
    expect(reset.spentToday).toEqual({});
    expect(reset.lastResetDay).not.toBe(yesterday);
  });

  it("should not reset daily spend when same day", () => {
    const today = new Date().toISOString().slice(0, 10);
    const key = makeKeyWithLimits({
      spentToday: { native: ONE_ETH },
      lastResetDay: today,
    });

    const result = resetDailySpend(key);
    // Should return same object (no reset needed)
    expect(result).toBe(key);
  });

  it("should reset monthly spend when month changes", () => {
    const lastMonth = "2025-01";
    const key = makeKeyWithLimits({
      spentThisMonth: { native: ONE_ETH * 40n },
      lastResetMonth: lastMonth,
    });

    const reset = resetMonthlySpend(key);
    expect(reset.spentThisMonth).toEqual({});
    expect(reset.lastResetMonth).not.toBe(lastMonth);
  });
});

// ===========================================================================
// KEY ROTATION
// ===========================================================================

describe("Key Rotation", () => {
  function makeOperatorKey(overrides: Partial<VaultKey> = {}): VaultKey {
    const derived = deriveOperatorKey(TEST_MASTER_SEED, 0);
    return makeBaseKey({
      id: "key_op_vault-001_0",
      tier: "operator",
      name: "Operator 0",
      publicKey: derived.publicKey,
      address: derived.address,
      ...overrides,
    });
  }

  it("should not rotate key without autoRotateInterval", () => {
    const key = makeOperatorKey();
    expect(shouldRotate(key)).toBe(false);
  });

  it("should not rotate freshly created key with interval", () => {
    const key = makeOperatorKey({
      scope: {
        allowedChains: [],
        allowedContracts: [],
        allowedFunctions: [],
        spendingLimits: [],
        expiry: null,
        autoRotateInterval: "P30D", // 30 days
      },
      createdAt: new Date().toISOString(),
    });
    expect(shouldRotate(key)).toBe(false);
  });

  it("should rotate key past its interval", () => {
    const oldDate = new Date(Date.now() - 31 * 86400 * 1000).toISOString();
    const key = makeOperatorKey({
      scope: {
        allowedChains: [],
        allowedContracts: [],
        allowedFunctions: [],
        spendingLimits: [],
        expiry: null,
        autoRotateInterval: "P30D",
      },
      createdAt: oldDate,
    });
    expect(shouldRotate(key)).toBe(true);
  });

  it("should not rotate revoked key", () => {
    const key = makeOperatorKey({ status: "revoked" });
    expect(shouldRotate(key)).toBe(false);
  });

  it("should create new key and mark old as rotating", () => {
    const oldKey = makeOperatorKey();
    const params: RotateKeyParams = {
      oldKey,
      masterSeed: TEST_MASTER_SEED,
      newIndex: 1,
    };

    const result = rotateKey(params);

    expect(result.oldKeyUpdated.status).toBe("rotating");
    expect(result.newKey.status).toBe("active");
    expect(result.newKey.tier).toBe("operator");
    expect(result.newKey.address).not.toBe(oldKey.address);
    expect(result.newPrivateKey.length).toBe(32);
    expect(result.overlapExpiresAt).toBeDefined();
  });

  it("should inherit permissions and scope from old key", () => {
    const oldKey = makeOperatorKey({
      permissions: createPermissions(PERM.SIGN_TRANSACTION, PERM.VIEW_BALANCES),
      scope: {
        allowedChains: ["1", "8453"],
        allowedContracts: [],
        allowedFunctions: [],
        spendingLimits: [],
        expiry: null,
        autoRotateInterval: "P7D",
      },
    });

    const result = rotateKey({ oldKey, masterSeed: TEST_MASTER_SEED, newIndex: 1 });

    expect(result.newKey.permissions.mask).toBe(oldKey.permissions.mask);
    expect(result.newKey.scope.allowedChains).toEqual(["1", "8453"]);
  });

  it("should reject rotation of root keys", () => {
    const rootKey = makeBaseKey({ tier: "root" });
    expect(() =>
      rotateKey({ oldKey: rootKey, masterSeed: TEST_MASTER_SEED, newIndex: 1 }),
    ).toThrow(/root/i);
  });

  it("should reject rotation of session keys", () => {
    const sessionKey = makeBaseKey({ tier: "session" });
    expect(() =>
      rotateKey({ oldKey: sessionKey, masterSeed: TEST_MASTER_SEED, newIndex: 1 }),
    ).toThrow(/session/i);
  });

  it("should reject rotation of non-active keys", () => {
    const revokedKey = makeOperatorKey({ status: "revoked" });
    expect(() =>
      rotateKey({ oldKey: revokedKey, masterSeed: TEST_MASTER_SEED, newIndex: 1 }),
    ).toThrow(/active/i);
  });

  it("should rotate agent keys", () => {
    const derived = deriveAgentKey(TEST_MASTER_SEED, 0);
    const agentKey = makeBaseKey({
      id: "key_agent_vault-001_0",
      tier: "agent",
      publicKey: derived.publicKey,
      address: derived.address,
    });

    const result = rotateKey({ oldKey: agentKey, masterSeed: TEST_MASTER_SEED, newIndex: 1 });
    expect(result.newKey.tier).toBe("agent");
    expect(result.newKey.id).toContain("agent");
  });
});

// ===========================================================================
// MEMORY VAULT STORE
// ===========================================================================

describe("MemoryVaultStore", () => {
  let store: MemoryVaultStore;

  beforeEach(() => {
    store = new MemoryVaultStore();
  });

  it("should set and get a value", async () => {
    await store.set("key1", "value1");
    const result = await store.get("key1");
    expect(result).toBe("value1");
  });

  it("should return null for missing key", async () => {
    const result = await store.get("nonexistent");
    expect(result).toBeNull();
  });

  it("should overwrite existing value", async () => {
    await store.set("key1", "old");
    await store.set("key1", "new");
    expect(await store.get("key1")).toBe("new");
  });

  it("should delete a key", async () => {
    await store.set("key1", "value1");
    await store.delete("key1");
    expect(await store.get("key1")).toBeNull();
  });

  it("should list all keys", async () => {
    await store.set("a", "1");
    await store.set("b", "2");
    await store.set("c", "3");
    const keys = await store.list();
    expect(keys.sort()).toEqual(["a", "b", "c"]);
  });

  it("should clear all data", async () => {
    await store.set("a", "1");
    await store.set("b", "2");
    await store.clear();
    const keys = await store.list();
    expect(keys).toEqual([]);
  });

  it("should handle storing JSON wallet records", async () => {
    const record = {
      id: "wallet-001",
      name: "Test Wallet",
      encryptedMnemonic: "encrypted-data-here",
      accounts: [
        { chain: "Ethereum", chain_id: "1", address: "0xabc", derivation_path: "m/44'/60'/0'/0'/0'" },
      ],
      createdAt: new Date().toISOString(),
    };

    await store.set(`wallet:${record.id}`, JSON.stringify(record));
    const json = await store.get(`wallet:${record.id}`);
    expect(json).not.toBeNull();
    const parsed = JSON.parse(json!);
    expect(parsed.id).toBe("wallet-001");
    expect(parsed.accounts.length).toBe(1);
  });

  it("should handle wallet name index", async () => {
    const walletId = "wallet-001";
    const walletName = "my-wallet";
    await store.set(`wallet:${walletId}`, '{"id":"wallet-001"}');
    await store.set(`wallet-name:${walletName}`, walletId);

    // Look up by name
    const id = await store.get(`wallet-name:${walletName}`);
    expect(id).toBe(walletId);
    const data = await store.get(`wallet:${id}`);
    expect(data).not.toBeNull();
  });

  it("should handle concurrent operations", async () => {
    const ops = Array.from({ length: 100 }, (_, i) =>
      store.set(`key-${i}`, `value-${i}`),
    );
    await Promise.all(ops);

    const keys = await store.list();
    expect(keys.length).toBe(100);

    const reads = await Promise.all(
      Array.from({ length: 100 }, (_, i) => store.get(`key-${i}`)),
    );
    for (let i = 0; i < 100; i++) {
      expect(reads[i]).toBe(`value-${i}`);
    }
  });
});

// ===========================================================================
// FULL KEY HIERARCHY FLOW
// ===========================================================================

describe("Full Key Hierarchy Lifecycle", () => {
  it("should create a complete 4-tier hierarchy from entropy", () => {
    // 1. Derive master seed from entropy
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);
    const masterSeed = deriveMasterSeed(entropy);

    // 2. Create root key
    const rootDerived = deriveKeyAtPath(masterSeed, DERIVATION_PATHS.evm(0));
    const rootAddress = publicKeyToEvmAddress(rootDerived.publicKey);
    const rootKey = createRootKey("test-vault", rootDerived.publicKey, rootAddress);

    expect(rootKey.tier).toBe("root");

    // 3. Create operator key
    const { key: operatorKey, privateKey: opPriv } = createOperatorKey({
      vaultId: "test-vault",
      name: "Primary Operator",
      parentKeyId: rootKey.id,
      masterSeed,
      index: 0,
    });

    expect(operatorKey.tier).toBe("operator");
    expect(operatorKey.parentKeyId).toBe(rootKey.id);

    // 4. Create agent key from operator
    const { key: agentKey, privateKey: agentPriv } = createAgentKey({
      vaultId: "test-vault",
      name: "DeFi Agent",
      parentKeyId: operatorKey.id,
      parentTier: "operator",
      parentPermissions: operatorKey.permissions,
      masterSeed,
      index: 0,
      spendingLimits: [
        {
          tokenAddress: "native",
          perTx: 1_000_000_000_000_000_000n,
          daily: 10_000_000_000_000_000_000n,
          monthly: 100_000_000_000_000_000_000n,
        },
      ],
    });

    expect(agentKey.tier).toBe("agent");
    expect(agentKey.parentKeyId).toBe(operatorKey.id);
    expect(agentKey.scope.spendingLimits.length).toBe(1);

    // 5. Create session key from agent
    const { key: sessionKey } = createSessionKey({
      vaultId: "test-vault",
      name: "Swap Session",
      parentKeyId: agentKey.id,
      parentTier: "agent",
      parentPermissions: agentKey.permissions,
      scope: {
        allowedChains: ["1"],
        allowedContracts: ["0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2"],
      },
    });

    expect(sessionKey.tier).toBe("session");
    expect(sessionKey.parentKeyId).toBe(agentKey.id);
    expect(sessionKey.scope.allowedChains).toEqual(["1"]);
    expect(sessionKey.scope.allowedContracts.length).toBe(1);

    // 6. Verify permission delegation
    // Root has all permissions
    expect(hasPermission(rootKey.permissions, PERM.CREATE_OPERATOR_KEY)).toBe(true);

    // Operator can create agents but not operators
    expect(hasPermission(operatorKey.permissions, PERM.CREATE_AGENT_KEY)).toBe(true);
    expect(hasPermission(operatorKey.permissions, PERM.CREATE_OPERATOR_KEY)).toBe(false);

    // Agent can create sessions
    expect(hasPermission(agentKey.permissions, PERM.CREATE_SESSION_KEY)).toBe(true);
    expect(hasPermission(agentKey.permissions, PERM.CREATE_OPERATOR_KEY)).toBe(false);

    // Session can only sign
    expect(hasPermission(sessionKey.permissions, PERM.SIGN_TRANSACTION)).toBe(true);
    expect(hasPermission(sessionKey.permissions, PERM.CREATE_SESSION_KEY)).toBe(false);

    // 7. Verify all addresses are different
    const addresses = new Set([
      rootKey.address,
      operatorKey.address,
      agentKey.address,
      sessionKey.address,
    ]);
    expect(addresses.size).toBe(4);
  });

  it("should enforce permission narrowing through the hierarchy", () => {
    const masterSeed = deriveMasterSeed(TEST_ENTROPY);

    // Create operator with limited permissions
    const { key: operatorKey } = createOperatorKey({
      vaultId: "vault-001",
      name: "Limited Operator",
      parentKeyId: "root",
      masterSeed,
      index: 0,
      permissions: createPermissions(
        PERM.CREATE_AGENT_KEY,
        PERM.CREATE_SESSION_KEY,
        PERM.SIGN_TRANSACTION,
        // Notably missing: VIEW_BALANCES, MANAGE_POLICY
      ),
    });

    // Create agent from this limited operator
    const { key: agentKey } = createAgentKey({
      vaultId: "vault-001",
      name: "Agent",
      parentKeyId: operatorKey.id,
      parentTier: "operator",
      parentPermissions: operatorKey.permissions,
      masterSeed,
      index: 0,
    });

    // Agent should not have VIEW_BALANCES since operator didn't have it
    expect(hasPermission(agentKey.permissions, PERM.VIEW_BALANCES)).toBe(false);
    // Agent should have SIGN_TRANSACTION (requested by default, parent has it)
    expect(hasPermission(agentKey.permissions, PERM.SIGN_TRANSACTION)).toBe(true);
  });
});

// ===========================================================================
// SIGNING WITH DERIVED KEYS
// ===========================================================================

describe("Signing with Derived Keys", () => {
  it("should sign and verify with operator key", () => {
    const { privateKey, publicKey } = deriveOperatorKey(TEST_MASTER_SEED, 0);
    const message = new Uint8Array(32);
    message.fill(0xab);

    const sig = secp256k1.sign(message, privateKey);
    const isValid = secp256k1.verify(sig, message, publicKey);
    expect(isValid).toBe(true);
  });

  it("should sign and verify with agent key", () => {
    const { privateKey, publicKey } = deriveAgentKey(TEST_MASTER_SEED, 0);
    const message = new Uint8Array(32);
    message.fill(0xcd);

    const sig = secp256k1.sign(message, privateKey);
    const isValid = secp256k1.verify(sig, message, publicKey);
    expect(isValid).toBe(true);
  });

  it("should sign and verify with session key", () => {
    const { privateKey, publicKey } = generateSessionKey();
    const message = new Uint8Array(32);
    message.fill(0xef);

    const sig = secp256k1.sign(message, privateKey);
    const isValid = secp256k1.verify(sig, message, publicKey);
    expect(isValid).toBe(true);
  });

  it("should not verify with wrong key", () => {
    const operator = deriveOperatorKey(TEST_MASTER_SEED, 0);
    const agent = deriveAgentKey(TEST_MASTER_SEED, 0);
    const message = new Uint8Array(32);
    message.fill(0xab);

    const sig = secp256k1.sign(message, operator.privateKey);
    const isValid = secp256k1.verify(sig, message, agent.publicKey);
    expect(isValid).toBe(false);
  });

  it("should recover correct address from operator signature", () => {
    const { privateKey, publicKey, address } = deriveOperatorKey(TEST_MASTER_SEED, 0);
    const message = new Uint8Array(32);
    message.fill(0x42);

    const sig = secp256k1.sign(message, privateKey);
    const recovered = sig.recoverPublicKey(message);
    const recoveredAddress = publicKeyToEvmAddress(
      recovered.toRawBytes(true),
    );

    expect(recoveredAddress).toBe(address);
  });
});
