/**
 * MACHINA Vault — Policy Engine & DeFi Scope Enforcement Tests
 *
 * These tests verify the critical security invariant: agents can execute
 * allowed DeFi operations but CANNOT steal funds. The policy engine is
 * the last line of defense before signing.
 */

import { describe, it, expect, beforeEach } from "vitest";

import { PolicyEngine } from "../src/policy/engine.js";
import { evaluateCondition } from "../src/policy/conditions.js";
import type {
  PolicyRule,
  PolicyCondition,
  PolicyEvalRequest,
  PolicyContext,
  PolicyAction,
} from "../src/policy/types.js";
import {
  checkSpendingLimit,
  recordSpend,
  resetDailySpend,
  resetMonthlySpend,
} from "../src/keys/spending.js";
import type { VaultKey, SpendingLimit } from "../src/keys/types.js";
import {
  CONSERVATIVE_PRESET,
  STANDARD_PRESET,
  AGGRESSIVE_PRESET,
  LOCKDOWN_PRESET,
} from "../src/policy/presets.js";

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

const AAVE_POOL = "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2";
const UNISWAP_ROUTER = "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45";
const COMPOUND_COMET = "0xc3d688b66703497daa19211eedff47f25384cdc3";
const LIDO_STETH = "0xae7ab96520de3a18e5e111b5eaab095312d7fe84";
const USDC_ADDRESS = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const RANDOM_EOA = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/** Known DeFi function selectors */
const SELECTORS = {
  ERC20_TRANSFER: "0xa9059cbb",
  ERC20_TRANSFER_FROM: "0x23b872dd",
  ERC20_APPROVE: "0x095ea7b3",
  AAVE_SUPPLY: "0x617ba037",
  AAVE_WITHDRAW: "0x69328dec",
  COMPOUND_SUPPLY: "0xf2b9fdb8",
  LIDO_SUBMIT: "0xa1903eab",
  UNISWAP_EXACT_INPUT_SINGLE: "0x414bf389",
  UNISWAP_MULTICALL: "0x5ae401dc",
  SELF_DESTRUCT: "0xff",
} as const;

function makeRequest(overrides: Partial<PolicyEvalRequest> = {}): PolicyEvalRequest {
  return {
    keyId: "agent-key-0",
    keyTier: "agent",
    vaultId: "vault-001",
    chain: "1",
    to: AAVE_POOL,
    value: 0n,
    valueUsd: 100,
    timestamp: Date.now(),
    ...overrides,
  };
}

function makeContext(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    recentTxCount: 0,
    lastTxTimestamp: null,
    dailySpendUsd: 0,
    monthlySpendUsd: 0,
    ...overrides,
  };
}

function makeDenyRule(
  id: string,
  conditions: PolicyCondition[],
  overrides: Partial<PolicyRule> = {},
): PolicyRule {
  return {
    id,
    name: `Deny: ${id}`,
    description: "Test deny rule",
    scope: "vault",
    conditions,
    action: "deny",
    priority: 10,
    enabled: true,
    createdBy: "root-key-0",
    createdAt: new Date().toISOString(),
    expiresAt: null,
    ...overrides,
  };
}

function makeApprovalRule(
  id: string,
  conditions: PolicyCondition[],
  overrides: Partial<PolicyRule> = {},
): PolicyRule {
  return {
    id,
    name: `Approval: ${id}`,
    description: "Test approval rule",
    scope: "vault",
    conditions,
    action: "require_approval",
    priority: 20,
    enabled: true,
    createdBy: "root-key-0",
    createdAt: new Date().toISOString(),
    expiresAt: null,
    ...overrides,
  };
}

function makeVaultKey(overrides: Partial<VaultKey> = {}): VaultKey {
  const today = new Date().toISOString().slice(0, 10);
  const month = new Date().toISOString().slice(0, 7);
  return {
    id: "agent-key-0",
    vaultId: "vault-001",
    tier: "agent",
    name: "Test Agent Key",
    publicKey: new Uint8Array(33),
    address: "0x0000000000000000000000000000000000000001",
    parentKeyId: "operator-key-0",
    permissions: { mask: 0n },
    scope: {
      allowedChains: ["1"],
      allowedContracts: [AAVE_POOL, UNISWAP_ROUTER],
      allowedFunctions: [SELECTORS.ERC20_APPROVE, SELECTORS.UNISWAP_MULTICALL],
      spendingLimits: [
        {
          tokenAddress: "native",
          perTx: 1_000_000_000_000_000_000n, // 1 ETH
          daily: 5_000_000_000_000_000_000n, // 5 ETH
          monthly: 50_000_000_000_000_000_000n, // 50 ETH
        },
      ],
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
// DEFI SCOPE ENFORCER — ALLOWED OPERATIONS
// ===========================================================================

describe("DeFi Scope Enforcer — Allowed Operations", () => {
  // Security: These tests verify that LEGITIMATE DeFi operations are NOT blocked.
  // False positives (blocking valid operations) erode trust and cause fund lockups.

  let engine: PolicyEngine;

  beforeEach(() => {
    engine = new PolicyEngine([
      makeDenyRule("block-unknown-contracts", [
        { type: "allowed_contracts", addresses: [AAVE_POOL, UNISWAP_ROUTER, COMPOUND_COMET, LIDO_STETH, USDC_ADDRESS] },
      ]),
    ]);
  });

  it("should ALLOW calls to Aave V3 pool (known contract)", () => {
    const result = engine.evaluate(makeRequest({ to: AAVE_POOL }), makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should ALLOW calls to Uniswap router (known contract)", () => {
    const result = engine.evaluate(makeRequest({ to: UNISWAP_ROUTER }), makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should ALLOW calls to Compound comet (known contract)", () => {
    const result = engine.evaluate(makeRequest({ to: COMPOUND_COMET }), makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should ALLOW calls to Lido stETH (known contract)", () => {
    const result = engine.evaluate(makeRequest({ to: LIDO_STETH }), makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should ALLOW ERC20 approve to known protocol spender", () => {
    const result = engine.evaluate(
      makeRequest({ to: USDC_ADDRESS, functionSelector: SELECTORS.ERC20_APPROVE }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });

  it("should ALLOW with case-insensitive address matching", () => {
    const result = engine.evaluate(
      makeRequest({ to: AAVE_POOL.toUpperCase().replace("0X", "0x") }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });

  it("should ALLOW root key to bypass ALL policies", () => {
    const denyAll = new PolicyEngine([
      makeDenyRule("deny-everything", [
        { type: "allowed_contracts", addresses: [] },
      ]),
    ]);
    const result = denyAll.evaluate(
      makeRequest({ keyTier: "root", to: RANDOM_EOA }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });
});

// ===========================================================================
// DEFI SCOPE ENFORCER — BLOCKED OPERATIONS (THE SECURITY BOUNDARY)
// ===========================================================================

describe("DeFi Scope Enforcer — Blocked Operations (Security Boundary)", () => {
  // Security: These tests verify agents CANNOT steal funds. This is the most
  // critical test section in the entire vault.

  let engine: PolicyEngine;

  beforeEach(() => {
    engine = new PolicyEngine([
      makeDenyRule("block-unknown-contracts", [
        { type: "allowed_contracts", addresses: [AAVE_POOL, UNISWAP_ROUTER, USDC_ADDRESS] },
      ]),
      makeDenyRule("block-transfers", [
        { type: "blocked_functions", selectors: [SELECTORS.ERC20_TRANSFER, SELECTORS.ERC20_TRANSFER_FROM] },
      ]),
      makeDenyRule("block-unknown-recipients", [
        { type: "recipient_blocklist", addresses: [RANDOM_EOA] },
      ]),
    ]);
  });

  it("should DENY call to unregistered contract", () => {
    const result = engine.evaluate(
      makeRequest({ to: RANDOM_EOA }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
    expect(result.action).toBe("deny");
  });

  it("should DENY ERC20 transfer to unknown address", () => {
    const result = engine.evaluate(
      makeRequest({
        to: USDC_ADDRESS,
        functionSelector: SELECTORS.ERC20_TRANSFER,
      }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("should DENY ERC20 transferFrom to unknown address", () => {
    const result = engine.evaluate(
      makeRequest({
        to: USDC_ADDRESS,
        functionSelector: SELECTORS.ERC20_TRANSFER_FROM,
      }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("should DENY native ETH transfer to blocked recipient", () => {
    const result = engine.evaluate(
      makeRequest({ to: RANDOM_EOA, value: 1_000_000_000_000_000_000n }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("should DENY calls to fake pool with same selector as Aave", () => {
    const fakePool = "0x1111111111111111111111111111111111111111";
    const result = engine.evaluate(
      makeRequest({
        to: fakePool,
        functionSelector: SELECTORS.AAVE_SUPPLY,
      }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });
});

// ===========================================================================
// FUNCTION SELECTOR ENFORCEMENT
// ===========================================================================

describe("Function Selector Enforcement", () => {
  it("should DENY blocked function selectors", () => {
    const engine = new PolicyEngine([
      makeDenyRule("block-selfdestruct", [
        { type: "blocked_functions", selectors: ["0xff"] },
      ]),
    ]);
    const result = engine.evaluate(
      makeRequest({ functionSelector: "0xff" }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("should ALLOW when function selector not blocked", () => {
    const engine = new PolicyEngine([
      makeDenyRule("block-transfer", [
        { type: "blocked_functions", selectors: [SELECTORS.ERC20_TRANSFER] },
      ]),
    ]);
    // approve is not blocked
    const result = engine.evaluate(
      makeRequest({ functionSelector: SELECTORS.ERC20_APPROVE }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });

  it("should handle missing function selector (plain transfer)", () => {
    const engine = new PolicyEngine([
      makeDenyRule("block-transfer", [
        { type: "blocked_functions", selectors: [SELECTORS.ERC20_TRANSFER] },
      ]),
    ]);
    // No function selector = plain ETH transfer, should not match blocked_functions
    const result = engine.evaluate(
      makeRequest({ functionSelector: undefined }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });
});

// ===========================================================================
// CHAIN RESTRICTIONS
// ===========================================================================

describe("Chain Restrictions", () => {
  it("should DENY transactions on blocked chains", () => {
    const engine = new PolicyEngine([
      makeDenyRule("block-bsc", [
        { type: "blocked_chains", chainIds: ["56"] },
      ]),
    ]);
    const result = engine.evaluate(
      makeRequest({ chain: "56" }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("should ALLOW transactions on non-blocked chains", () => {
    const engine = new PolicyEngine([
      makeDenyRule("block-bsc", [
        { type: "blocked_chains", chainIds: ["56"] },
      ]),
    ]);
    const result = engine.evaluate(
      makeRequest({ chain: "1" }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });

  it("should DENY transactions on chains not in allowlist", () => {
    const engine = new PolicyEngine([
      makeDenyRule("only-eth-base", [
        { type: "allowed_chains", chainIds: ["1", "8453"] },
      ]),
    ]);
    const result = engine.evaluate(
      makeRequest({ chain: "42161" }), // Arbitrum not in allowlist
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });
});

// ===========================================================================
// SPENDING LIMITS
// ===========================================================================

describe("Spending Limits", () => {
  // Security: Spending limits prevent catastrophic fund loss even if
  // policy rules have a gap. They are the quantitative safety net.

  it("should enforce per-transaction limit", () => {
    const key = makeVaultKey();
    const result = checkSpendingLimit(key, "native", 2_000_000_000_000_000_000n); // 2 ETH > 1 ETH limit
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("per-transaction");
  });

  it("should allow within per-transaction limit", () => {
    const key = makeVaultKey();
    const result = checkSpendingLimit(key, "native", 500_000_000_000_000_000n); // 0.5 ETH
    expect(result.allowed).toBe(true);
  });

  it("should enforce daily aggregate limit", () => {
    let key = makeVaultKey();
    // Spend 4 ETH today
    key = recordSpend(key, "native", 4_000_000_000_000_000_000n);

    // Try to spend 0.5 more (within per-tx limit but would push daily to 4.5 ETH)
    // First, make the daily limit tight: set daily = 4 ETH so 4 + 0.5 > 4
    key = {
      ...key,
      scope: {
        ...key.scope,
        spendingLimits: [
          {
            tokenAddress: "native",
            perTx: 1_000_000_000_000_000_000n, // 1 ETH per tx
            daily: 4_000_000_000_000_000_000n,  // 4 ETH daily
            monthly: 50_000_000_000_000_000_000n,
          },
        ],
      },
    };

    const result = checkSpendingLimit(key, "native", 500_000_000_000_000_000n); // 0.5 ETH
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Daily");
  });

  it("should enforce monthly aggregate limit", () => {
    let key = makeVaultKey({
      scope: {
        ...makeVaultKey().scope,
        spendingLimits: [
          {
            tokenAddress: "native",
            perTx: 10_000_000_000_000_000_000n,
            daily: 100_000_000_000_000_000_000n,
            monthly: 20_000_000_000_000_000_000n, // 20 ETH monthly
          },
        ],
      },
    });

    // Spend 19 ETH this month
    key = recordSpend(key, "native", 19_000_000_000_000_000_000n);

    // Try to spend 2 more (would total 21 ETH, exceeding 20 ETH monthly limit)
    const result = checkSpendingLimit(key, "native", 2_000_000_000_000_000_000n);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Monthly");
  });

  it("should allow spending when no limit defined for token", () => {
    const key = makeVaultKey();
    // No spending limit for USDC, so it should be allowed
    const result = checkSpendingLimit(key, USDC_ADDRESS, 999_999_999n);
    expect(result.allowed).toBe(true);
  });

  it("should reject spending when key is revoked", () => {
    const key = makeVaultKey({ status: "revoked" });
    const result = checkSpendingLimit(key, "native", 1n);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("revoked");
  });

  it("should reject spending when key is expired", () => {
    const key = makeVaultKey({
      status: "active",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    const result = checkSpendingLimit(key, "native", 1n);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("expired");
  });

  it("should record spend and increment sign count", () => {
    const key = makeVaultKey();
    const updated = recordSpend(key, "native", 100_000_000_000_000_000n);
    expect(updated.signCount).toBe(1);
    expect(updated.spentToday["native"]).toBe(100_000_000_000_000_000n);
    expect(updated.spentThisMonth["native"]).toBe(100_000_000_000_000_000n);
    expect(updated.lastUsedAt).toBeDefined();
  });

  it("should accumulate multiple spends correctly", () => {
    let key = makeVaultKey();
    key = recordSpend(key, "native", 100_000_000_000_000_000n);
    key = recordSpend(key, "native", 200_000_000_000_000_000n);
    key = recordSpend(key, "native", 300_000_000_000_000_000n);

    expect(key.signCount).toBe(3);
    expect(key.spentToday["native"]).toBe(600_000_000_000_000_000n);
    expect(key.spentThisMonth["native"]).toBe(600_000_000_000_000_000n);
  });

  it("should auto-reset daily at midnight UTC (different day)", () => {
    const key = makeVaultKey({
      lastResetDay: "2025-01-01",
      spentToday: { native: 999_000_000_000_000_000_000n },
    });
    const reset = resetDailySpend(key);
    // Today is different from 2025-01-01, so spend should reset
    expect(reset.spentToday).toEqual({});
  });

  it("should auto-reset monthly at month boundary", () => {
    const key = makeVaultKey({
      lastResetMonth: "2024-12",
      spentThisMonth: { native: 999_000_000_000_000_000_000n },
    });
    const reset = resetMonthlySpend(key);
    expect(reset.spentThisMonth).toEqual({});
  });

  it("should NOT reset daily spend if same day", () => {
    const today = new Date().toISOString().slice(0, 10);
    const key = makeVaultKey({
      lastResetDay: today,
      spentToday: { native: 1_000_000_000_000_000_000n },
    });
    const reset = resetDailySpend(key);
    expect(reset.spentToday["native"]).toBe(1_000_000_000_000_000_000n);
  });
});

// ===========================================================================
// VALUE-BASED LIMITS (USD)
// ===========================================================================

describe("Value-Based Limits (USD)", () => {
  it("should DENY transaction exceeding max USD value", () => {
    const engine = new PolicyEngine([
      makeDenyRule("max-500", [{ type: "max_value_usd", threshold: 500 }]),
    ]);
    const result = engine.evaluate(
      makeRequest({ valueUsd: 600 }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("should ALLOW transaction within max USD value", () => {
    const engine = new PolicyEngine([
      makeDenyRule("max-500", [{ type: "max_value_usd", threshold: 500 }]),
    ]);
    const result = engine.evaluate(
      makeRequest({ valueUsd: 400 }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });

  it("should DENY when daily USD spend would exceed limit", () => {
    const engine = new PolicyEngine([
      makeDenyRule("daily-10k", [{ type: "daily_limit_usd", threshold: 10000 }]),
    ]);
    const result = engine.evaluate(
      makeRequest({ valueUsd: 5000 }),
      makeContext({ dailySpendUsd: 8000 }), // 8000 + 5000 = 13000 > 10000
    );
    expect(result.allowed).toBe(false);
  });

  it("should DENY when monthly USD spend would exceed limit", () => {
    const engine = new PolicyEngine([
      makeDenyRule("monthly-100k", [{ type: "monthly_limit_usd", threshold: 100000 }]),
    ]);
    const result = engine.evaluate(
      makeRequest({ valueUsd: 10000 }),
      makeContext({ monthlySpendUsd: 95000 }),
    );
    expect(result.allowed).toBe(false);
  });
});

// ===========================================================================
// VELOCITY AND COOLDOWN
// ===========================================================================

describe("Velocity and Cooldown Limits", () => {
  it("should trigger rate limit when velocity exceeded", () => {
    const engine = new PolicyEngine([
      makeDenyRule("velocity-50", [
        { type: "velocity_limit", maxTxCount: 50, windowSeconds: 3600 },
      ], { action: "rate_limit" }),
    ]);
    const result = engine.evaluate(
      makeRequest(),
      makeContext({ recentTxCount: 51 }),
    );
    expect(result.allowed).toBe(false);
    expect(result.action).toBe("rate_limit");
  });

  it("should ALLOW when velocity within limit", () => {
    const engine = new PolicyEngine([
      makeDenyRule("velocity-50", [
        { type: "velocity_limit", maxTxCount: 50, windowSeconds: 3600 },
      ], { action: "rate_limit" }),
    ]);
    const result = engine.evaluate(
      makeRequest(),
      makeContext({ recentTxCount: 10 }),
    );
    expect(result.allowed).toBe(true);
  });

  it("should trigger cooldown when transactions too close together", () => {
    const engine = new PolicyEngine([
      makeDenyRule("cooldown-60s", [
        { type: "cooldown_seconds", seconds: 60 },
      ]),
    ]);
    const result = engine.evaluate(
      makeRequest(),
      makeContext({ lastTxTimestamp: Date.now() - 10_000 }), // 10 seconds ago
    );
    expect(result.allowed).toBe(false);
  });

  it("should ALLOW after cooldown period has elapsed", () => {
    const engine = new PolicyEngine([
      makeDenyRule("cooldown-60s", [
        { type: "cooldown_seconds", seconds: 60 },
      ]),
    ]);
    const result = engine.evaluate(
      makeRequest(),
      makeContext({ lastTxTimestamp: Date.now() - 120_000 }), // 2 minutes ago
    );
    expect(result.allowed).toBe(true);
  });
});

// ===========================================================================
// KEY TIER ENFORCEMENT
// ===========================================================================

describe("Key Tier Enforcement", () => {
  it("should DENY session key when operator tier required", () => {
    const engine = new PolicyEngine([
      makeDenyRule("require-operator", [
        { type: "require_key_tier", minTier: "operator" },
      ]),
    ]);
    const result = engine.evaluate(
      makeRequest({ keyTier: "session" }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("should DENY agent key when operator tier required", () => {
    const engine = new PolicyEngine([
      makeDenyRule("require-operator", [
        { type: "require_key_tier", minTier: "operator" },
      ]),
    ]);
    const result = engine.evaluate(
      makeRequest({ keyTier: "agent" }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("should ALLOW operator key when operator tier required", () => {
    const engine = new PolicyEngine([
      makeDenyRule("require-operator", [
        { type: "require_key_tier", minTier: "operator" },
      ]),
    ]);
    const result = engine.evaluate(
      makeRequest({ keyTier: "operator" }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });

  it("should ALWAYS bypass policies for root key tier", () => {
    const engine = new PolicyEngine([
      makeDenyRule("deny-all-agents", [
        { type: "require_key_tier", minTier: "root" },
      ]),
      makeDenyRule("deny-all-contracts", [
        { type: "allowed_contracts", addresses: [] },
      ]),
    ]);
    const result = engine.evaluate(
      makeRequest({ keyTier: "root" }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });
});

// ===========================================================================
// POLICY RULE MANAGEMENT
// ===========================================================================

describe("Policy Rule Management", () => {
  it("should add rules dynamically", () => {
    const engine = new PolicyEngine();
    expect(engine.getRules().length).toBe(0);

    engine.addRule(makeDenyRule("new-rule", [{ type: "max_value_usd", threshold: 100 }]));
    expect(engine.getRules().length).toBe(1);
  });

  it("should remove rules", () => {
    const engine = new PolicyEngine([
      makeDenyRule("rule-1", [{ type: "max_value_usd", threshold: 100 }]),
    ]);
    engine.removeRule("rule-1");
    expect(engine.getRules().length).toBe(0);
  });

  it("should update rules", () => {
    const engine = new PolicyEngine([
      makeDenyRule("rule-1", [{ type: "max_value_usd", threshold: 100 }]),
    ]);
    engine.updateRule("rule-1", { enabled: false });
    const rules = engine.getRules();
    expect(rules[0].enabled).toBe(false);
  });

  it("should throw when updating non-existent rule", () => {
    const engine = new PolicyEngine();
    expect(() => engine.updateRule("nonexistent", { enabled: false })).toThrow();
  });

  it("should skip disabled rules during evaluation", () => {
    const engine = new PolicyEngine([
      makeDenyRule("disabled-deny", [{ type: "max_value_usd", threshold: 0 }], { enabled: false }),
    ]);
    const result = engine.evaluate(makeRequest({ valueUsd: 1000 }), makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should skip expired rules during evaluation", () => {
    const engine = new PolicyEngine([
      makeDenyRule("expired-deny", [{ type: "max_value_usd", threshold: 0 }], {
        expiresAt: new Date(Date.now() - 60000).toISOString(),
      }),
    ]);
    const result = engine.evaluate(makeRequest({ valueUsd: 1000 }), makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should evaluate rules in priority order (lower number first)", () => {
    const engine = new PolicyEngine([
      makeDenyRule("low-priority-deny", [{ type: "max_value_usd", threshold: 50 }], { priority: 100 }),
      makeApprovalRule("high-priority-approve", [{ type: "max_value_usd", threshold: 50 }], { priority: 1 }),
    ]);
    // The deny rule at priority 100 should still trigger (deny short-circuits)
    // but the approval rule at priority 1 is evaluated first
    // Since approval does not short-circuit, deny at priority 100 will execute
    const result = engine.evaluate(makeRequest({ valueUsd: 100 }), makeContext());
    expect(result.allowed).toBe(false);
  });

  it("should accumulate require_approval without short-circuiting", () => {
    const engine = new PolicyEngine([
      makeApprovalRule("approve-1", [{ type: "max_value_usd", threshold: 50 }]),
    ]);
    const result = engine.evaluate(makeRequest({ valueUsd: 100 }), makeContext());
    expect(result.allowed).toBe(false);
    expect(result.requiresApproval).toBe(true);
  });
});

// ===========================================================================
// TIME WINDOW ENFORCEMENT
// ===========================================================================

describe("Time Window Enforcement", () => {
  it("should DENY outside allowed hours (simple range 9-17)", () => {
    const engine = new PolicyEngine([
      makeDenyRule("business-hours", [
        { type: "time_window", startHourUtc: 9, endHourUtc: 17 },
      ]),
    ]);
    // Set timestamp to 3 AM UTC
    const timestamp = new Date("2026-03-27T03:00:00Z").getTime();
    const result = engine.evaluate(
      makeRequest({ timestamp }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("should ALLOW within allowed hours", () => {
    const engine = new PolicyEngine([
      makeDenyRule("business-hours", [
        { type: "time_window", startHourUtc: 9, endHourUtc: 17 },
      ]),
    ]);
    const timestamp = new Date("2026-03-27T12:00:00Z").getTime();
    const result = engine.evaluate(
      makeRequest({ timestamp }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });

  it("should handle wrapping time range (e.g. 22-06)", () => {
    const engine = new PolicyEngine([
      makeDenyRule("night-window", [
        { type: "time_window", startHourUtc: 22, endHourUtc: 6 },
      ]),
    ]);
    // 23:00 UTC should be within 22-06 window (allowed)
    const timestamp = new Date("2026-03-27T23:00:00Z").getTime();
    const result = engine.evaluate(
      makeRequest({ timestamp }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });

  it("should enforce day-of-week restrictions", () => {
    const engine = new PolicyEngine([
      makeDenyRule("weekdays-only", [
        { type: "time_window", startHourUtc: 0, endHourUtc: 24, daysOfWeek: [1, 2, 3, 4, 5] },
      ]),
    ]);
    // Saturday = day 6
    const saturday = new Date("2026-03-28T12:00:00Z").getTime(); // March 28, 2026 is Saturday
    const result = engine.evaluate(
      makeRequest({ timestamp: saturday }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });
});

// ===========================================================================
// GAS CAP ENFORCEMENT
// ===========================================================================

describe("Gas Cap Enforcement", () => {
  it("should DENY when gas estimate exceeds threshold", () => {
    const engine = new PolicyEngine([
      makeDenyRule("gas-cap", [{ type: "max_gas_usd", threshold: 50 }]),
    ]);
    const result = engine.evaluate(
      makeRequest({ gasEstimateUsd: 75 }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("should ALLOW when no gas estimate provided", () => {
    const engine = new PolicyEngine([
      makeDenyRule("gas-cap", [{ type: "max_gas_usd", threshold: 50 }]),
    ]);
    const result = engine.evaluate(
      makeRequest({ gasEstimateUsd: undefined }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);
  });
});

// ===========================================================================
// POLICY PRESETS
// ===========================================================================

describe("Policy Presets", () => {
  it("LOCKDOWN preset should deny all non-root transactions", () => {
    const rules = LOCKDOWN_PRESET();
    const engine = new PolicyEngine(rules);

    // Agent key should be denied
    const agentResult = engine.evaluate(makeRequest({ keyTier: "agent" }), makeContext());
    expect(agentResult.allowed).toBe(false);

    // Operator key should be denied
    const opResult = engine.evaluate(makeRequest({ keyTier: "operator" }), makeContext());
    expect(opResult.allowed).toBe(false);

    // Root key should be allowed (bypasses all)
    const rootResult = engine.evaluate(makeRequest({ keyTier: "root" }), makeContext());
    expect(rootResult.allowed).toBe(true);
  });

  it("STANDARD preset should have daily and monthly limits", () => {
    const rules = STANDARD_PRESET();
    const engine = new PolicyEngine(rules);

    // $15,000 with $8,000 already spent today = $23,000 > $10,000 daily limit
    const result = engine.evaluate(
      makeRequest({ valueUsd: 15000 }),
      makeContext({ dailySpendUsd: 8000 }),
    );
    expect(result.allowed).toBe(false);
  });

  it("CONSERVATIVE preset should require operator tier", () => {
    const rules = CONSERVATIVE_PRESET();
    const engine = new PolicyEngine(rules);

    const result = engine.evaluate(
      makeRequest({ keyTier: "agent", valueUsd: 10 }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });

  it("AGGRESSIVE preset should allow higher daily limits than standard", () => {
    const rules = AGGRESSIVE_PRESET();
    const engine = new PolicyEngine(rules);

    // $5k with $0 spent should be fine under $100k daily limit and under $10k approval threshold
    const result = engine.evaluate(
      makeRequest({ keyTier: "operator", valueUsd: 5000 }),
      makeContext(),
    );
    expect(result.allowed).toBe(true);

    // But $50k triggers require_approval (threshold $10k)
    const bigResult = engine.evaluate(
      makeRequest({ keyTier: "operator", valueUsd: 50000 }),
      makeContext(),
    );
    expect(bigResult.allowed).toBe(false);
    expect(bigResult.requiresApproval).toBe(true);
  });
});

// ===========================================================================
// MULTI-CONDITION RULES
// ===========================================================================

describe("Multi-Condition Rules", () => {
  // Security: Rules with multiple conditions must ALL match to trigger.
  // A bug here could make rules too strict or too permissive.

  it("should require ALL conditions to match for a rule to trigger", () => {
    const engine = new PolicyEngine([
      makeDenyRule("compound-rule", [
        { type: "max_value_usd", threshold: 500 },
        { type: "allowed_chains", chainIds: ["1"] },
      ]),
    ]);

    // Only one condition matches (value > 500 but chain IS allowed)
    // max_value_usd triggers at 600, but allowed_chains does NOT trigger for chain "1"
    const result = engine.evaluate(
      makeRequest({ valueUsd: 600, chain: "1" }),
      makeContext(),
    );
    // Chain "1" IS in allowlist so that condition does NOT match (not triggered)
    // Therefore the rule does NOT fire as a whole
    expect(result.allowed).toBe(true);
  });

  it("should trigger when ALL conditions match", () => {
    const engine = new PolicyEngine([
      makeDenyRule("compound-rule", [
        { type: "max_value_usd", threshold: 500 },
        { type: "blocked_chains", chainIds: ["56"] }, // BSC
      ]),
    ]);

    const result = engine.evaluate(
      makeRequest({ valueUsd: 600, chain: "56" }),
      makeContext(),
    );
    expect(result.allowed).toBe(false);
  });
});
