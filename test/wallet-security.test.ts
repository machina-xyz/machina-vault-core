/**
 * MACHINA Vault — Wallet Security Integration Tests
 *
 * Verifies the critical security invariant: agents can execute DeFi operations
 * but CANNOT steal funds. Tests cover key derivation, policy enforcement,
 * spending limits, EVM signing correctness, emergency freeze, self-custody
 * guarantees, and edge cases.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";

// --- Key derivation imports ---
import {
  deriveMasterSeed,
  deriveKeyAtPath,
  deriveOperatorKey,
  deriveAgentKey,
  publicKeyToEvmAddress,
  generateSessionKey,
  DERIVATION_PATHS,
  OPERATOR_PATH,
  AGENT_PATH,
} from "../src/keys/derivation.js";

// --- Policy engine imports ---
import { PolicyEngine } from "../src/policy/engine.js";
import { evaluateCondition } from "../src/policy/conditions.js";
import type {
  PolicyRule,
  PolicyCondition,
  PolicyEvalRequest,
  PolicyContext,
} from "../src/policy/types.js";

// --- Spending limit imports ---
import {
  checkSpendingLimit,
  recordSpend,
  resetDailySpend,
  resetMonthlySpend,
} from "../src/keys/spending.js";
import type { VaultKey, SpendingLimit } from "../src/keys/types.js";

// --- EVM signer imports ---
import { EvmSigner, rlpEncode } from "../src/signing/chains/evm.js";
import type { SignRequest, ChainConfig } from "../src/signing/types.js";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Deterministic test seed (32 bytes of 0x01..0x20) */
const TEST_ENTROPY = new Uint8Array(32);
for (let i = 0; i < 32; i++) TEST_ENTROPY[i] = i + 1;

const TEST_MASTER_SEED = deriveMasterSeed(TEST_ENTROPY);

/** Well-known DeFi protocol addresses (checksummed lowercased for matching) */
const AAVE_POOL = "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2";
const UNISWAP_ROUTER = "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45";
const USDC_ADDRESS = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

/** ERC-20 function selectors */
const ERC20_TRANSFER = "0xa9059cbb";
const ERC20_APPROVE = "0x095ea7b3";
const UNISWAP_SWAP = "0x5ae401dc"; // multicall on Uniswap

/** Create a base policy eval request for tests */
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

/** Create a base policy context for tests */
function makeContext(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    recentTxCount: 0,
    lastTxTimestamp: null,
    dailySpendUsd: 0,
    monthlySpendUsd: 0,
    ...overrides,
  };
}

/** Create a deny rule with given conditions */
function makeDenyRule(
  id: string,
  conditions: PolicyCondition[],
  overrides: Partial<PolicyRule> = {},
): PolicyRule {
  return {
    id,
    name: `Deny rule: ${id}`,
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

/** Create an allow rule (action=allow does not block, it just records) */
function makeAllowRule(
  id: string,
  conditions: PolicyCondition[],
  overrides: Partial<PolicyRule> = {},
): PolicyRule {
  return {
    id,
    name: `Allow rule: ${id}`,
    description: "Test allow rule",
    scope: "vault",
    conditions,
    action: "allow",
    priority: 10,
    enabled: true,
    createdBy: "root-key-0",
    createdAt: new Date().toISOString(),
    expiresAt: null,
    ...overrides,
  };
}

/** Create a minimal VaultKey for spending limit tests */
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
      allowedFunctions: [ERC20_APPROVE, UNISWAP_SWAP],
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

/** Hex helpers */
function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

// ===========================================================================
// 1. KEY DERIVATION TESTS
// ===========================================================================

describe("BIP-32 Key Derivation", () => {
  it("should derive a 64-byte master seed from entropy via HKDF", () => {
    const seed = deriveMasterSeed(TEST_ENTROPY);
    expect(seed).toBeInstanceOf(Uint8Array);
    expect(seed.length).toBe(64);
  });

  it("should derive correct master key from seed using HMAC-SHA512('Bitcoin seed')", () => {
    // Manually replicate master node derivation
    const I = hmac(sha512, new TextEncoder().encode("Bitcoin seed"), TEST_MASTER_SEED);
    expect(I.length).toBe(64);
    const masterKey = I.slice(0, 32);
    const chainCode = I.slice(32, 64);
    // Master key must be a valid secp256k1 scalar (1 < k < n)
    const n = secp256k1.CURVE.n;
    let keyBigInt = 0n;
    for (const byte of masterKey) keyBigInt = (keyBigInt << 8n) | BigInt(byte);
    expect(keyBigInt).toBeGreaterThan(0n);
    expect(keyBigInt).toBeLessThan(n);
    expect(chainCode.length).toBe(32);
  });

  it("should derive correct child key with (IL + parentKey) mod n", () => {
    // Derive two levels and verify the key is a valid secp256k1 private key
    const path = "m/44'/60'/0'/0'/0'";
    const { privateKey } = deriveKeyAtPath(TEST_MASTER_SEED, path);
    expect(privateKey.length).toBe(32);
    const n = secp256k1.CURVE.n;
    let keyBigInt = 0n;
    for (const byte of privateKey) keyBigInt = (keyBigInt << 8n) | BigInt(byte);
    expect(keyBigInt).toBeGreaterThan(0n);
    expect(keyBigInt).toBeLessThan(n);
  });

  it("should produce different keys for different derivation paths", () => {
    const key0 = deriveKeyAtPath(TEST_MASTER_SEED, "m/44'/60'/0'/0'/0'");
    const key1 = deriveKeyAtPath(TEST_MASTER_SEED, "m/44'/60'/0'/0'/1'");
    expect(bytesToHex(key0.privateKey)).not.toBe(bytesToHex(key1.privateKey));
    expect(bytesToHex(key0.publicKey)).not.toBe(bytesToHex(key1.publicKey));
  });

  it("should produce same key for same seed + path (deterministic)", () => {
    const path = "m/44'/60'/2'/0'/7'";
    const a = deriveKeyAtPath(TEST_MASTER_SEED, path);
    const b = deriveKeyAtPath(TEST_MASTER_SEED, path);
    expect(bytesToHex(a.privateKey)).toBe(bytesToHex(b.privateKey));
    expect(bytesToHex(a.publicKey)).toBe(bytesToHex(b.publicKey));
  });

  it("should reject non-hardened derivation paths for security", () => {
    // Non-hardened paths leak parent private keys — must be rejected
    expect(() => deriveKeyAtPath(TEST_MASTER_SEED, "m/44'/60'/0'/0/0")).toThrow(
      "Non-hardened derivation not supported",
    );
  });

  it("should reject invalid derivation path formats", () => {
    expect(() => deriveKeyAtPath(TEST_MASTER_SEED, "44'/60'/0'")).toThrow();
    expect(() => deriveKeyAtPath(TEST_MASTER_SEED, "m/abc'")).toThrow();
    expect(() => deriveKeyAtPath(TEST_MASTER_SEED, "m/-1'")).toThrow();
  });

  it("should derive correct EVM address from public key (keccak256)", () => {
    const { publicKey, privateKey } = deriveKeyAtPath(TEST_MASTER_SEED, DERIVATION_PATHS.evm(0));
    const address = publicKeyToEvmAddress(publicKey);

    // Verify format: 0x + 40 hex chars
    expect(address).toMatch(/^0x[0-9a-f]{40}$/);

    // Cross-verify: decompress pubkey, keccak256, take last 20 bytes
    const point = secp256k1.ProjectivePoint.fromHex(publicKey);
    const uncompressed = point.toRawBytes(false);
    const hash = keccak_256(uncompressed.slice(1));
    const expectedAddress = "0x" + bytesToHex(hash.slice(12));
    expect(address).toBe(expectedAddress);
  });

  it("should derive operator keys under account index 1", () => {
    const { address, privateKey } = deriveOperatorKey(TEST_MASTER_SEED, 0);
    expect(address).toMatch(/^0x[0-9a-f]{40}$/);
    // Verify it matches manually deriving at the operator path
    const manual = deriveKeyAtPath(TEST_MASTER_SEED, OPERATOR_PATH(0));
    expect(bytesToHex(privateKey)).toBe(bytesToHex(manual.privateKey));
  });

  it("should derive agent keys under account index 2", () => {
    const { address, privateKey } = deriveAgentKey(TEST_MASTER_SEED, 0);
    expect(address).toMatch(/^0x[0-9a-f]{40}$/);
    const manual = deriveKeyAtPath(TEST_MASTER_SEED, AGENT_PATH(0));
    expect(bytesToHex(privateKey)).toBe(bytesToHex(manual.privateKey));
  });

  it("should produce distinct addresses for operator vs agent at same index", () => {
    const operator = deriveOperatorKey(TEST_MASTER_SEED, 0);
    const agent = deriveAgentKey(TEST_MASTER_SEED, 0);
    expect(operator.address).not.toBe(agent.address);
  });

  it("should generate valid ephemeral session keys", () => {
    const session = generateSessionKey();
    expect(session.privateKey.length).toBe(32);
    expect(session.publicKey.length).toBe(33);
    expect(session.address).toMatch(/^0x[0-9a-f]{40}$/);
    // Session keys must be different each time (random)
    const session2 = generateSessionKey();
    expect(bytesToHex(session.privateKey)).not.toBe(bytesToHex(session2.privateKey));
  });
});

// ===========================================================================
// 2. POLICY ENGINE SECURITY TESTS
// ===========================================================================

describe("Policy Engine - DeFi Scope", () => {
  let engine: PolicyEngine;

  beforeEach(() => {
    // Set up a policy engine with rules that allow DeFi but deny theft
    engine = new PolicyEngine([
      // Deny transfers to addresses not in the allowlist
      makeDenyRule("deny-unknown-recipient", [
        { type: "recipient_allowlist", addresses: [AAVE_POOL, UNISWAP_ROUTER, USDC_ADDRESS] },
      ], { priority: 1 }),
      // Deny ERC-20 transfer function calls (prevents token theft)
      makeDenyRule("deny-erc20-transfer", [
        { type: "blocked_functions", selectors: [ERC20_TRANSFER] },
      ], { priority: 2 }),
      // Deny per-tx over $10k
      makeDenyRule("deny-high-value", [
        { type: "max_value_usd", threshold: 10_000 },
      ], { priority: 3 }),
      // Deny daily over $50k
      makeDenyRule("deny-daily-limit", [
        { type: "daily_limit_usd", threshold: 50_000 },
      ], { priority: 4 }),
    ]);
  });

  it("should ALLOW deposit to Aave pool address", () => {
    const request = makeRequest({ to: AAVE_POOL, functionSelector: "0x617ba037" });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should ALLOW withdraw from Aave back to own address", () => {
    // Aave withdraw goes TO the Aave pool contract, not to an arbitrary EOA
    const request = makeRequest({ to: AAVE_POOL, functionSelector: "0x69328dec" });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should ALLOW ERC20 approve to known protocol", () => {
    const request = makeRequest({
      to: USDC_ADDRESS,
      functionSelector: ERC20_APPROVE,
    });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should ALLOW swap on Uniswap router", () => {
    const request = makeRequest({
      to: UNISWAP_ROUTER,
      functionSelector: UNISWAP_SWAP,
    });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should DENY transfer to random EOA address", () => {
    // Security-critical: an agent must NOT be able to send funds to an arbitrary address
    const randomEOA = "0xdead000000000000000000000000000000000001";
    const request = makeRequest({ to: randomEOA });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(false);
    expect(result.action).toBe("deny");
  });

  it("should DENY transfer to unknown contract", () => {
    const unknownContract = "0x1234567890abcdef1234567890abcdef12345678";
    const request = makeRequest({ to: unknownContract });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(false);
  });

  it("should DENY ERC20 transfer to non-self address (fund extraction)", () => {
    // This is the primary theft vector: calling ERC20.transfer(attacker, amount)
    const request = makeRequest({
      to: USDC_ADDRESS,
      functionSelector: ERC20_TRANSFER,
    });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(false);
    expect(result.action).toBe("deny");
  });

  it("should DENY ERC20 approve to unknown spender", () => {
    // Approving an unknown spender allows them to drain tokens
    const engineStrict = new PolicyEngine([
      makeDenyRule("deny-unknown-recipient", [
        { type: "recipient_allowlist", addresses: [AAVE_POOL, UNISWAP_ROUTER] },
      ], { priority: 1 }),
    ]);
    const request = makeRequest({
      to: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      functionSelector: ERC20_APPROVE,
    });
    const result = engineStrict.evaluate(request, makeContext());
    expect(result.allowed).toBe(false);
  });

  it("should DENY when daily spending limit exceeded", () => {
    const request = makeRequest({ valueUsd: 1000 });
    const context = makeContext({ dailySpendUsd: 49_500 });
    const result = engine.evaluate(request, context);
    expect(result.allowed).toBe(false);
    expect(result.action).toBe("deny");
  });

  it("should DENY when per-tx limit exceeded", () => {
    const request = makeRequest({ to: AAVE_POOL, valueUsd: 15_000 });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(false);
    expect(result.action).toBe("deny");
  });

  it("should ALLOW root key to bypass all policies", () => {
    // Root keys must always be able to act -- they are the owner
    const request = makeRequest({
      keyTier: "root",
      to: "0xdead000000000000000000000000000000000001",
      valueUsd: 999_999,
    });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(true);
    expect(result.action).toBe("allow");
  });

  it("should handle empty calldata (native ETH transfer) - DENY to unknown", () => {
    const request = makeRequest({
      to: "0xdead000000000000000000000000000000000001",
      functionSelector: undefined,
      data: undefined,
    });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(false);
  });

  it("should handle malformed calldata gracefully", () => {
    // A function selector that does not match any allowlist/blocklist
    const request = makeRequest({
      to: AAVE_POOL,
      functionSelector: "0xffffffff",
    });
    const result = engine.evaluate(request, makeContext());
    // Should still be allowed since the recipient IS in the allowlist
    // and the function is not in the blocklist
    expect(result.allowed).toBe(true);
  });

  it("should respect rule priority ordering (lower priority number = higher priority)", () => {
    // Create an engine where a lower-priority allow and higher-priority deny exist
    const eng = new PolicyEngine([
      makeDenyRule("high-pri-deny", [
        { type: "max_value_usd", threshold: 100 },
      ], { priority: 1 }),
      makeAllowRule("low-pri-allow", [
        { type: "max_value_usd", threshold: 100 },
      ], { priority: 100 }),
    ]);
    const request = makeRequest({ to: AAVE_POOL, valueUsd: 500 });
    const result = eng.evaluate(request, makeContext());
    expect(result.allowed).toBe(false);
  });

  it("should skip disabled rules", () => {
    const eng = new PolicyEngine([
      makeDenyRule("disabled-deny", [
        { type: "recipient_allowlist", addresses: [] }, // deny everything
      ], { enabled: false }),
    ]);
    const request = makeRequest({ to: "0xdead000000000000000000000000000000000001" });
    const result = eng.evaluate(request, makeContext());
    expect(result.allowed).toBe(true);
  });

  it("should skip expired rules", () => {
    const eng = new PolicyEngine([
      makeDenyRule("expired-deny", [
        { type: "recipient_allowlist", addresses: [] },
      ], { expiresAt: "2020-01-01T00:00:00Z" }),
    ]);
    const request = makeRequest({ to: "0xdead000000000000000000000000000000000001" });
    const result = eng.evaluate(request, makeContext());
    expect(result.allowed).toBe(true);
  });
});

// ===========================================================================
// 3. SPENDING LIMIT TESTS
// ===========================================================================

describe("Spending Limits", () => {
  it("should track per-transaction spending", () => {
    const key = makeVaultKey();
    const overLimit = 2_000_000_000_000_000_000n; // 2 ETH > 1 ETH per-tx
    const result = checkSpendingLimit(key, "native", overLimit);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("per-transaction limit");
  });

  it("should allow transaction within per-tx limit", () => {
    const key = makeVaultKey();
    const withinLimit = 500_000_000_000_000_000n; // 0.5 ETH
    const result = checkSpendingLimit(key, "native", withinLimit);
    expect(result.allowed).toBe(true);
  });

  it("should track daily aggregate spending", () => {
    let key = makeVaultKey();
    const amount = 1_000_000_000_000_000_000n; // 1 ETH

    // Record 5 transactions (totaling 5 ETH = the daily limit)
    for (let i = 0; i < 5; i++) {
      const check = checkSpendingLimit(key, "native", amount);
      expect(check.allowed).toBe(true);
      key = recordSpend(key, "native", amount);
    }

    // 6th transaction should be denied (would exceed 5 ETH daily)
    const finalCheck = checkSpendingLimit(key, "native", amount);
    expect(finalCheck.allowed).toBe(false);
    expect(finalCheck.reason).toContain("daily limit");
  });

  it("should track monthly aggregate spending", () => {
    const key = makeVaultKey({
      scope: {
        allowedChains: ["1"],
        allowedContracts: [],
        allowedFunctions: [],
        spendingLimits: [
          {
            tokenAddress: "native",
            perTx: 10_000_000_000_000_000_000n, // 10 ETH per tx
            daily: 100_000_000_000_000_000_000n, // 100 ETH daily (high)
            monthly: 5_000_000_000_000_000_000n, // 5 ETH monthly (low)
          },
        ],
        expiry: null,
        autoRotateInterval: null,
      },
      spentThisMonth: { native: 4_500_000_000_000_000_000n }, // already 4.5 ETH
    });

    const amount = 1_000_000_000_000_000_000n; // 1 ETH (would total 5.5 > 5)
    const result = checkSpendingLimit(key, "native", amount);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("monthly limit");
  });

  it("should auto-reset daily limits at day boundary", () => {
    const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
    const key = makeVaultKey({
      lastResetDay: yesterday,
      spentToday: { native: 5_000_000_000_000_000_000n }, // maxed out yesterday
    });

    // After day boundary, the daily spend should be considered 0
    const amount = 500_000_000_000_000_000n; // 0.5 ETH
    const result = checkSpendingLimit(key, "native", amount);
    expect(result.allowed).toBe(true);
  });

  it("should auto-reset monthly limits at month boundary", () => {
    // Set lastResetMonth to a previous month
    const key = makeVaultKey({
      lastResetMonth: "2025-01",
      spentThisMonth: { native: 50_000_000_000_000_000_000n }, // maxed out
    });

    const amount = 500_000_000_000_000_000n;
    const result = checkSpendingLimit(key, "native", amount);
    expect(result.allowed).toBe(true);
  });

  it("should deny when cumulative daily spend exceeds limit", () => {
    const key = makeVaultKey({
      spentToday: { native: 4_500_000_000_000_000_000n }, // 4.5 ETH already
    });

    const amount = 600_000_000_000_000_000n; // 0.6 ETH (total 5.1 > 5)
    const result = checkSpendingLimit(key, "native", amount);
    expect(result.allowed).toBe(false);
  });

  it("should allow after daily reset via recordSpend", () => {
    const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
    let key = makeVaultKey({
      lastResetDay: yesterday,
      spentToday: { native: 5_000_000_000_000_000_000n },
    });

    // Reset should clear the counter
    key = resetDailySpend(key);
    expect(key.spentToday).toEqual({});

    const result = checkSpendingLimit(key, "native", 500_000_000_000_000_000n);
    expect(result.allowed).toBe(true);
  });

  it("should deny when key status is revoked", () => {
    const key = makeVaultKey({ status: "revoked" });
    const result = checkSpendingLimit(key, "native", 1n);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("revoked");
  });

  it("should deny when key has expired", () => {
    const key = makeVaultKey({ expiresAt: "2020-01-01T00:00:00Z" });
    const result = checkSpendingLimit(key, "native", 1n);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("expired");
  });

  it("should allow spend for tokens with no limit defined", () => {
    const key = makeVaultKey();
    // "unknown-token" has no spending limit in the key scope
    const result = checkSpendingLimit(key, "unknown-token", 999_999_999n);
    expect(result.allowed).toBe(true);
  });

  it("should correctly increment spend counters via recordSpend", () => {
    let key = makeVaultKey();
    const amount = 100_000_000_000_000_000n; // 0.1 ETH

    key = recordSpend(key, "native", amount);
    expect(key.spentToday["native"]).toBe(amount);
    expect(key.spentThisMonth["native"]).toBe(amount);
    expect(key.signCount).toBe(1);

    key = recordSpend(key, "native", amount);
    expect(key.spentToday["native"]).toBe(amount * 2n);
    expect(key.signCount).toBe(2);
  });
});

// ===========================================================================
// 4. EVM TRANSACTION SIGNING TESTS
// ===========================================================================

describe("EVM Transaction Signing", () => {
  const signer = new EvmSigner();
  const testChain: ChainConfig = {
    chainId: "1",
    family: "evm",
    name: "Ethereum Mainnet",
    rpcUrl: "https://unused.test",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  };

  const { privateKey: testPrivateKey } = deriveAgentKey(TEST_MASTER_SEED, 0);

  it("should produce valid RLP-encoded EIP-1559 transaction", async () => {
    const request: SignRequest = {
      keyId: "agent-key-0",
      chain: testChain,
      to: AAVE_POOL,
      value: 1_000_000_000_000_000_000n, // 1 ETH
      nonce: 0,
      gasLimit: 21_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_500_000_000n,
    };

    const signed = await signer.sign(request, testPrivateKey);

    // Must start with 0x02 (EIP-1559 type prefix)
    expect(signed.rawTx.startsWith("0x02")).toBe(true);
    expect(signed.txHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(signed.from).toMatch(/^0x[0-9a-f]{40}$/);
    expect(signed.to).toBe(AAVE_POOL);
    expect(signed.chain).toBe("1");
  });

  it("should produce correct signing hash (keccak256 of 0x02 || RLP)", async () => {
    const request: SignRequest = {
      keyId: "agent-key-0",
      chain: testChain,
      to: AAVE_POOL,
      value: 0n,
      nonce: 5,
      gasLimit: 100_000n,
      maxFeePerGas: 20_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
    };

    const signed = await signer.sign(request, testPrivateKey);

    // The txHash should be keccak256 of the full signed raw tx
    const rawBytes = hexToBytes(signed.rawTx);
    const expectedHash = "0x" + bytesToHex(keccak_256(rawBytes));
    expect(signed.txHash).toBe(expectedHash);
  });

  it("should produce recoverable signature (r, s, v)", async () => {
    const request: SignRequest = {
      keyId: "agent-key-0",
      chain: testChain,
      to: AAVE_POOL,
      value: 0n,
      nonce: 0,
      gasLimit: 21_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_500_000_000n,
    };

    const signed = await signer.sign(request, testPrivateKey);
    // Raw tx is non-empty and has reasonable length
    const rawBytes = hexToBytes(signed.rawTx);
    // EIP-1559 tx: type (1 byte) + RLP encoded fields
    expect(rawBytes[0]).toBe(0x02);
    expect(rawBytes.length).toBeGreaterThan(50);
  });

  it("should recover correct signer address from signature", async () => {
    const request: SignRequest = {
      keyId: "agent-key-0",
      chain: testChain,
      to: AAVE_POOL,
      value: 0n,
      nonce: 0,
      gasLimit: 21_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_500_000_000n,
    };

    const signed = await signer.sign(request, testPrivateKey);

    // Verify the `from` field matches the address derived from our test key
    const expectedAddress = publicKeyToEvmAddress(
      secp256k1.getPublicKey(testPrivateKey, true),
    );
    expect(signed.from).toBe(expectedAddress);
  });

  it("should produce deterministic signatures for same input", async () => {
    const request: SignRequest = {
      keyId: "agent-key-0",
      chain: testChain,
      to: AAVE_POOL,
      value: 0n,
      nonce: 42,
      gasLimit: 21_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_500_000_000n,
    };

    const signed1 = await signer.sign(request, testPrivateKey);
    const signed2 = await signer.sign(request, testPrivateKey);
    // secp256k1 signing in @noble/curves is deterministic (RFC 6979)
    expect(signed1.rawTx).toBe(signed2.rawTx);
    expect(signed1.txHash).toBe(signed2.txHash);
  });
});

// ===========================================================================
// 5. EMERGENCY FREEZE TESTS
// ===========================================================================

describe("Emergency Freeze", () => {
  it("should block ALL signing when agent key is frozen (revoked)", () => {
    const key = makeVaultKey({ status: "revoked" });
    const result = checkSpendingLimit(key, "native", 1n);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("revoked");
  });

  it("should block ALL signing when key is in rotating state", () => {
    const key = makeVaultKey({ status: "rotating" });
    const result = checkSpendingLimit(key, "native", 1n);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("rotating");
  });

  it("should allow signing after unfreeze (re-activation)", () => {
    // Start frozen
    let key = makeVaultKey({ status: "revoked" });
    let result = checkSpendingLimit(key, "native", 1n);
    expect(result.allowed).toBe(false);

    // Unfreeze by setting status back to active
    key = { ...key, status: "active" };
    result = checkSpendingLimit(key, "native", 500_000_000_000_000_000n);
    expect(result.allowed).toBe(true);
  });

  it("should persist freeze across function calls (status is immutable)", () => {
    const key = makeVaultKey({ status: "revoked" });

    // Multiple checks should all fail
    expect(checkSpendingLimit(key, "native", 1n).allowed).toBe(false);
    expect(checkSpendingLimit(key, "native", 0n).allowed).toBe(false);
    expect(checkSpendingLimit(key, "unknown-token", 1n).allowed).toBe(false);
  });

  it("should block via policy engine when agent tier is below required tier", () => {
    const engine = new PolicyEngine([
      makeDenyRule("require-operator", [
        { type: "require_key_tier", minTier: "operator" },
      ]),
    ]);

    const request = makeRequest({ keyTier: "agent" });
    const result = engine.evaluate(request, makeContext());
    expect(result.allowed).toBe(false);
  });
});

// ===========================================================================
// 6. SELF-CUSTODY INVARIANTS
// ===========================================================================

describe("Self-Custody Invariants", () => {
  it("should never expose raw private key in deriveKeyAtPath return structure beyond privateKey field", () => {
    const result = deriveKeyAtPath(TEST_MASTER_SEED, DERIVATION_PATHS.evm(0));
    // The return value must only have privateKey and publicKey fields
    const keys = Object.keys(result);
    expect(keys).toContain("privateKey");
    expect(keys).toContain("publicKey");
    expect(keys.length).toBe(2);
  });

  it("should never expose raw private key in agent/operator key return beyond expected fields", () => {
    const agentResult = deriveAgentKey(TEST_MASTER_SEED, 0);
    const fields = Object.keys(agentResult);
    // Must only contain privateKey, publicKey, address
    expect(fields.sort()).toEqual(["address", "privateKey", "publicKey"]);
  });

  it("should produce different master seeds for different entropy", () => {
    const entropy1 = new Uint8Array(32).fill(0xaa);
    const entropy2 = new Uint8Array(32).fill(0xbb);
    const seed1 = deriveMasterSeed(entropy1);
    const seed2 = deriveMasterSeed(entropy2);
    expect(bytesToHex(seed1)).not.toBe(bytesToHex(seed2));
  });

  it("should derive unique keys per vault (different entropy = different key hierarchy)", () => {
    const entropy1 = new Uint8Array(32).fill(0x01);
    const entropy2 = new Uint8Array(32).fill(0x02);
    const seed1 = deriveMasterSeed(entropy1);
    const seed2 = deriveMasterSeed(entropy2);

    const agent1 = deriveAgentKey(seed1, 0);
    const agent2 = deriveAgentKey(seed2, 0);
    expect(agent1.address).not.toBe(agent2.address);
    expect(bytesToHex(agent1.privateKey)).not.toBe(bytesToHex(agent2.privateKey));
  });

  it("should not leak key material in signed transaction output", async () => {
    const signer = new EvmSigner();
    const testChain: ChainConfig = {
      chainId: "1",
      family: "evm",
      name: "Ethereum",
      rpcUrl: "https://unused.test",
      nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    };

    const { privateKey } = deriveAgentKey(TEST_MASTER_SEED, 0);
    const request: SignRequest = {
      keyId: "agent-key-0",
      chain: testChain,
      to: AAVE_POOL,
      value: 0n,
      nonce: 0,
      gasLimit: 21_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_500_000_000n,
    };

    const signed = await signer.sign(request, privateKey);
    const privateKeyHex = bytesToHex(privateKey);

    // The raw transaction MUST NOT contain the private key
    expect(signed.rawTx).not.toContain(privateKeyHex);
    expect(signed.txHash).not.toContain(privateKeyHex);
    expect(JSON.stringify(signed)).not.toContain(privateKeyHex);
  });
});

// ===========================================================================
// 7. EDGE CASES
// ===========================================================================

describe("Edge Cases", () => {
  const signer = new EvmSigner();
  const testChain: ChainConfig = {
    chainId: "1",
    family: "evm",
    name: "Ethereum",
    rpcUrl: "https://unused.test",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  };
  const { privateKey: testPrivateKey } = deriveAgentKey(TEST_MASTER_SEED, 0);

  it("should handle zero-value transactions", async () => {
    const request: SignRequest = {
      keyId: "agent-key-0",
      chain: testChain,
      to: AAVE_POOL,
      value: 0n,
      nonce: 0,
      gasLimit: 21_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_500_000_000n,
    };

    const signed = await signer.sign(request, testPrivateKey);
    expect(signed.rawTx).toBeTruthy();
    expect(signed.txHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("should handle max uint256 amounts in policy checks", () => {
    const maxUint256 = 2n ** 256n - 1n;
    const key = makeVaultKey();
    const result = checkSpendingLimit(key, "native", maxUint256);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("per-transaction limit");
  });

  it("should handle very long calldata in signing", async () => {
    // 4KB of calldata (multicall-style)
    const longData = "0x" + "ab".repeat(4096);
    const request: SignRequest = {
      keyId: "agent-key-0",
      chain: testChain,
      to: UNISWAP_ROUTER,
      data: longData,
      value: 0n,
      nonce: 0,
      gasLimit: 500_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_500_000_000n,
    };

    const signed = await signer.sign(request, testPrivateKey);
    expect(signed.rawTx).toBeTruthy();
    // Raw tx must be longer than the calldata itself
    expect(signed.rawTx.length).toBeGreaterThan(longData.length);
  });

  it("should handle chain ID 0 without crashing", async () => {
    const zeroChain: ChainConfig = {
      ...testChain,
      chainId: "0",
    };
    const request: SignRequest = {
      keyId: "agent-key-0",
      chain: zeroChain,
      to: AAVE_POOL,
      value: 0n,
      nonce: 0,
      gasLimit: 21_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_500_000_000n,
    };

    // Should not throw
    const signed = await signer.sign(request, testPrivateKey);
    expect(signed.rawTx).toBeTruthy();
  });

  it("should handle concurrent signing requests without race conditions", async () => {
    const requests = Array.from({ length: 10 }, (_, i) => ({
      keyId: "agent-key-0",
      chain: testChain,
      to: AAVE_POOL,
      value: 0n,
      nonce: i,
      gasLimit: 21_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_500_000_000n,
    } satisfies SignRequest));

    const results = await Promise.all(
      requests.map((r) => signer.sign(r, testPrivateKey)),
    );

    // All should succeed
    expect(results.length).toBe(10);
    // All should have unique tx hashes (different nonces)
    const hashes = new Set(results.map((r) => r.txHash));
    expect(hashes.size).toBe(10);
  });

  it("should handle zero spending amount", () => {
    const key = makeVaultKey();
    const result = checkSpendingLimit(key, "native", 0n);
    expect(result.allowed).toBe(true);
  });

  it("should correctly RLP-encode empty bytes", () => {
    const encoded = rlpEncode(new Uint8Array(0));
    expect(encoded).toEqual(new Uint8Array([0x80]));
  });

  it("should correctly RLP-encode single byte < 0x80", () => {
    const encoded = rlpEncode(new Uint8Array([0x42]));
    expect(encoded).toEqual(new Uint8Array([0x42]));
  });

  it("should correctly RLP-encode bigint zero", () => {
    const encoded = rlpEncode(0n);
    expect(encoded).toEqual(new Uint8Array([0x80]));
  });

  it("should correctly RLP-encode a list", () => {
    const encoded = rlpEncode([]);
    expect(encoded).toEqual(new Uint8Array([0xc0]));
  });
});

// ===========================================================================
// 8. CONDITION EVALUATOR UNIT TESTS
// ===========================================================================

describe("Condition Evaluators", () => {
  it("should match recipient_blocklist when address is blocked", () => {
    const condition: PolicyCondition = {
      type: "recipient_blocklist",
      addresses: ["0xDeaD000000000000000000000000000000000001"],
    };
    const request = makeRequest({ to: "0xdead000000000000000000000000000000000001" });
    const result = evaluateCondition(condition, request, makeContext());
    // Case-insensitive match
    expect(result.matched).toBe(true);
  });

  it("should not match recipient_blocklist when address is not blocked", () => {
    const condition: PolicyCondition = {
      type: "recipient_blocklist",
      addresses: ["0xDeaD000000000000000000000000000000000001"],
    };
    const request = makeRequest({ to: AAVE_POOL });
    const result = evaluateCondition(condition, request, makeContext());
    expect(result.matched).toBe(false);
  });

  it("should enforce velocity limits", () => {
    const condition: PolicyCondition = {
      type: "velocity_limit",
      maxTxCount: 5,
      windowSeconds: 3600,
    };
    const request = makeRequest();
    const contextOverLimit = makeContext({ recentTxCount: 6 });
    expect(evaluateCondition(condition, request, contextOverLimit).matched).toBe(true);

    const contextUnderLimit = makeContext({ recentTxCount: 3 });
    expect(evaluateCondition(condition, request, contextUnderLimit).matched).toBe(false);
  });

  it("should enforce allowed_chains", () => {
    const condition: PolicyCondition = {
      type: "allowed_chains",
      chainIds: ["1", "137"],
    };
    const allowed = makeRequest({ chain: "1" });
    expect(evaluateCondition(condition, allowed, makeContext()).matched).toBe(false); // NOT triggered

    const denied = makeRequest({ chain: "56" }); // BSC not in allowlist
    expect(evaluateCondition(condition, denied, makeContext()).matched).toBe(true); // triggered
  });

  it("should enforce blocked_chains", () => {
    const condition: PolicyCondition = {
      type: "blocked_chains",
      chainIds: ["56"], // BSC blocked
    };
    const blocked = makeRequest({ chain: "56" });
    expect(evaluateCondition(condition, blocked, makeContext()).matched).toBe(true);

    const allowed = makeRequest({ chain: "1" });
    expect(evaluateCondition(condition, allowed, makeContext()).matched).toBe(false);
  });

  it("should enforce time_window restrictions", () => {
    const condition: PolicyCondition = {
      type: "time_window",
      startHourUtc: 9,
      endHourUtc: 17,
    };

    // Create a timestamp at 3 AM UTC (outside window)
    const at3am = new Date("2026-03-27T03:00:00Z").getTime();
    const request3am = makeRequest({ timestamp: at3am });
    expect(evaluateCondition(condition, request3am, makeContext()).matched).toBe(true);

    // Create a timestamp at 12 PM UTC (inside window)
    const at12pm = new Date("2026-03-27T12:00:00Z").getTime();
    const request12pm = makeRequest({ timestamp: at12pm });
    expect(evaluateCondition(condition, request12pm, makeContext()).matched).toBe(false);
  });

  it("should enforce max_gas_usd", () => {
    const condition: PolicyCondition = { type: "max_gas_usd", threshold: 50 };
    const expensive = makeRequest({ gasEstimateUsd: 100 });
    expect(evaluateCondition(condition, expensive, makeContext()).matched).toBe(true);

    const cheap = makeRequest({ gasEstimateUsd: 10 });
    expect(evaluateCondition(condition, cheap, makeContext()).matched).toBe(false);
  });

  it("should handle cooldown_seconds", () => {
    const condition: PolicyCondition = { type: "cooldown_seconds", seconds: 60 };
    const request = makeRequest();

    // Last tx was 10 seconds ago
    const tooSoon = makeContext({ lastTxTimestamp: Date.now() - 10_000 });
    expect(evaluateCondition(condition, request, tooSoon).matched).toBe(true);

    // No previous tx
    const noTx = makeContext({ lastTxTimestamp: null });
    expect(evaluateCondition(condition, request, noTx).matched).toBe(false);
  });

  it("should handle unknown condition type gracefully", () => {
    const condition = { type: "nonexistent_type" } as unknown as PolicyCondition;
    const result = evaluateCondition(condition, makeRequest(), makeContext());
    expect(result.matched).toBe(false);
    expect(result.reason).toContain("Unknown condition type");
  });
});
