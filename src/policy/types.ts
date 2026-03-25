/**
 * MACHINA Vault — Policy Types
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 */

export type PolicyAction = "allow" | "deny" | "require_approval" | "rate_limit" | "alert";
export type PolicyStatus = "active" | "disabled" | "expired";
export type PolicyScope = "vault" | "key" | "chain" | "contract" | "function";

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  scope: PolicyScope;
  conditions: PolicyCondition[];
  action: PolicyAction;
  priority: number;         // lower = evaluated first
  enabled: boolean;
  createdBy: string;        // key ID that created this policy
  createdAt: string;
  expiresAt: string | null;
}

export type PolicyCondition =
  | { type: "max_value_usd"; threshold: number }
  | { type: "max_value_token"; token: string; threshold: bigint }
  | { type: "daily_limit_usd"; threshold: number }
  | { type: "monthly_limit_usd"; threshold: number }
  | { type: "allowed_contracts"; addresses: string[] }
  | { type: "blocked_contracts"; addresses: string[] }
  | { type: "allowed_functions"; selectors: string[] }
  | { type: "blocked_functions"; selectors: string[] }
  | { type: "allowed_chains"; chainIds: string[] }
  | { type: "blocked_chains"; chainIds: string[] }
  | { type: "time_window"; startHourUtc: number; endHourUtc: number; daysOfWeek?: number[] }
  | { type: "max_gas_usd"; threshold: number }
  | { type: "require_key_tier"; minTier: "root" | "operator" | "agent" }
  | { type: "cooldown_seconds"; seconds: number }
  | { type: "velocity_limit"; maxTxCount: number; windowSeconds: number }
  | { type: "recipient_allowlist"; addresses: string[] }
  | { type: "recipient_blocklist"; addresses: string[] };

export interface PolicyEvalRequest {
  keyId: string;
  keyTier: "root" | "operator" | "agent" | "session";
  vaultId: string;
  chain: string;
  to: string;
  value: bigint;
  valueUsd: number;
  data?: string;              // hex calldata
  functionSelector?: string;  // first 4 bytes of data
  gasEstimateUsd?: number;
  timestamp: number;          // Unix ms
}

export interface PolicyEvalResult {
  allowed: boolean;
  action: PolicyAction;
  matchedRules: Array<{ ruleId: string; ruleName: string; action: PolicyAction; reason: string }>;
  requiresApproval: boolean;
  approvalKeyTier?: "root" | "operator";
  evaluatedAt: string;
  evaluationTimeMs: number;
}

export interface PolicyContext {
  recentTxCount: number;
  lastTxTimestamp: number | null;
  dailySpendUsd: number;
  monthlySpendUsd: number;
}
