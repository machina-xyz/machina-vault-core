/**
 * MACHINA Vault — Policy Evaluation Engine
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 *
 * Evaluates policy rules against transaction requests inside the TEE
 * before any signing operation proceeds. Designed for sub-millisecond
 * evaluation on typical rule sets within Cloudflare Workers.
 */

import type {
  PolicyRule,
  PolicyScope,
  PolicyAction,
  PolicyEvalRequest,
  PolicyEvalResult,
  PolicyContext,
} from "./types.js";
import { evaluateCondition } from "./conditions.js";

export class PolicyEngine {
  private rules: Map<string, PolicyRule>;

  constructor(rules: PolicyRule[] = []) {
    this.rules = new Map();
    for (const rule of rules) {
      this.rules.set(rule.id, rule);
    }
  }

  /**
   * Evaluate all active rules against a transaction request.
   *
   * Evaluation order:
   *  1. Root keys bypass all policies — always allowed.
   *  2. Rules sorted by priority (ascending — lower number = higher priority).
   *  3. Disabled / expired rules are skipped.
   *  4. A rule matches when ALL of its conditions match.
   *  5. First "deny" match short-circuits evaluation → denied.
   *  6. "require_approval" matches accumulate.
   *  7. If no deny and no require_approval → allowed.
   */
  evaluate(request: PolicyEvalRequest, context: PolicyContext): PolicyEvalResult {
    const start = performance.now();

    // Root keys bypass all policies
    if (request.keyTier === "root") {
      return this.buildResult(true, "allow", [], false, undefined, start);
    }

    const sortedRules = this.getActiveRulesSorted(request.timestamp);
    const matchedRules: PolicyEvalResult["matchedRules"] = [];
    let requiresApproval = false;
    let approvalKeyTier: "root" | "operator" | undefined;

    for (const rule of sortedRules) {
      const conditionResults = rule.conditions.map((c) =>
        evaluateCondition(c, request, context),
      );

      // A rule matches only when ALL conditions match
      const allMatched = conditionResults.every((r) => r.matched);
      if (!allMatched) continue;

      const reasons = conditionResults
        .filter((r) => r.matched)
        .map((r) => r.reason)
        .join("; ");

      matchedRules.push({
        ruleId: rule.id,
        ruleName: rule.name,
        action: rule.action,
        reason: reasons,
      });

      // Deny short-circuits
      if (rule.action === "deny") {
        return this.buildResult(false, "deny", matchedRules, false, undefined, start);
      }

      if (rule.action === "require_approval") {
        requiresApproval = true;
        // Determine minimum approval tier — operator can approve unless
        // the rule explicitly targets operator-level, in which case root is needed.
        const tierCondition = rule.conditions.find(
          (c) => c.type === "require_key_tier",
        );
        if (tierCondition && tierCondition.type === "require_key_tier" && tierCondition.minTier === "root") {
          approvalKeyTier = "root";
        } else if (!approvalKeyTier) {
          approvalKeyTier = "operator";
        }
      }

      if (rule.action === "rate_limit") {
        // Rate limit acts as a soft deny — treated same as deny when triggered
        return this.buildResult(false, "rate_limit", matchedRules, false, undefined, start);
      }

      // "alert" rules are recorded but do not block
    }

    if (requiresApproval) {
      return this.buildResult(false, "require_approval", matchedRules, true, approvalKeyTier, start);
    }

    // No blocking rules matched → allowed
    return this.buildResult(true, "allow", matchedRules, false, undefined, start);
  }

  addRule(rule: PolicyRule): void {
    this.rules.set(rule.id, rule);
  }

  removeRule(ruleId: string): void {
    this.rules.delete(ruleId);
  }

  updateRule(ruleId: string, updates: Partial<PolicyRule>): void {
    const existing = this.rules.get(ruleId);
    if (!existing) {
      throw new Error(`Policy rule not found: ${ruleId}`);
    }
    this.rules.set(ruleId, { ...existing, ...updates, id: ruleId });
  }

  getRules(scope?: PolicyScope): PolicyRule[] {
    const all = Array.from(this.rules.values());
    if (!scope) return all;
    return all.filter((r) => r.scope === scope);
  }

  // ---- private helpers ----

  private getActiveRulesSorted(timestamp: number): PolicyRule[] {
    const active: PolicyRule[] = [];
    for (const rule of this.rules.values()) {
      if (!rule.enabled) continue;
      if (rule.expiresAt !== null && new Date(rule.expiresAt).getTime() <= timestamp) continue;
      active.push(rule);
    }
    active.sort((a, b) => a.priority - b.priority);
    return active;
  }

  private buildResult(
    allowed: boolean,
    action: PolicyAction,
    matchedRules: PolicyEvalResult["matchedRules"],
    requiresApproval: boolean,
    approvalKeyTier: "root" | "operator" | undefined,
    startMs: number,
  ): PolicyEvalResult {
    const evaluationTimeMs = performance.now() - startMs;
    return {
      allowed,
      action,
      matchedRules,
      requiresApproval,
      ...(approvalKeyTier ? { approvalKeyTier } : {}),
      evaluatedAt: new Date().toISOString(),
      evaluationTimeMs,
    };
  }
}
