/**
 * MACHINA Vault — Policy Evaluation Engine
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 *
 * Evaluates policy rules against transaction requests inside the TEE
 * before any signing operation proceeds. Designed for sub-millisecond
 * evaluation on typical rule sets within Cloudflare Workers.
 */
import type { PolicyRule, PolicyScope, PolicyEvalRequest, PolicyEvalResult, PolicyContext } from "./types.js";
export declare class PolicyEngine {
    private rules;
    constructor(rules?: PolicyRule[]);
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
    evaluate(request: PolicyEvalRequest, context: PolicyContext): PolicyEvalResult;
    addRule(rule: PolicyRule): void;
    removeRule(ruleId: string): void;
    updateRule(ruleId: string, updates: Partial<PolicyRule>): void;
    getRules(scope?: PolicyScope): PolicyRule[];
    private getActiveRulesSorted;
    private buildResult;
}
