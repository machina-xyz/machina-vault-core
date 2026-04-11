/**
 * MACHINA Vault — Condition Evaluators
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 *
 * Each condition type has a dedicated evaluator that returns whether the
 * condition matched (i.e. the policy restriction is triggered) and a
 * human-readable reason string.
 */
import type { PolicyCondition, PolicyEvalRequest, PolicyContext } from "./types.js";
export interface ConditionResult {
    matched: boolean;
    reason: string;
}
/**
 * Evaluate a single policy condition against a transaction request.
 * Returns whether the condition matched (triggered) and a reason string.
 */
export declare function evaluateCondition(condition: PolicyCondition, request: PolicyEvalRequest, context: PolicyContext): ConditionResult;
