/**
 * MACHINA Vault — Policy Module
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 */
export type { PolicyAction, PolicyStatus, PolicyScope, PolicyRule, PolicyCondition, PolicyEvalRequest, PolicyEvalResult, PolicyContext, } from "./types.js";
export { PolicyEngine } from "./engine.js";
export { evaluateCondition } from "./conditions.js";
export type { ConditionResult } from "./conditions.js";
export { CONSERVATIVE_PRESET, STANDARD_PRESET, AGGRESSIVE_PRESET, LOCKDOWN_PRESET, } from "./presets.js";
export { parseNaturalLanguagePolicy } from "./natural-language.js";
//# sourceMappingURL=index.d.ts.map