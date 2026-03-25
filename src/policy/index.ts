/**
 * MACHINA Vault — Policy Module
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 */

// Types
export type {
  PolicyAction,
  PolicyStatus,
  PolicyScope,
  PolicyRule,
  PolicyCondition,
  PolicyEvalRequest,
  PolicyEvalResult,
  PolicyContext,
} from "./types.js";

// Engine
export { PolicyEngine } from "./engine.js";

// Condition evaluators
export { evaluateCondition } from "./conditions.js";
export type { ConditionResult } from "./conditions.js";

// Presets
export {
  CONSERVATIVE_PRESET,
  STANDARD_PRESET,
  AGGRESSIVE_PRESET,
  LOCKDOWN_PRESET,
} from "./presets.js";

// Natural language parser
export { parseNaturalLanguagePolicy } from "./natural-language.js";
