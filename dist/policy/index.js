/**
 * MACHINA Vault — Policy Module
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 */
// Engine
export { PolicyEngine } from "./engine.js";
// Condition evaluators
export { evaluateCondition } from "./conditions.js";
// Presets
export { CONSERVATIVE_PRESET, STANDARD_PRESET, AGGRESSIVE_PRESET, LOCKDOWN_PRESET, } from "./presets.js";
// Natural language parser
export { parseNaturalLanguagePolicy } from "./natural-language.js";
