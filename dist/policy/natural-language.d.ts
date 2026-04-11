/**
 * MACHINA Vault — Natural Language Policy Parser
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 *
 * Regex-based parser that converts simple English descriptions into
 * PolicyRule objects. No LLM dependency — pure string matching.
 */
import type { PolicyRule } from "./types.js";
/**
 * Parse a natural language policy description into a PolicyRule.
 * Returns null if the input could not be understood.
 *
 * Examples:
 *  - "block transactions over $1000"
 *  - "require approval for transactions over $500"
 *  - "only allow transfers to 0x1234..."
 *  - "limit to 5 transactions per hour"
 *  - "no transactions between 10pm and 6am"
 *  - "daily limit of $5000"
 */
export declare function parseNaturalLanguagePolicy(input: string): PolicyRule | null;
