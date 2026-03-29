/**
 * MACHINA Vault — Built-in Policy Presets
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 *
 * Ready-to-use rule sets for common security postures.
 * Each preset is a function that returns rules with unique generated IDs.
 */
import type { PolicyRule } from "./types.js";
/**
 * Conservative preset — tight limits for cautious operations.
 * - $100 daily USD limit
 * - Require approval for any transaction over $50
 * - Only stablecoin-like transfers (no contract interactions)
 * - Block transactions outside business hours (9-17 UTC, weekdays)
 */
export declare function CONSERVATIVE_PRESET(): PolicyRule[];
/**
 * Standard preset — balanced limits for normal operations.
 * - $10,000 daily USD limit
 * - Require approval for transactions over $1,000
 * - Common DeFi contract interactions allowed
 * - Velocity limit: 50 txs per hour
 */
export declare function STANDARD_PRESET(): PolicyRule[];
/**
 * Aggressive preset — high limits for active trading / DeFi operations.
 * - $100,000 daily USD limit
 * - Require approval for transactions over $10,000
 * - Wide contract allowlist
 * - Velocity limit: 200 txs per hour
 */
export declare function AGGRESSIVE_PRESET(): PolicyRule[];
/**
 * Lockdown preset — deny everything except Root key transactions.
 * Used during incidents or when a vault needs to be frozen.
 */
export declare function LOCKDOWN_PRESET(): PolicyRule[];
//# sourceMappingURL=presets.d.ts.map