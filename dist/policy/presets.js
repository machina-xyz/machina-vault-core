/**
 * MACHINA Vault — Built-in Policy Presets
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 *
 * Ready-to-use rule sets for common security postures.
 * Each preset is a function that returns rules with unique generated IDs.
 */
let idCounter = 0;
function generateId(prefix) {
    idCounter += 1;
    return `${prefix}-${Date.now().toString(36)}-${idCounter.toString(36)}`;
}
function makeRule(partial) {
    const { idPrefix, ...rest } = partial;
    return {
        id: generateId(idPrefix),
        createdBy: "system",
        createdAt: new Date().toISOString(),
        ...rest,
    };
}
/**
 * Conservative preset — tight limits for cautious operations.
 * - $100 daily USD limit
 * - Require approval for any transaction over $50
 * - Only stablecoin-like transfers (no contract interactions)
 * - Block transactions outside business hours (9-17 UTC, weekdays)
 */
export function CONSERVATIVE_PRESET() {
    return [
        makeRule({
            idPrefix: "cons",
            name: "Conservative: Daily limit $100",
            description: "Deny transactions that would push daily spend over $100",
            scope: "vault",
            conditions: [{ type: "daily_limit_usd", threshold: 100 }],
            action: "deny",
            priority: 10,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "cons",
            name: "Conservative: Approval over $50",
            description: "Require operator approval for any transaction over $50 USD",
            scope: "vault",
            conditions: [{ type: "max_value_usd", threshold: 50 }],
            action: "require_approval",
            priority: 20,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "cons",
            name: "Conservative: Block contract calls",
            description: "Block any transaction with calldata (only plain transfers allowed)",
            scope: "vault",
            conditions: [
                { type: "blocked_functions", selectors: ["*"] },
            ],
            action: "deny",
            priority: 5,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "cons",
            name: "Conservative: Business hours only",
            description: "Block transactions outside 9-17 UTC on weekdays",
            scope: "vault",
            conditions: [{ type: "time_window", startHourUtc: 9, endHourUtc: 17, daysOfWeek: [1, 2, 3, 4, 5] }],
            action: "deny",
            priority: 15,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "cons",
            name: "Conservative: Agent tier blocked",
            description: "Require at least operator tier for all transactions",
            scope: "vault",
            conditions: [{ type: "require_key_tier", minTier: "operator" }],
            action: "deny",
            priority: 1,
            enabled: true,
            expiresAt: null,
        }),
    ];
}
/**
 * Standard preset — balanced limits for normal operations.
 * - $10,000 daily USD limit
 * - Require approval for transactions over $1,000
 * - Common DeFi contract interactions allowed
 * - Velocity limit: 50 txs per hour
 */
export function STANDARD_PRESET() {
    return [
        makeRule({
            idPrefix: "std",
            name: "Standard: Daily limit $10k",
            description: "Deny transactions that would push daily spend over $10,000",
            scope: "vault",
            conditions: [{ type: "daily_limit_usd", threshold: 10_000 }],
            action: "deny",
            priority: 10,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "std",
            name: "Standard: Monthly limit $100k",
            description: "Deny transactions that would push monthly spend over $100,000",
            scope: "vault",
            conditions: [{ type: "monthly_limit_usd", threshold: 100_000 }],
            action: "deny",
            priority: 11,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "std",
            name: "Standard: Approval over $1k",
            description: "Require operator approval for any transaction over $1,000 USD",
            scope: "vault",
            conditions: [{ type: "max_value_usd", threshold: 1_000 }],
            action: "require_approval",
            priority: 20,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "std",
            name: "Standard: Velocity limit",
            description: "Rate limit to 50 transactions per hour",
            scope: "vault",
            conditions: [{ type: "velocity_limit", maxTxCount: 50, windowSeconds: 3600 }],
            action: "rate_limit",
            priority: 15,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "std",
            name: "Standard: Gas cap",
            description: "Deny transactions with gas estimates over $50",
            scope: "vault",
            conditions: [{ type: "max_gas_usd", threshold: 50 }],
            action: "deny",
            priority: 12,
            enabled: true,
            expiresAt: null,
        }),
    ];
}
/**
 * Aggressive preset — high limits for active trading / DeFi operations.
 * - $100,000 daily USD limit
 * - Require approval for transactions over $10,000
 * - Wide contract allowlist
 * - Velocity limit: 200 txs per hour
 */
export function AGGRESSIVE_PRESET() {
    return [
        makeRule({
            idPrefix: "agg",
            name: "Aggressive: Daily limit $100k",
            description: "Deny transactions that would push daily spend over $100,000",
            scope: "vault",
            conditions: [{ type: "daily_limit_usd", threshold: 100_000 }],
            action: "deny",
            priority: 10,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "agg",
            name: "Aggressive: Monthly limit $1M",
            description: "Deny transactions that would push monthly spend over $1,000,000",
            scope: "vault",
            conditions: [{ type: "monthly_limit_usd", threshold: 1_000_000 }],
            action: "deny",
            priority: 11,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "agg",
            name: "Aggressive: Approval over $10k",
            description: "Require operator approval for any transaction over $10,000 USD",
            scope: "vault",
            conditions: [{ type: "max_value_usd", threshold: 10_000 }],
            action: "require_approval",
            priority: 20,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "agg",
            name: "Aggressive: Velocity limit",
            description: "Rate limit to 200 transactions per hour",
            scope: "vault",
            conditions: [{ type: "velocity_limit", maxTxCount: 200, windowSeconds: 3600 }],
            action: "rate_limit",
            priority: 15,
            enabled: true,
            expiresAt: null,
        }),
        makeRule({
            idPrefix: "agg",
            name: "Aggressive: Gas cap",
            description: "Deny transactions with gas estimates over $200",
            scope: "vault",
            conditions: [{ type: "max_gas_usd", threshold: 200 }],
            action: "deny",
            priority: 12,
            enabled: true,
            expiresAt: null,
        }),
    ];
}
/**
 * Lockdown preset — deny everything except Root key transactions.
 * Used during incidents or when a vault needs to be frozen.
 */
export function LOCKDOWN_PRESET() {
    return [
        makeRule({
            idPrefix: "lock",
            name: "Lockdown: Root only",
            description: "Deny all transactions from non-root keys. Root keys bypass policies automatically.",
            scope: "vault",
            conditions: [{ type: "require_key_tier", minTier: "root" }],
            action: "deny",
            priority: 0,
            enabled: true,
            expiresAt: null,
        }),
    ];
}
