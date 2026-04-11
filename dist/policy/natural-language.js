/**
 * MACHINA Vault — Natural Language Policy Parser
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 *
 * Regex-based parser that converts simple English descriptions into
 * PolicyRule objects. No LLM dependency — pure string matching.
 */
let nlIdCounter = 0;
function generateNlId() {
    nlIdCounter += 1;
    return `nl-${Date.now().toString(36)}-${nlIdCounter.toString(36)}`;
}
// ---- Pattern matchers ----
const AMOUNT_RE = /\$\s?([\d,]+(?:\.\d+)?)/;
const ADDRESS_RE = /(0x[a-fA-F0-9]{40})/g;
const COUNT_RE = /(\d+)\s+transactions?/i;
const WINDOW_RE = /per\s+(hour|minute|day)/i;
const TIME_RE = /(\d{1,2})\s*(am|pm)/gi;
function parseAmount(text) {
    const match = text.match(AMOUNT_RE);
    if (!match)
        return null;
    return parseFloat(match[1].replace(/,/g, ""));
}
function parseAddresses(text) {
    const matches = text.match(ADDRESS_RE);
    return matches ?? [];
}
function parseCount(text) {
    const match = text.match(COUNT_RE);
    return match ? parseInt(match[1], 10) : null;
}
function parseWindowSeconds(text) {
    const match = text.match(WINDOW_RE);
    if (!match)
        return 3600; // default 1 hour
    switch (match[1].toLowerCase()) {
        case "minute": return 60;
        case "hour": return 3600;
        case "day": return 86400;
        default: return 3600;
    }
}
function parseHour24(hourStr, ampm) {
    let h = parseInt(hourStr, 10);
    if (ampm.toLowerCase() === "pm" && h < 12)
        h += 12;
    if (ampm.toLowerCase() === "am" && h === 12)
        h = 0;
    return h;
}
// ---- Intent detectors ----
function tryBlockOverAmount(input) {
    const lower = input.toLowerCase();
    if (!(lower.includes("block") || lower.includes("deny") || lower.includes("reject")))
        return null;
    if (!(lower.includes("over") || lower.includes("above") || lower.includes("exceed")))
        return null;
    const amount = parseAmount(input);
    if (amount === null)
        return null;
    return {
        action: "deny",
        conditions: [{ type: "max_value_usd", threshold: amount }],
        name: `Block transactions over $${amount}`,
        description: `Deny any transaction with USD value exceeding $${amount}`,
    };
}
function tryRequireApprovalOverAmount(input) {
    const lower = input.toLowerCase();
    if (!lower.includes("approv"))
        return null;
    if (!(lower.includes("over") || lower.includes("above") || lower.includes("exceed")))
        return null;
    const amount = parseAmount(input);
    if (amount === null)
        return null;
    return {
        action: "require_approval",
        conditions: [{ type: "max_value_usd", threshold: amount }],
        name: `Require approval over $${amount}`,
        description: `Require operator approval for transactions exceeding $${amount}`,
    };
}
function tryRecipientAllowlist(input) {
    const lower = input.toLowerCase();
    if (!(lower.includes("only allow") || lower.includes("only send") || lower.includes("only transfer")))
        return null;
    const addresses = parseAddresses(input);
    if (addresses.length === 0)
        return null;
    return {
        action: "deny",
        conditions: [{ type: "recipient_allowlist", addresses }],
        name: `Restrict recipients to ${addresses.length} address(es)`,
        description: `Only allow transfers to specified addresses: ${addresses.join(", ")}`,
    };
}
function tryRecipientBlocklist(input) {
    const lower = input.toLowerCase();
    if (!(lower.includes("block") || lower.includes("deny") || lower.includes("blacklist")))
        return null;
    if (!(lower.includes("to ") || lower.includes("recipient") || lower.includes("address")))
        return null;
    const addresses = parseAddresses(input);
    if (addresses.length === 0)
        return null;
    // Ensure this isn't an "over $X" pattern (handled by tryBlockOverAmount)
    if (lower.includes("over") || lower.includes("above"))
        return null;
    return {
        action: "deny",
        conditions: [{ type: "recipient_blocklist", addresses }],
        name: `Block transfers to ${addresses.length} address(es)`,
        description: `Deny transfers to blocked addresses: ${addresses.join(", ")}`,
    };
}
function tryVelocityLimit(input) {
    const lower = input.toLowerCase();
    if (!(lower.includes("limit") || lower.includes("max") || lower.includes("cap")))
        return null;
    const count = parseCount(input);
    if (count === null)
        return null;
    const windowSeconds = parseWindowSeconds(input);
    return {
        action: "rate_limit",
        conditions: [{ type: "velocity_limit", maxTxCount: count, windowSeconds }],
        name: `Limit to ${count} txs per ${windowSeconds}s`,
        description: `Rate limit to ${count} transactions per ${windowSeconds} seconds`,
    };
}
function tryTimeWindow(input) {
    const lower = input.toLowerCase();
    if (!(lower.includes("between") || lower.includes("after") || lower.includes("before") || lower.includes("outside")))
        return null;
    if (!(lower.includes("am") || lower.includes("pm")))
        return null;
    const timeMatches = [];
    const re = /(\d{1,2})\s*(am|pm)/gi;
    let m;
    while ((m = re.exec(input)) !== null) {
        timeMatches.push({ hour: parseHour24(m[1], m[2]) });
    }
    if (timeMatches.length < 2)
        return null;
    // "no transactions between 10pm and 6am" → block window 22-6
    // We interpret as: block when OUTSIDE the inverse window
    const startHour = timeMatches[0].hour;
    const endHour = timeMatches[1].hour;
    if (lower.includes("no ") || lower.includes("block") || lower.includes("deny")) {
        // User wants to BLOCK during this window, so the allowed window is the inverse
        return {
            action: "deny",
            conditions: [{ type: "time_window", startHourUtc: endHour, endHourUtc: startHour }],
            name: `Block transactions ${formatHour(startHour)}-${formatHour(endHour)} UTC`,
            description: `Deny transactions between ${formatHour(startHour)} and ${formatHour(endHour)} UTC`,
        };
    }
    // "allow transactions between 9am and 5pm" → allowed window 9-17
    return {
        action: "deny",
        conditions: [{ type: "time_window", startHourUtc: startHour, endHourUtc: endHour }],
        name: `Only allow transactions ${formatHour(startHour)}-${formatHour(endHour)} UTC`,
        description: `Deny transactions outside ${formatHour(startHour)} to ${formatHour(endHour)} UTC`,
    };
}
function tryDailyLimit(input) {
    const lower = input.toLowerCase();
    if (!lower.includes("daily") && !lower.includes("per day"))
        return null;
    if (!(lower.includes("limit") || lower.includes("max") || lower.includes("cap")))
        return null;
    const amount = parseAmount(input);
    if (amount === null)
        return null;
    return {
        action: "deny",
        conditions: [{ type: "daily_limit_usd", threshold: amount }],
        name: `Daily limit $${amount}`,
        description: `Deny transactions that would exceed $${amount} daily spend`,
    };
}
function tryBlockChain(input) {
    const lower = input.toLowerCase();
    if (!(lower.includes("block") || lower.includes("deny") || lower.includes("no ")))
        return null;
    if (!lower.includes("chain"))
        return null;
    // Look for chain IDs (numbers)
    const chainIds = Array.from(lower.matchAll(/chain\s*(?:id\s*)?(\d+)/g)).map((m) => m[1]);
    if (chainIds.length === 0)
        return null;
    return {
        action: "deny",
        conditions: [{ type: "blocked_chains", chainIds }],
        name: `Block chain(s) ${chainIds.join(", ")}`,
        description: `Deny transactions on chain IDs: ${chainIds.join(", ")}`,
    };
}
function formatHour(h) {
    if (h === 0)
        return "12am";
    if (h === 12)
        return "12pm";
    return h < 12 ? `${h}am` : `${h - 12}pm`;
}
// ---- Public API ----
const PARSERS = [
    tryBlockOverAmount,
    tryRequireApprovalOverAmount,
    tryRecipientAllowlist,
    tryRecipientBlocklist,
    tryVelocityLimit,
    tryTimeWindow,
    tryDailyLimit,
    tryBlockChain,
];
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
export function parseNaturalLanguagePolicy(input) {
    const trimmed = input.trim();
    if (!trimmed)
        return null;
    for (const parser of PARSERS) {
        const result = parser(trimmed);
        if (result) {
            return {
                id: generateNlId(),
                name: result.name,
                description: result.description,
                scope: "vault",
                conditions: result.conditions,
                action: result.action,
                priority: 50, // default mid-priority for user-created rules
                enabled: true,
                createdBy: "natural-language",
                createdAt: new Date().toISOString(),
                expiresAt: null,
            };
        }
    }
    return null;
}
