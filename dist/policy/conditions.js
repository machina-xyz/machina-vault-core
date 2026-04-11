/**
 * MACHINA Vault — Condition Evaluators
 * MAC-899: Policy-Before-Signing: TEE-Enforced Policy Evaluation
 *
 * Each condition type has a dedicated evaluator that returns whether the
 * condition matched (i.e. the policy restriction is triggered) and a
 * human-readable reason string.
 */
const TIER_RANK = {
    root: 3,
    operator: 2,
    agent: 1,
    session: 0,
};
function normalizeAddress(addr) {
    return addr.toLowerCase();
}
const evaluators = {
    max_value_usd(condition, request) {
        const exceeded = request.valueUsd > condition.threshold;
        return {
            matched: exceeded,
            reason: exceeded
                ? `Transaction value $${request.valueUsd} exceeds max $${condition.threshold}`
                : `Transaction value $${request.valueUsd} within limit $${condition.threshold}`,
        };
    },
    max_value_token(condition, request) {
        // Token-specific value check uses the raw bigint value
        const exceeded = request.value > condition.threshold;
        return {
            matched: exceeded,
            reason: exceeded
                ? `Token ${condition.token} value ${request.value} exceeds max ${condition.threshold}`
                : `Token ${condition.token} value ${request.value} within limit ${condition.threshold}`,
        };
    },
    daily_limit_usd(condition, request, context) {
        const projectedTotal = context.dailySpendUsd + request.valueUsd;
        const exceeded = projectedTotal > condition.threshold;
        return {
            matched: exceeded,
            reason: exceeded
                ? `Daily spend $${projectedTotal.toFixed(2)} would exceed limit $${condition.threshold}`
                : `Daily spend $${projectedTotal.toFixed(2)} within limit $${condition.threshold}`,
        };
    },
    monthly_limit_usd(condition, request, context) {
        const projectedTotal = context.monthlySpendUsd + request.valueUsd;
        const exceeded = projectedTotal > condition.threshold;
        return {
            matched: exceeded,
            reason: exceeded
                ? `Monthly spend $${projectedTotal.toFixed(2)} would exceed limit $${condition.threshold}`
                : `Monthly spend $${projectedTotal.toFixed(2)} within limit $${condition.threshold}`,
        };
    },
    allowed_contracts(condition, request) {
        const normalized = condition.addresses.map(normalizeAddress);
        const isAllowed = normalized.includes(normalizeAddress(request.to));
        return {
            matched: !isAllowed,
            reason: isAllowed
                ? `Contract ${request.to} is in the allowlist`
                : `Contract ${request.to} is not in the allowlist`,
        };
    },
    blocked_contracts(condition, request) {
        const normalized = condition.addresses.map(normalizeAddress);
        const isBlocked = normalized.includes(normalizeAddress(request.to));
        return {
            matched: isBlocked,
            reason: isBlocked
                ? `Contract ${request.to} is blocked`
                : `Contract ${request.to} is not blocked`,
        };
    },
    allowed_functions(condition, request) {
        if (!request.functionSelector) {
            return { matched: false, reason: "No function selector present (plain transfer)" };
        }
        const normalized = condition.selectors.map((s) => s.toLowerCase());
        const isAllowed = normalized.includes(request.functionSelector.toLowerCase());
        return {
            matched: !isAllowed,
            reason: isAllowed
                ? `Function ${request.functionSelector} is in the allowlist`
                : `Function ${request.functionSelector} is not in the allowlist`,
        };
    },
    blocked_functions(condition, request) {
        if (!request.functionSelector) {
            return { matched: false, reason: "No function selector present (plain transfer)" };
        }
        const normalized = condition.selectors.map((s) => s.toLowerCase());
        const isBlocked = normalized.includes(request.functionSelector.toLowerCase());
        return {
            matched: isBlocked,
            reason: isBlocked
                ? `Function ${request.functionSelector} is blocked`
                : `Function ${request.functionSelector} is not blocked`,
        };
    },
    allowed_chains(condition, request) {
        const isAllowed = condition.chainIds.includes(request.chain);
        return {
            matched: !isAllowed,
            reason: isAllowed
                ? `Chain ${request.chain} is in the allowlist`
                : `Chain ${request.chain} is not in the allowlist`,
        };
    },
    blocked_chains(condition, request) {
        const isBlocked = condition.chainIds.includes(request.chain);
        return {
            matched: isBlocked,
            reason: isBlocked
                ? `Chain ${request.chain} is blocked`
                : `Chain ${request.chain} is not blocked`,
        };
    },
    time_window(condition, request) {
        const date = new Date(request.timestamp);
        const hourUtc = date.getUTCHours();
        const dayOfWeek = date.getUTCDay(); // 0 = Sunday
        // Check day-of-week restriction
        if (condition.daysOfWeek && condition.daysOfWeek.length > 0) {
            if (!condition.daysOfWeek.includes(dayOfWeek)) {
                return {
                    matched: true,
                    reason: `Day ${dayOfWeek} is outside allowed days [${condition.daysOfWeek.join(", ")}]`,
                };
            }
        }
        // Check hour window — the window defines ALLOWED hours
        let outsideWindow;
        if (condition.startHourUtc <= condition.endHourUtc) {
            // Simple range, e.g. 9-17
            outsideWindow = hourUtc < condition.startHourUtc || hourUtc >= condition.endHourUtc;
        }
        else {
            // Wrapping range, e.g. 22-6 means allowed from 22:00 to 06:00
            outsideWindow = hourUtc < condition.startHourUtc && hourUtc >= condition.endHourUtc;
        }
        return {
            matched: outsideWindow,
            reason: outsideWindow
                ? `Current hour ${hourUtc} UTC is outside allowed window ${condition.startHourUtc}-${condition.endHourUtc}`
                : `Current hour ${hourUtc} UTC is within allowed window ${condition.startHourUtc}-${condition.endHourUtc}`,
        };
    },
    max_gas_usd(condition, request) {
        if (request.gasEstimateUsd === undefined) {
            return { matched: false, reason: "No gas estimate provided" };
        }
        const exceeded = request.gasEstimateUsd > condition.threshold;
        return {
            matched: exceeded,
            reason: exceeded
                ? `Gas estimate $${request.gasEstimateUsd} exceeds max $${condition.threshold}`
                : `Gas estimate $${request.gasEstimateUsd} within limit $${condition.threshold}`,
        };
    },
    require_key_tier(condition, request) {
        const requestRank = TIER_RANK[request.keyTier] ?? 0;
        const requiredRank = TIER_RANK[condition.minTier] ?? 0;
        const insufficient = requestRank < requiredRank;
        return {
            matched: insufficient,
            reason: insufficient
                ? `Key tier "${request.keyTier}" is below required minimum "${condition.minTier}"`
                : `Key tier "${request.keyTier}" meets minimum "${condition.minTier}"`,
        };
    },
    cooldown_seconds(condition, _request, context) {
        if (context.lastTxTimestamp === null) {
            return { matched: false, reason: "No previous transaction — cooldown does not apply" };
        }
        const elapsedMs = Date.now() - context.lastTxTimestamp;
        const elapsedSec = elapsedMs / 1000;
        const tooSoon = elapsedSec < condition.seconds;
        return {
            matched: tooSoon,
            reason: tooSoon
                ? `Only ${elapsedSec.toFixed(1)}s since last tx, cooldown requires ${condition.seconds}s`
                : `${elapsedSec.toFixed(1)}s since last tx, cooldown ${condition.seconds}s satisfied`,
        };
    },
    velocity_limit(condition, _request, context) {
        const exceeded = context.recentTxCount >= condition.maxTxCount;
        return {
            matched: exceeded,
            reason: exceeded
                ? `${context.recentTxCount} txs in window exceeds limit of ${condition.maxTxCount} per ${condition.windowSeconds}s`
                : `${context.recentTxCount} txs in window within limit of ${condition.maxTxCount} per ${condition.windowSeconds}s`,
        };
    },
    recipient_allowlist(condition, request) {
        const normalized = condition.addresses.map(normalizeAddress);
        const isAllowed = normalized.includes(normalizeAddress(request.to));
        return {
            matched: !isAllowed,
            reason: isAllowed
                ? `Recipient ${request.to} is in the allowlist`
                : `Recipient ${request.to} is not in the allowlist`,
        };
    },
    recipient_blocklist(condition, request) {
        const normalized = condition.addresses.map(normalizeAddress);
        const isBlocked = normalized.includes(normalizeAddress(request.to));
        return {
            matched: isBlocked,
            reason: isBlocked
                ? `Recipient ${request.to} is blocked`
                : `Recipient ${request.to} is not blocked`,
        };
    },
};
/**
 * Evaluate a single policy condition against a transaction request.
 * Returns whether the condition matched (triggered) and a reason string.
 */
export function evaluateCondition(condition, request, context) {
    const evaluator = evaluators[condition.type];
    if (!evaluator) {
        return { matched: false, reason: `Unknown condition type: ${condition.type}` };
    }
    return evaluator(condition, request, context);
}
