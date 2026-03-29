/**
 * Vault Reputation Integration
 *
 * Connects vault identity to the MACHINA reputation protocol.
 * Reputation is computed from on-chain activity, peer attestations,
 * and compliance history.
 */
/**
 * Calculate reputation tier from score.
 */
export function getReputationTier(score) {
    if (score >= 800)
        return "elite";
    if (score >= 600)
        return "trusted";
    if (score >= 400)
        return "established";
    if (score >= 200)
        return "emerging";
    return "unverified";
}
/**
 * Create initial reputation snapshot for a new vault.
 */
export function createInitialReputation(agentId) {
    return {
        agentId,
        overallScore: 100,
        components: {
            transactionHistory: 0,
            peerAttestations: 0,
            complianceRecord: 100, // Start with full compliance (no violations)
            protocolParticipation: 0,
            longevity: 0,
        },
        tier: "unverified",
        lastUpdated: new Date().toISOString(),
    };
}
/**
 * Update reputation based on a completed transaction.
 */
export function updateReputationForTransaction(snapshot, params) {
    const txScore = snapshot.components.transactionHistory;
    const increment = params.success
        ? Math.min(5, Math.ceil(Math.log10(Math.max(1, params.valueUsd))))
        : -10;
    const newTxScore = Math.max(0, Math.min(200, txScore + increment));
    const newOverall = newTxScore +
        snapshot.components.peerAttestations +
        snapshot.components.complianceRecord +
        snapshot.components.protocolParticipation +
        snapshot.components.longevity;
    return {
        ...snapshot,
        overallScore: Math.min(1000, newOverall),
        components: {
            ...snapshot.components,
            transactionHistory: newTxScore,
        },
        tier: getReputationTier(Math.min(1000, newOverall)),
        lastUpdated: new Date().toISOString(),
    };
}
/**
 * Update reputation based on a peer attestation.
 */
export function updateReputationForAttestation(snapshot, params) {
    // Weight attestation by attester's own reputation
    const weight = Math.max(1, Math.floor(params.attesterScore / 200));
    const increment = params.positive ? weight * 2 : -(weight * 3);
    const newAttScore = Math.max(0, Math.min(200, snapshot.components.peerAttestations + increment));
    const newOverall = snapshot.components.transactionHistory +
        newAttScore +
        snapshot.components.complianceRecord +
        snapshot.components.protocolParticipation +
        snapshot.components.longevity;
    return {
        ...snapshot,
        overallScore: Math.min(1000, newOverall),
        components: {
            ...snapshot.components,
            peerAttestations: newAttScore,
        },
        tier: getReputationTier(Math.min(1000, newOverall)),
        lastUpdated: new Date().toISOString(),
    };
}
/**
 * Apply longevity bonus based on account age.
 */
export function updateLongevityScore(snapshot, accountCreatedAt) {
    const ageMs = Date.now() - new Date(accountCreatedAt).getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);
    // Score grows logarithmically with age: 0 at day 0, ~200 at 1 year
    const longevityScore = Math.min(200, Math.floor(Math.log2(Math.max(1, ageDays)) * 28));
    const newOverall = snapshot.components.transactionHistory +
        snapshot.components.peerAttestations +
        snapshot.components.complianceRecord +
        snapshot.components.protocolParticipation +
        longevityScore;
    return {
        ...snapshot,
        overallScore: Math.min(1000, newOverall),
        components: {
            ...snapshot.components,
            longevity: longevityScore,
        },
        tier: getReputationTier(Math.min(1000, newOverall)),
        lastUpdated: new Date().toISOString(),
    };
}
/**
 * Check if an agent meets a minimum reputation threshold.
 * Used for reputation-gated operations (e.g., large transfers, governance voting).
 */
export function meetsReputationThreshold(snapshot, minScore, minTier) {
    if (minScore !== undefined && snapshot.overallScore < minScore)
        return false;
    if (minTier !== undefined) {
        const tierOrder = ["unverified", "emerging", "established", "trusted", "elite"];
        const currentIdx = tierOrder.indexOf(snapshot.tier);
        const requiredIdx = tierOrder.indexOf(minTier);
        if (currentIdx < requiredIdx)
            return false;
    }
    return true;
}
//# sourceMappingURL=reputation.js.map