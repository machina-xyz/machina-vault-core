/**
 * Vault Reputation Integration
 *
 * Connects vault identity to the MACHINA reputation protocol.
 * Reputation is computed from on-chain activity, peer attestations,
 * and compliance history.
 */
export interface ReputationSnapshot {
    agentId: string;
    overallScore: number;
    components: {
        transactionHistory: number;
        peerAttestations: number;
        complianceRecord: number;
        protocolParticipation: number;
        longevity: number;
    };
    tier: ReputationTier;
    lastUpdated: string;
}
export type ReputationTier = "unverified" | "emerging" | "established" | "trusted" | "elite";
/**
 * Calculate reputation tier from score.
 */
export declare function getReputationTier(score: number): ReputationTier;
/**
 * Create initial reputation snapshot for a new vault.
 */
export declare function createInitialReputation(agentId: string): ReputationSnapshot;
/**
 * Update reputation based on a completed transaction.
 */
export declare function updateReputationForTransaction(snapshot: ReputationSnapshot, params: {
    success: boolean;
    valueUsd: number;
    chainId: string;
}): ReputationSnapshot;
/**
 * Update reputation based on a peer attestation.
 */
export declare function updateReputationForAttestation(snapshot: ReputationSnapshot, params: {
    attesterScore: number;
    positive: boolean;
}): ReputationSnapshot;
/**
 * Apply longevity bonus based on account age.
 */
export declare function updateLongevityScore(snapshot: ReputationSnapshot, accountCreatedAt: string): ReputationSnapshot;
/**
 * Check if an agent meets a minimum reputation threshold.
 * Used for reputation-gated operations (e.g., large transfers, governance voting).
 */
export declare function meetsReputationThreshold(snapshot: ReputationSnapshot, minScore?: number, minTier?: ReputationTier): boolean;
//# sourceMappingURL=reputation.d.ts.map