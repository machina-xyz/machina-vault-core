/**
 * Social Recovery via Shamir Secret Sharing
 *
 * Splits a master seed into n shares with threshold t.
 * Any t shares can reconstruct the seed; fewer than t reveals nothing.
 *
 * Uses GF(256) arithmetic for Shamir's Secret Sharing scheme.
 */
import type { RecoveryConfig, RecoveryGuardian, RecoveryRequest } from "./types.js";
/**
 * Split a secret into n shares with threshold t using Shamir's Secret Sharing.
 *
 * @param secret - The secret bytes to split
 * @param threshold - Minimum shares needed to reconstruct (t)
 * @param totalShares - Total number of shares to generate (n)
 * @returns Array of shares, each with an index (1-based) and data
 */
export declare function splitSecret(secret: Uint8Array, threshold: number, totalShares: number): Array<{
    index: number;
    data: Uint8Array;
}>;
/**
 * Reconstruct a secret from t shares using Lagrange interpolation in GF(256).
 *
 * @param shares - Array of shares (must have at least threshold shares)
 * @returns Reconstructed secret bytes
 */
export declare function reconstructSecret(shares: Array<{
    index: number;
    data: Uint8Array;
}>): Uint8Array;
/**
 * Create a recovery configuration for a vault.
 */
export declare function createRecoveryConfig(vaultId: string, threshold: number, guardians: Array<{
    identifier: string;
    type: RecoveryGuardian["type"];
    name: string;
}>, options?: {
    cloudBackup?: boolean;
    hardwareBackup?: boolean;
    cooldownSeconds?: number;
}): RecoveryConfig;
/**
 * Initiate a recovery request.
 */
export declare function initiateRecovery(vaultId: string, config: RecoveryConfig, method: RecoveryRequest["method"]): RecoveryRequest;
/**
 * Submit a guardian share for recovery.
 */
export declare function submitRecoveryShare(request: RecoveryRequest, guardianId: string): RecoveryRequest;
//# sourceMappingURL=social-recovery.d.ts.map