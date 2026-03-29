/**
 * Recovery Types
 *
 * Social recovery and backup mechanisms for vault access restoration.
 */
export type RecoveryMethod = "social" | "cloud" | "hardware";
export type RecoveryStatus = "pending" | "in_progress" | "completed" | "failed" | "expired";
export interface RecoveryConfig {
    vaultId: string;
    /** Shamir Secret Sharing threshold: t-of-n */
    threshold: number;
    /** Total number of guardians */
    totalGuardians: number;
    /** Guardian details */
    guardians: RecoveryGuardian[];
    /** Cloud backup enabled */
    cloudBackupEnabled: boolean;
    /** Hardware backup enabled */
    hardwareBackupEnabled: boolean;
    /** Recovery cooldown period (seconds) before recovery takes effect */
    cooldownSeconds: number;
    createdAt: string;
    updatedAt: string;
}
export interface RecoveryGuardian {
    id: string;
    /** Guardian identifier (address, email, or phone) */
    identifier: string;
    /** Guardian type */
    type: "address" | "email" | "social";
    /** Display name */
    name: string;
    /** Whether this guardian has confirmed participation */
    confirmed: boolean;
    /** Shamir share index (1-based) */
    shareIndex: number;
    /** Encrypted share (only stored if cloud backup, otherwise held by guardian) */
    encryptedShare: string | null;
    addedAt: string;
}
export interface RecoveryRequest {
    id: string;
    vaultId: string;
    method: RecoveryMethod;
    status: RecoveryStatus;
    /** Shares collected so far */
    sharesCollected: number;
    /** Threshold needed */
    sharesRequired: number;
    /** Guardians who have submitted shares */
    respondedGuardians: string[];
    /** Cooldown expiry (recovery takes effect after this time) */
    cooldownExpiresAt: string;
    /** Recovery expiry (request expires if not completed) */
    requestExpiresAt: string;
    createdAt: string;
    completedAt: string | null;
}
//# sourceMappingURL=types.d.ts.map