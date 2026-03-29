/**
 * MACHINA Vault — Key Hierarchy Types
 * MAC-897: 4-Tier Key Hierarchy (Root → Operator → Agent → Session Keys)
 */
export type KeyTier = "root" | "operator" | "agent" | "session";
export type KeyStatus = "active" | "revoked" | "expired" | "rotating";
export interface KeyPermissions {
    /** 256-bit permission bitfield */
    mask: bigint;
}
/** Permission bit positions */
export declare const PERM: {
    readonly CREATE_OPERATOR_KEY: 0n;
    readonly REVOKE_OPERATOR_KEY: 1n;
    readonly CREATE_AGENT_KEY: 2n;
    readonly REVOKE_AGENT_KEY: 3n;
    readonly CREATE_SESSION_KEY: 4n;
    readonly REVOKE_SESSION_KEY: 5n;
    readonly SIGN_TRANSACTION: 6n;
    readonly MANAGE_POLICY: 7n;
    readonly VIEW_BALANCES: 8n;
    readonly INITIATE_RECOVERY: 9n;
    readonly MANAGE_IDENTITY: 10n;
    readonly APPROVE_TRANSACTION: 11n;
    readonly MANAGE_ALLOWLIST: 12n;
    readonly ROTATE_KEYS: 13n;
    readonly VIEW_AUDIT_LOG: 14n;
    readonly MANAGE_WEBHOOKS: 15n;
};
export interface SpendingLimit {
    /** "native" for native token, or ERC-20 contract address */
    tokenAddress: string;
    /** Max per transaction (in token base units) */
    perTx: bigint;
    /** Max per day */
    daily: bigint;
    /** Max per month */
    monthly: bigint;
}
export interface KeyScope {
    /** Allowed chain IDs (e.g. ["1", "137", "8453"]) */
    allowedChains: string[];
    /** Allowed contract addresses */
    allowedContracts: string[];
    /** Allowed 4-byte function selectors (hex-encoded) */
    allowedFunctions: string[];
    /** Spending limits per token */
    spendingLimits: SpendingLimit[];
    /** ISO 8601 expiry timestamp, or null for no expiry */
    expiry: string | null;
    /** ISO 8601 duration for auto-rotation, or null */
    autoRotateInterval: string | null;
}
export interface VaultKey {
    /** Unique key identifier */
    id: string;
    /** Parent vault ID */
    vaultId: string;
    /** Key tier in the hierarchy */
    tier: KeyTier;
    /** Human-readable key name */
    name: string;
    /** secp256k1 or ed25519 public key (compressed) */
    publicKey: Uint8Array;
    /** Derived address (0x-prefixed for EVM) */
    address: string;
    /** ID of the parent key that created this one; null for root */
    parentKeyId: string | null;
    /** Permission bitfield */
    permissions: KeyPermissions;
    /** Scope constraints */
    scope: KeyScope;
    /** Current key status */
    status: KeyStatus;
    /** Total number of signatures produced */
    signCount: number;
    /** ISO 8601 creation timestamp */
    createdAt: string;
    /** ISO 8601 expiry timestamp, or null */
    expiresAt: string | null;
    /** ISO 8601 revocation timestamp, or null */
    revokedAt: string | null;
    /** ISO 8601 last usage timestamp, or null */
    lastUsedAt: string | null;
    /** Spending tracking: tokenAddress → amount spent today */
    spentToday: Record<string, bigint>;
    /** Spending tracking: tokenAddress → amount spent this month */
    spentThisMonth: Record<string, bigint>;
    /** ISO date (YYYY-MM-DD) of last daily spend reset */
    lastResetDay: string;
    /** ISO month (YYYY-MM) of last monthly spend reset */
    lastResetMonth: string;
}
//# sourceMappingURL=types.d.ts.map