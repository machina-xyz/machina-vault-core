/**
 * MACHINA Vault — Privacy Module Types
 * MAC-903: Stealth Addresses (ERC-5564) & ZK Balance Proofs
 *
 * Types for stealth address generation/scanning and Pedersen commitment
 * based balance proofs. All hex strings are 0x-prefixed unless noted.
 */
/** ERC-5564 scheme ID for secp256k1 */
export declare const SCHEME_ID_SECP256K1 = 1;
/**
 * Stealth meta-address: the public component shared with senders.
 * Encoded as st:eth:0x<spendingPubKey><viewingPubKey>
 */
export interface StealthMetaAddress {
    /** Compressed secp256k1 spending public key (hex) */
    spendingPubKey: string;
    /** Compressed secp256k1 viewing public key (hex) */
    viewingPubKey: string;
    /** ERC-5564 scheme prefix (1 for secp256k1) */
    prefix: number;
}
/**
 * A derived stealth address with its ephemeral public key and view tag.
 * The sender produces this; the recipient scans for it.
 */
export interface StealthAddress {
    /** Ethereum address (0x-prefixed, checksummed) */
    address: string;
    /** Compressed ephemeral public key R (hex) */
    ephemeralPubKey: string;
    /** View tag: first byte of hash(shared_secret) for fast scanning */
    viewTag: number;
}
/**
 * Full stealth key pair: spending + viewing keys.
 * The spending key MUST be kept in secure enclave; the viewing key
 * can be shared with a scanning service.
 */
export interface StealthKeyPair {
    /** Spending private key scalar (hex) */
    spendingKey: string;
    /** Viewing private key scalar (hex) */
    viewingKey: string;
    /** Compressed spending public key S (hex) */
    spendingPubKey: string;
    /** Compressed viewing public key V (hex) */
    viewingPubKey: string;
}
/**
 * Pedersen commitment based balance proof.
 *
 * WARNING: This is NOT a full zero-knowledge proof. It provides:
 * - Commitment hiding: the balance value is hidden behind the commitment
 * - Commitment binding: the prover cannot change the balance after committing
 * - Simplified range proof via bit decomposition commitments
 *
 * For production-grade ZK proofs, a SNARK/STARK circuit is required.
 */
export interface BalanceProof {
    /** Pedersen commitment C = balance * G + blinding * H (hex) */
    commitment: string;
    /** Serialised range proof data (hex) */
    rangeProofData: string;
    /** Token contract address (or "native" for ETH) */
    tokenAddress: string;
    /** Chain ID */
    chainId: string;
    /** ISO 8601 timestamp of proof creation */
    timestamp: string;
}
/**
 * Request parameters for creating a balance proof.
 */
export interface BalanceProofRequest {
    /** The actual balance to commit to */
    balance: bigint;
    /** Token contract address (or "native" for ETH) */
    tokenAddress: string;
    /** Chain ID */
    chainId: string;
    /** Optional: prove balance >= minBalance */
    minBalance?: bigint;
    /** Optional: prove balance <= maxBalance */
    maxBalance?: bigint;
}
/**
 * Result of verifying a balance proof.
 */
export interface BalanceProofVerification {
    /** Whether the proof structure and commitments are valid */
    valid: boolean;
    /** Token contract address from the proof */
    tokenAddress: string;
    /** Chain ID from the proof */
    chainId: string;
    /** Whether the range proof (if present) validates successfully */
    withinRange: boolean;
}
/**
 * Privacy module configuration.
 */
export interface PrivacyConfig {
    /** Enable stealth address generation and scanning */
    stealthEnabled: boolean;
    /** Enable balance proof creation and verification */
    balanceProofsEnabled: boolean;
    /** Default view tag length in bytes (ERC-5564 uses 1) */
    defaultViewTag: number;
}
/**
 * On-chain announcement log entry per ERC-5564.
 * Emitted by the ERC-5564 Announcer contract.
 */
export interface AnnouncementLog {
    /** The derived stealth address */
    stealthAddress: string;
    /** Compressed ephemeral public key R (hex) */
    ephemeralPubKey: string;
    /** View tag for fast scanning */
    viewTag: number;
    /** Encoded metadata (hex) */
    metadata: string;
    /** ERC-5564 scheme ID (1 for secp256k1) */
    schemeId: number;
    /** Address of the caller who made the announcement */
    caller: string;
    /** Block number of the announcement */
    blockNumber: number;
}
