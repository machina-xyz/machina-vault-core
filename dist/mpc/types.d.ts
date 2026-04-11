/**
 * MACHINA Vault — MPC Threshold Signing Types
 * MAC-901: DKLS23-based MPC threshold signing
 *
 * Core type definitions for distributed key generation, threshold signing,
 * and proactive secret resharing protocols.
 */
export interface MPCKeyShare {
    /** Unique identifier for this party */
    partyId: string;
    /** 1-based share index (evaluation point on the polynomial) */
    shareIndex: number;
    /** Compressed secp256k1 public key (hex) — the combined group key */
    publicKey: string;
    /** Secret share value (hex-encoded scalar mod n) */
    secretShare: string;
    /** Minimum number of shares required to sign */
    threshold: number;
    /** Total number of parties in the sharing */
    totalParties: number;
    /** Chain code for BIP-32 compatible derivation (hex, 32 bytes) */
    chainCode: string;
    /** ISO 8601 creation timestamp */
    createdAt: string;
}
export type MPCSessionType = "keygen" | "signing" | "reshare";
export type MPCSessionStatus = "initialized" | "round1" | "round2" | "round3" | "round4" | "completed" | "failed";
export interface MPCSession {
    /** Unique session identifier */
    sessionId: string;
    /** Protocol phase this session is executing */
    type: MPCSessionType;
    /** Participating parties */
    parties: PartyInfo[];
    /** Threshold (t of n) */
    threshold: number;
    /** Current session status */
    status: MPCSessionStatus;
    /** Current round number (1-based) */
    round: number;
    /** Total rounds in this protocol */
    totalRounds: number;
    /** ISO 8601 creation timestamp */
    createdAt: string;
}
export interface PartyInfo {
    /** Unique identifier for this party */
    partyId: string;
    /** 1-based index used as the polynomial evaluation point */
    index: number;
    /** Hex-encoded public commitment (compressed point on secp256k1) */
    publicCommitment: string;
    /** Whether this party has completed the current round */
    ready: boolean;
}
export interface MPCSignRequest {
    /** Session ID coordinating this signing ceremony */
    sessionId: string;
    /** Message to sign (hex-encoded, typically a 32-byte hash) */
    message: string;
    /** Optional BIP-32 derivation path (e.g. "m/44'/60'/0'/0/0") */
    derivationPath?: string;
    /** Party IDs participating in this signing (must be >= threshold) */
    parties: string[];
}
export interface MPCSignResult {
    /** DER-encoded ECDSA signature (hex) */
    signature: string;
    /** Recovery ID (0 or 1) for ecrecover */
    recoveryId: number;
    /** Compressed public key of the signer (hex) */
    publicKey: string;
    /** Party IDs that participated */
    parties: string[];
}
/** Round 1: Each party broadcasts Feldman VSS commitments */
export interface KeygenRound1Msg {
    /** Sender party ID */
    fromParty: string;
    /** Sender's 1-based index */
    fromIndex: number;
    /**
     * Feldman VSS commitments: g^a_0, g^a_1, ..., g^a_{t-1}
     * Each entry is a hex-encoded compressed secp256k1 point.
     */
    commitments: string[];
    /** Hash commitment to the coefficient zero point (used for consistency check) */
    hashCommitment: string;
}
/** Round 2: Each party sends encrypted share evaluations */
export interface KeygenRound2Msg {
    /** Sender party ID */
    fromParty: string;
    /** Sender's 1-based index */
    fromIndex: number;
    /** Recipient party ID */
    toParty: string;
    /** Recipient's 1-based index */
    toIndex: number;
    /** The evaluated share f_from(toIndex) — hex-encoded scalar */
    encryptedShare: string;
}
/** Round 3: Each party confirms verification and publishes its public share */
export interface KeygenRound3Msg {
    /** Sender party ID */
    fromParty: string;
    /** Sender's 1-based index */
    fromIndex: number;
    /** This party's public share point (hex, compressed) */
    publicShare: string;
    /** Proof of knowledge of the secret share (Schnorr proof) */
    proofR: string;
    /** Schnorr proof response */
    proofS: string;
}
/** Sign Round 1: Nonce commitment */
export interface SignRound1Msg {
    /** Sender party ID */
    fromParty: string;
    /** Sender's 1-based index */
    fromIndex: number;
    /** Hash commitment to the nonce point R_i = k_i * G (SHA-256 hash, hex) */
    commitment: string;
}
/** Sign Round 2: Nonce reveal */
export interface SignRound2Msg {
    /** Sender party ID */
    fromParty: string;
    /** Sender's 1-based index */
    fromIndex: number;
    /** Revealed nonce point R_i (hex, compressed) */
    noncePublic: string;
    /** Opening randomness for the commitment (hex) */
    opening: string;
}
/** Sign Round 3: Partial signature */
export interface SignRound3Msg {
    /** Sender party ID */
    fromParty: string;
    /** Sender's 1-based index */
    fromIndex: number;
    /** Partial signature s_i (hex-encoded scalar) */
    partialSignature: string;
}
/** Sign Round 4: Combined signature (broadcast by combiner) */
export interface SignRound4Msg {
    /** The final aggregated R point (hex, compressed) */
    combinedR: string;
    /** The final aggregated s scalar (hex) */
    combinedS: string;
    /** Recovery ID */
    recoveryId: number;
}
export interface ReshareConfig {
    /** Previous threshold (t) */
    oldThreshold: number;
    /** New threshold (t') */
    newThreshold: number;
    /** Party IDs of existing shareholders */
    oldParties: string[];
    /** Party IDs of new shareholders */
    newParties: string[];
}
/** Reshare Round 1: Old party distributes sub-shares to new parties */
export interface ReshareRound1Msg {
    /** Sender party ID (old party) */
    fromParty: string;
    /** Sender's 1-based index among old parties */
    fromIndex: number;
    /** Recipient party ID (new party) */
    toParty: string;
    /** Recipient's 1-based index among new parties */
    toIndex: number;
    /** Sub-share for the new party (hex scalar) */
    subShare: string;
    /**
     * Feldman commitments for the resharing polynomial:
     * g^b_0, g^b_1, ..., g^b_{t'-1}
     * where b_0 = old share value (so the secret is preserved)
     */
    commitments: string[];
}
