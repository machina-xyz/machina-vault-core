/**
 * MACHINA Vault — Threshold Signing Protocol
 * MAC-901: DKLS23-based MPC threshold signing
 *
 * Implements a 4-round threshold ECDSA signing protocol with a
 * TEE-combiner architecture (combiner runs inside a trusted enclave):
 *
 *   Round 1: Each party generates a nonce k_i, commits to R_i = k_i * G
 *   Round 2: Parties reveal R_i after receiving all commitments
 *   Round 3: Each party sends its nonce k_i and weighted secret share
 *            lambda_i * x_i to the TEE combiner (encrypted in transit)
 *   Round 4: Combiner reconstructs k = sum(k_i) and x = sum(lambda_i * x_i),
 *            computes standard ECDSA signature s = k^{-1} * (e + r * x)
 *
 * The partial signature in round 3 encodes both the nonce share and
 * the Lagrange-weighted secret share as a single 128-char hex string
 * (k_i || lambda_i*x_i). The TEE combiner is the only entity that
 * sees the plaintext values; they are encrypted in transit to the enclave.
 *
 * Cloudflare Workers compatible — Web Crypto API + @noble/curves only.
 */
import type { MPCKeyShare, MPCSignResult, SignRound1Msg, SignRound2Msg, SignRound3Msg, SignRound4Msg } from "./types.js";
import { Point } from "./keygen.js";
export interface SignRound1State {
    /** This party's key share */
    share: MPCKeyShare;
    /** The message hash being signed (32 bytes) */
    messageHash: Uint8Array;
    /** Secret nonce k_i */
    nonce: bigint;
    /** Public nonce R_i = k_i * G */
    noncePublic: typeof Point.BASE;
    /** Commitment randomness */
    commitmentOpening: Uint8Array;
    /** All participating party indices (1-based), populated in round 2 */
    participantIndices: number[];
}
export interface SignRound2State extends SignRound1State {
    /** All round 1 messages */
    round1Messages: SignRound1Msg[];
}
export interface SignRound3State extends SignRound2State {
    /** All round 2 messages (revealed nonce points) */
    round2Messages: SignRound2Msg[];
    /** Combined nonce point R = sum(R_i) */
    combinedR: typeof Point.BASE;
}
/**
 * Generate a secret nonce k_i, compute R_i = k_i * G, and create
 * a hash commitment H(R_i || randomness).
 */
export declare function signRound1(share: MPCKeyShare, messageHex: string, participantIds: string[]): {
    state: SignRound1State;
    round1Msg: SignRound1Msg;
};
/**
 * After receiving all commitments, reveal our nonce point R_i
 * and store the participant indices for Lagrange interpolation.
 */
export declare function signRound2(state: SignRound1State, round1Messages: SignRound1Msg[]): {
    state: SignRound2State;
    round2Msg: SignRound2Msg;
};
/**
 * Verify all revealed nonces against commitments, compute the combined
 * nonce point R, and produce a partial signature containing both
 * the nonce share k_i and the Lagrange-weighted secret share lambda_i * x_i.
 *
 * The partialSignature field encodes: k_i (64 hex) || lambda_i*x_i (64 hex).
 */
export declare function signRound3(state: SignRound2State, round2Messages: SignRound2Msg[]): {
    state: SignRound3State;
    round3Msg: SignRound3Msg;
};
/**
 * Combine all partial signatures into a valid ECDSA signature.
 * Executed by the TEE combiner which receives all parties' nonce
 * shares and weighted secret shares.
 *
 * Reconstructs k = sum(k_i) and x = sum(lambda_i * x_i), then
 * computes s = k^{-1} * (e + r * x) mod n.
 */
export declare function signRound4(state: SignRound3State, round3Messages: SignRound3Msg[]): {
    result: MPCSignResult;
    round4Msg: SignRound4Msg;
};
/**
 * Execute the complete 4-round threshold ECDSA signing protocol.
 *
 * Simulates all rounds locally — suitable for testing or when all
 * parties are co-located within a single TEE.
 *
 * @param shares - Key shares of participating parties (length >= threshold)
 * @param messageHex - 32-byte message hash (hex-encoded, 64 chars)
 * @returns Valid ECDSA signature with recovery ID
 */
export declare function thresholdSign(shares: MPCKeyShare[], messageHex: string): MPCSignResult;
/**
 * Verify an ECDSA signature against a public key.
 *
 * @param messageHex - 32-byte message hash (hex)
 * @param signatureHex - DER-encoded signature (hex)
 * @param publicKeyHex - Compressed secp256k1 public key (hex)
 */
export declare function verifySignature(messageHex: string, signatureHex: string, publicKeyHex: string): boolean;
//# sourceMappingURL=signing.d.ts.map