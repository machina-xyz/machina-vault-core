/**
 * MACHINA Vault — Distributed Key Generation (Feldman VSS)
 * MAC-901: DKLS23-based MPC threshold signing
 *
 * Implements a 3-round DKG protocol using Feldman's Verifiable Secret Sharing:
 *
 *   Round 1: Each party generates a random polynomial of degree t-1,
 *            broadcasts Feldman commitments (g^a_i for each coefficient).
 *
 *   Round 2: Each party evaluates its polynomial at every other party's
 *            index and sends the resulting share privately.
 *
 *   Round 3: Each party verifies received shares against the broadcasted
 *            commitments, computes its combined secret share, and derives
 *            the group public key as the sum of all parties' first commitments.
 *
 * Cloudflare Workers compatible — Web Crypto API + @noble/curves only.
 */
import type { MPCKeyShare, KeygenRound1Msg, KeygenRound2Msg, KeygenRound3Msg } from "./types.js";
declare const Point: import("@noble/curves/abstract/weierstrass").WeierstrassPointCons<bigint>;
type ProjectivePoint = typeof Point.BASE;
declare const CURVE_ORDER: bigint;
/** Generate a random non-zero scalar mod n */
declare function randomScalar(): bigint;
/** Encode a scalar as a 32-byte big-endian hex string */
declare function scalarToHex(s: bigint): string;
/** Decode a hex string to a scalar */
declare function hexToScalar(hex: string): bigint;
/**
 * Evaluate a polynomial at a given x value.
 *   f(x) = coefficients[0] + coefficients[1]*x + coefficients[2]*x^2 + ...
 * All arithmetic is mod curve order n.
 */
declare function evaluatePolynomial(coefficients: bigint[], x: bigint): bigint;
export interface KeygenRound1State {
    partyId: string;
    partyIndex: number;
    threshold: number;
    totalParties: number;
    /** The random polynomial coefficients (secret) */
    coefficients: bigint[];
    /** Feldman commitments: g^a_i for each coefficient */
    commitments: ProjectivePoint[];
    /** Chain code (random 32 bytes, will be XOR-combined in round 3) */
    chainCodeContribution: Uint8Array;
}
export interface KeygenRound2State extends KeygenRound1State {
    /** All round 1 messages received */
    round1Messages: KeygenRound1Msg[];
    /** All parties' Feldman commitments (indexed by partyId) */
    allCommitments: Map<string, ProjectivePoint[]>;
}
export interface KeygenRound3State extends KeygenRound2State {
    /** Shares received from other parties (indexed by fromParty) */
    receivedShares: Map<string, bigint>;
}
/**
 * Execute keygen round 1: generate a random polynomial of degree t-1,
 * compute Feldman commitments, and produce the round 1 broadcast message.
 *
 * @param partyId - Unique identifier for this party
 * @param partyIndex - 1-based index for this party
 * @param threshold - Minimum parties required (t)
 * @param totalParties - Total number of parties (n)
 * @returns State for round 2 and the round 1 message to broadcast
 */
export declare function keygenRound1(partyId: string, partyIndex: number, threshold: number, totalParties: number): {
    state: KeygenRound1State;
    round1Msg: KeygenRound1Msg;
};
/**
 * Execute keygen round 2: after receiving all round 1 messages, evaluate
 * our polynomial at each other party's index and produce share messages.
 *
 * @param state - State from round 1
 * @param round1Messages - All round 1 messages from all parties (including self)
 * @returns Updated state and array of round 2 messages (one per other party)
 */
export declare function keygenRound2(state: KeygenRound1State, round1Messages: KeygenRound1Msg[]): {
    state: KeygenRound2State;
    round2Messages: KeygenRound2Msg[];
};
/**
 * Execute keygen round 3: verify all received shares against Feldman commitments,
 * compute the combined secret share, and derive the group public key.
 *
 * @param state - State from round 2
 * @param round2Messages - All round 2 messages addressed to this party
 * @returns The final key share for this party and the round 3 broadcast message
 */
export declare function keygenRound3(state: KeygenRound2State, round2Messages: KeygenRound2Msg[]): {
    keyShare: MPCKeyShare;
    round3Msg: KeygenRound3Msg;
};
/**
 * Verify a party's round 3 message: check that their public share is consistent
 * with the Feldman commitments from all parties, and verify the Schnorr proof.
 *
 * @param msg - The round 3 message to verify
 * @param allCommitments - Map of partyId -> Feldman commitments from round 1
 * @param totalParties - Total number of parties
 */
export declare function verifyKeygenRound3(msg: KeygenRound3Msg, allCommitments: Map<string, ProjectivePoint[]>): boolean;
/**
 * Generate a complete set of key shares in a single call.
 * This simulates the full 3-round DKG protocol locally.
 *
 * WARNING: This runs the entire protocol in a single process and is only
 * suitable for testing or scenarios where a trusted dealer is acceptable.
 * In production, use the round-by-round functions.
 *
 * @param threshold - Minimum parties required to sign (t)
 * @param totalParties - Total number of parties (n)
 * @returns All key shares and the group public key
 */
export declare function generateKeyShares(threshold: number, totalParties: number): {
    shares: MPCKeyShare[];
    publicKey: string;
};
/**
 * Compute the Lagrange coefficient (lambda) for a party at index `i`
 * given a set of participating party indices.
 *
 * lambda_i = product_{j != i} (j / (j - i)) mod n
 *
 * @param i - The party's 1-based index
 * @param indices - All participating parties' 1-based indices
 * @returns The Lagrange coefficient as a scalar mod n
 */
export declare function lagrangeCoefficient(i: number, indices: number[]): bigint;
/**
 * Reconstruct the secret from a threshold number of shares using
 * Lagrange interpolation. Used for verification only — in production
 * the secret is never reconstructed.
 *
 * @param shares - Array of { index, value } pairs
 * @returns The reconstructed secret as a scalar
 */
export declare function reconstructSecret(shares: Array<{
    index: number;
    value: bigint;
}>): bigint;
/**
 * Compute the expected public point for a share evaluated at index x,
 * given the Feldman commitments.
 *
 * Expected = sum_{j=0}^{t-1} (x^j * C_j)
 *
 * This is the public-key equivalent of evaluating the polynomial at x.
 */
declare function verifyFeldmanShare(commitments: ProjectivePoint[], x: bigint): ProjectivePoint;
/** Modular inverse using extended Euclidean algorithm */
declare function modInverse(a: bigint, m: bigint): bigint;
/** Concatenate multiple Uint8Arrays */
declare function concatBytes(...arrays: Uint8Array[]): Uint8Array;
export { randomScalar, scalarToHex, hexToScalar, evaluatePolynomial, verifyFeldmanShare, modInverse, concatBytes, Point, CURVE_ORDER, };
export type { ProjectivePoint };
//# sourceMappingURL=keygen.d.ts.map