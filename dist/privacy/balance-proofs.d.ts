/**
 * MACHINA Vault — ZK Balance Proofs (Pedersen Commitments + Range Proofs)
 * MAC-903: Privacy-preserving balance attestation
 *
 * Implements Pedersen commitment based balance proofs with simplified range
 * proofs using bit decomposition commitments.
 *
 * IMPORTANT LIMITATIONS:
 * These are NOT full zero-knowledge proofs (which would require a SNARK/STARK
 * circuit or a complete Bulletproofs implementation). They provide:
 *
 * - Commitment hiding: the balance value is hidden behind the Pedersen commitment
 * - Commitment binding: the prover cannot change the balance after committing
 *   (computationally binding under the discrete logarithm assumption)
 * - Simplified range proof: proves balance is within [min, max] via bit
 *   decomposition commitments. This is a simplified Bulletproofs-style approach,
 *   NOT a full Bulletproofs implementation with inner-product arguments.
 *
 * For production-grade zero-knowledge proofs with succinctness and full
 * zero-knowledge guarantees, integrate a SNARK/STARK proving system.
 *
 * Cloudflare Workers V8 compatible — no Node.js APIs.
 */
import type { BalanceProof, BalanceProofRequest, BalanceProofVerification } from "./types.js";
/**
 * Create a Pedersen commitment to a balance value.
 *
 * C = balance * G + blinding * H
 *
 * Properties:
 * - Hiding: given C, the balance cannot be determined without the blinding factor
 * - Binding: the prover cannot open C to a different (balance, blinding) pair
 *
 * @param balance - The balance value to commit to
 * @returns Commitment point (hex) and blinding factor (hex)
 */
export declare function createBalanceCommitment(balance: bigint): {
    commitment: string;
    blinding: string;
};
/**
 * Create a balance proof with Pedersen commitment and optional range proof.
 *
 * If minBalance and/or maxBalance are specified, a simplified range proof is
 * included that demonstrates:
 * - balance >= minBalance (via bit decomposition of balance - minBalance)
 * - balance <= maxBalance (via bit decomposition of maxBalance - balance)
 *
 * @param request - Balance proof request parameters
 * @param blinding - Blinding factor from createBalanceCommitment (hex)
 * @returns BalanceProof with commitment and range proof data
 */
export declare function createBalanceProof(request: BalanceProofRequest, blinding: string): BalanceProof;
/**
 * Verify a balance proof: check commitment structure and range proof validity.
 *
 * Verification checks:
 * 1. The commitment is a valid secp256k1 point
 * 2. If range proof present: each bit commitment C_i commits to 0 or 1
 *    (verified by checking C_i is valid and sum of 2^i * C_i reconstructs
 *    the delta commitment)
 *
 * @param proof - The balance proof to verify
 * @param commitment - The expected commitment (hex)
 * @returns Verification result
 */
export declare function verifyBalanceProof(proof: BalanceProof, commitment: string): BalanceProofVerification;
/**
 * Create an aggregate solvency proof across multiple token balances.
 *
 * Uses the homomorphic property of Pedersen commitments:
 * C_total = sum(C_i) = sum(balance_i) * G + sum(blinding_i) * H
 *
 * This proves total solvency without revealing individual balances.
 *
 * @param balances - Array of token balances to prove solvency for
 * @returns Total commitment and individual proofs
 */
export declare function createSolvencyProof(balances: Array<{
    token: string;
    balance: bigint;
}>): {
    totalCommitment: string;
    proofs: BalanceProof[];
};
/**
 * Verify an aggregate solvency proof.
 *
 * Checks that the total commitment equals the homomorphic sum of individual
 * proof commitments, and that each individual proof is valid.
 *
 * @param totalCommitment - Expected total commitment (hex)
 * @param proofs - Individual balance proofs
 * @returns Verification result
 */
export declare function verifySolvencyProof(totalCommitment: string, proofs: BalanceProof[]): {
    valid: boolean;
};
