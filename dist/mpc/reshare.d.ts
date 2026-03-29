/**
 * MACHINA Vault — Proactive Secret Resharing
 * MAC-901: DKLS23-based MPC threshold signing
 *
 * Implements a 2-round resharing protocol that allows the threshold (t)
 * and/or the set of shareholders to change without reconstructing or
 * exposing the secret key. The group public key remains unchanged.
 *
 * Protocol overview:
 *
 *   Round 1: Each old party creates a new random polynomial of degree
 *            (newThreshold - 1) with its existing share as the constant
 *            term, evaluates it at each new party's index, and sends
 *            the resulting sub-shares along with Feldman commitments.
 *
 *   Round 2: Each new party verifies received sub-shares against the
 *            Feldman commitments, then combines them using Lagrange
 *            interpolation (over the old party indices) to obtain its
 *            new share of the original secret.
 *
 * Invariant: the group public key P = x * G is preserved across reshares.
 *
 * Cloudflare Workers compatible — Web Crypto API + @noble/curves only.
 */
import type { MPCKeyShare, ReshareConfig, ReshareRound1Msg, MPCSession } from "./types.js";
import { Point } from "./keygen.js";
export interface ReshareSession {
    /** Session metadata */
    session: MPCSession;
    /** Resharing configuration */
    config: ReshareConfig;
}
/**
 * Create a new reshare session. This is the coordination object that
 * all parties reference during the resharing protocol.
 */
export declare function initiateReshare(config: ReshareConfig): ReshareSession;
export interface ReshareRound1State {
    /** The old party's existing key share */
    oldShare: MPCKeyShare;
    /** Resharing configuration */
    config: ReshareConfig;
    /** The resharing polynomial coefficients */
    coefficients: bigint[];
    /** Feldman commitments for the resharing polynomial */
    commitments: typeof Point.BASE[];
}
/**
 * Reshare round 1 (executed by each old party):
 *
 * Create a random polynomial q_i(x) of degree (newThreshold - 1) where
 * q_i(0) = oldShare.secretShare. This ensures the new shares, when
 * combined via Lagrange interpolation over old party indices, reconstruct
 * the same secret.
 *
 * Evaluate q_i(j) for each new party j and produce sub-share messages.
 *
 * @param oldShare - This old party's existing key share
 * @param config - Resharing configuration
 * @returns State and round 1 messages (one per new party)
 */
export declare function reshareRound1(oldShare: MPCKeyShare, config: ReshareConfig): {
    state: ReshareRound1State;
    round1Messages: ReshareRound1Msg[];
};
/**
 * Reshare round 2 (executed by each new party):
 *
 * 1. Verify each received sub-share against the sender's Feldman commitments.
 * 2. Combine sub-shares using Lagrange interpolation over the old party indices
 *    to produce this new party's share of the original secret.
 * 3. Verify that the resulting public key matches the original group public key.
 *
 * @param newPartyId - This new party's ID
 * @param newPartyIndex - This new party's 1-based index
 * @param round1Messages - All round 1 messages addressed to this new party
 * @param config - Resharing configuration
 * @param expectedPublicKey - The group public key (hex) that must be preserved
 * @returns The new key share for this party
 */
export declare function reshareRound2(newPartyId: string, newPartyIndex: number, round1Messages: ReshareRound1Msg[], config: ReshareConfig, expectedPublicKey: string): MPCKeyShare;
/**
 * Execute the full resharing protocol in a single call.
 *
 * Redistributes shares from old parties to new parties, optionally
 * changing the threshold and/or the party set. The group public key
 * is preserved.
 *
 * @param oldShares - Existing key shares (at least oldThreshold required)
 * @param config - Resharing configuration
 * @returns New key shares for all new parties
 */
export declare function reshare(oldShares: MPCKeyShare[], config: ReshareConfig): MPCKeyShare[];
/**
 * Rotate shares without changing threshold or parties.
 * Generates fresh shares for the same set of parties with the same threshold.
 * The old shares become invalid; the group public key is preserved.
 *
 * This should be called periodically (e.g., every epoch) to limit the
 * window during which a compromised share is useful to an attacker.
 *
 * @param currentShares - Current valid key shares
 * @returns New key shares (old ones should be securely deleted)
 */
export declare function proactiveRefresh(currentShares: MPCKeyShare[]): MPCKeyShare[];
//# sourceMappingURL=reshare.d.ts.map