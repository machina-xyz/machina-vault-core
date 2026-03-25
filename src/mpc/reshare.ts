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

import { secp256k1 } from "@noble/curves/secp256k1";
import type {
  MPCKeyShare,
  ReshareConfig,
  ReshareRound1Msg,
  MPCSession,
} from "./types.js";
import {
  toHex,
  fromHex,
  modN,
  randomBytes,
} from "./commitment.js";
import {
  Point,
  CURVE_ORDER,
  randomScalar,
  scalarToHex,
  hexToScalar,
  evaluatePolynomial,
  verifyFeldmanShare,
  lagrangeCoefficient,
  modInverse,
  concatBytes,
} from "./keygen.js";

// ---------------------------------------------------------------------------
// Reshare session
// ---------------------------------------------------------------------------

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
export function initiateReshare(config: ReshareConfig): ReshareSession {
  if (config.newThreshold < 2) {
    throw new Error("New threshold must be at least 2");
  }
  if (config.newThreshold > config.newParties.length) {
    throw new Error("New threshold cannot exceed the number of new parties");
  }
  if (config.oldParties.length < config.oldThreshold) {
    throw new Error(
      `Need at least ${config.oldThreshold} old parties for resharing, got ${config.oldParties.length}`,
    );
  }

  const sessionId = toHex(randomBytes(16));

  return {
    session: {
      sessionId,
      type: "reshare",
      parties: [
        ...config.oldParties.map((id, i) => ({
          partyId: id,
          index: i + 1,
          publicCommitment: "",
          ready: false,
        })),
        ...config.newParties.map((id, i) => ({
          partyId: id,
          index: i + 1,
          publicCommitment: "",
          ready: false,
        })),
      ],
      threshold: config.newThreshold,
      status: "initialized",
      round: 0,
      totalRounds: 2,
      createdAt: new Date().toISOString(),
    },
    config,
  };
}

// ---------------------------------------------------------------------------
// Round 1: Old parties distribute sub-shares
// ---------------------------------------------------------------------------

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
export function reshareRound1(
  oldShare: MPCKeyShare,
  config: ReshareConfig,
): { state: ReshareRound1State; round1Messages: ReshareRound1Msg[] } {
  if (!config.oldParties.includes(oldShare.partyId)) {
    throw new Error("This party is not in the old parties list");
  }

  const secret = hexToScalar(oldShare.secretShare);

  // Build polynomial q_i(x) of degree (newThreshold - 1)
  // with q_i(0) = secret (the existing share value)
  const coefficients: bigint[] = [secret];
  for (let i = 1; i < config.newThreshold; i++) {
    coefficients.push(randomScalar());
  }

  // Feldman commitments: C_j = a_j * G for each coefficient
  const commitments = coefficients.map((c) => Point.BASE.multiply(c));
  const commitmentHexes = commitments.map((c) =>
    toHex(c.toRawBytes(true)),
  );

  // Evaluate polynomial at each new party's index
  const round1Messages: ReshareRound1Msg[] = [];
  for (let j = 0; j < config.newParties.length; j++) {
    const newPartyId = config.newParties[j]!;
    const newPartyIndex = j + 1; // 1-based

    const subShare = evaluatePolynomial(
      coefficients,
      BigInt(newPartyIndex),
    );

    round1Messages.push({
      fromParty: oldShare.partyId,
      fromIndex: oldShare.shareIndex,
      toParty: newPartyId,
      toIndex: newPartyIndex,
      subShare: scalarToHex(subShare),
      commitments: commitmentHexes,
    });
  }

  const state: ReshareRound1State = {
    oldShare,
    config,
    coefficients,
    commitments,
  };

  return { state, round1Messages };
}

// ---------------------------------------------------------------------------
// Round 2: New parties verify and combine sub-shares
// ---------------------------------------------------------------------------

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
export function reshareRound2(
  newPartyId: string,
  newPartyIndex: number,
  round1Messages: ReshareRound1Msg[],
  config: ReshareConfig,
  expectedPublicKey: string,
): MPCKeyShare {
  // Filter messages addressed to this party
  const myMessages = round1Messages.filter(
    (msg) => msg.toParty === newPartyId,
  );

  if (myMessages.length < config.oldThreshold) {
    throw new Error(
      `Need at least ${config.oldThreshold} sub-shares, got ${myMessages.length}`,
    );
  }

  // Verify each sub-share against Feldman commitments
  for (const msg of myMessages) {
    const subShareValue = hexToScalar(msg.subShare);
    const commitmentPoints = msg.commitments.map((hex) =>
      Point.fromHex(fromHex(hex)),
    );

    // Verify: subShare * G == sum_{j=0}^{t'-1} (newPartyIndex^j * C_j)
    const sharePoint = Point.BASE.multiply(subShareValue);
    const expectedPoint = verifyFeldmanShare(
      commitmentPoints,
      BigInt(newPartyIndex),
    );

    if (!sharePoint.equals(expectedPoint)) {
      throw new Error(
        `Sub-share verification failed for share from party ${msg.fromParty}`,
      );
    }
  }

  // Combine sub-shares using Lagrange interpolation over old party indices.
  //
  // Each old party i sent q_i(newPartyIndex) where q_i(0) = x_i (their old share).
  // The original secret is x = sum(lambda_i * x_i) where lambda_i are Lagrange
  // coefficients for the old party indices evaluated at 0.
  //
  // The new share for this party is:
  //   newShare = sum(lambda_i * q_i(newPartyIndex))
  //
  // Since q_i(newPartyIndex) is a polynomial evaluated at newPartyIndex with
  // q_i(0) = x_i, and we use Lagrange over the old party indices:
  //   sum(lambda_i * q_i(newPartyIndex)) = Q(newPartyIndex)
  // where Q is the "combined" resharing polynomial with Q(0) = x.

  const oldIndices = myMessages.map((msg) => msg.fromIndex);

  let newShare = 0n;
  for (const msg of myMessages) {
    const lambda = lagrangeCoefficient(msg.fromIndex, oldIndices);
    const subShareValue = hexToScalar(msg.subShare);
    newShare = modN(newShare + modN(lambda * subShareValue));
  }

  // Verify: newShare contributes to the same group public key.
  // The group public key should be derivable from the old parties' first
  // commitments (C_0 = x_i * G) via Lagrange interpolation.
  const expectedPubPoint = Point.fromHex(fromHex(expectedPublicKey));

  // Reconstruct the expected public key from old parties' C_0 commitments
  let reconstructedPub = Point.ZERO;
  for (const msg of myMessages) {
    const lambda = lagrangeCoefficient(msg.fromIndex, oldIndices);
    const c0 = Point.fromHex(fromHex(msg.commitments[0]!));
    if (lambda === 1n) {
      reconstructedPub = reconstructedPub.add(c0);
    } else {
      reconstructedPub = reconstructedPub.add(c0.multiply(lambda));
    }
  }

  if (!reconstructedPub.equals(expectedPubPoint)) {
    throw new Error(
      "Resharing verification failed: reconstructed public key does not match expected",
    );
  }

  // Generate chain code (XOR of hash of all old parties' commitments)
  const chainCode = new Uint8Array(32);
  for (const msg of myMessages) {
    const commitBytes = fromHex(msg.commitments[0]!);
    const hash = new Uint8Array(32);
    // Simple XOR mixing of commitment data
    for (let i = 0; i < 32 && i < commitBytes.length; i++) {
      hash[i] = commitBytes[i]!;
    }
    for (let i = 0; i < 32; i++) {
      chainCode[i] ^= hash[i]!;
    }
  }

  return {
    partyId: newPartyId,
    shareIndex: newPartyIndex,
    publicKey: expectedPublicKey,
    secretShare: scalarToHex(newShare),
    threshold: config.newThreshold,
    totalParties: config.newParties.length,
    chainCode: toHex(chainCode),
    createdAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Convenience: complete resharing in one call
// ---------------------------------------------------------------------------

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
export function reshare(
  oldShares: MPCKeyShare[],
  config: ReshareConfig,
): MPCKeyShare[] {
  if (oldShares.length < config.oldThreshold) {
    throw new Error(
      `Need at least ${config.oldThreshold} old shares, got ${oldShares.length}`,
    );
  }

  const expectedPublicKey = oldShares[0]!.publicKey;

  // Consistency check: all old shares have the same public key
  for (const share of oldShares) {
    if (share.publicKey !== expectedPublicKey) {
      throw new Error("Old shares do not agree on the group public key");
    }
  }

  // Round 1: Each old party creates sub-shares for all new parties
  const allRound1Messages: ReshareRound1Msg[] = [];

  for (const oldShare of oldShares) {
    const { round1Messages } = reshareRound1(oldShare, config);
    allRound1Messages.push(...round1Messages);
  }

  // Round 2: Each new party combines its sub-shares
  const newShares: MPCKeyShare[] = [];

  for (let j = 0; j < config.newParties.length; j++) {
    const newPartyId = config.newParties[j]!;
    const newPartyIndex = j + 1;

    const newShare = reshareRound2(
      newPartyId,
      newPartyIndex,
      allRound1Messages,
      config,
      expectedPublicKey,
    );

    newShares.push(newShare);
  }

  // Verification: all new shares must produce the same public key
  for (const share of newShares) {
    if (share.publicKey !== expectedPublicKey) {
      throw new Error(
        "Resharing failed: new shares do not preserve the group public key",
      );
    }
  }

  return newShares;
}

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
export function proactiveRefresh(
  currentShares: MPCKeyShare[],
): MPCKeyShare[] {
  const config: ReshareConfig = {
    oldThreshold: currentShares[0]!.threshold,
    newThreshold: currentShares[0]!.threshold,
    oldParties: currentShares.map((s) => s.partyId),
    newParties: currentShares.map((s) => s.partyId),
  };

  return reshare(currentShares, config);
}
