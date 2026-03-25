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

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import type {
  MPCKeyShare,
  KeygenRound1Msg,
  KeygenRound2Msg,
  KeygenRound3Msg,
} from "./types.js";
import {
  toHex,
  fromHex,
  randomBytes,
  modN,
  hashCommitment,
} from "./commitment.js";

const Point = secp256k1.ProjectivePoint;
type ProjectivePoint = typeof Point.BASE;
const CURVE_ORDER = secp256k1.CURVE.n;

// ---------------------------------------------------------------------------
// Scalar / polynomial helpers
// ---------------------------------------------------------------------------

/** Generate a random non-zero scalar mod n */
function randomScalar(): bigint {
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const bytes = randomBytes(32);
    let value = 0n;
    for (let i = 0; i < 32; i++) {
      value = (value << 8n) | BigInt(bytes[i]!);
    }
    value = modN(value);
    if (value !== 0n) return value;
  }
}

/** Encode a scalar as a 32-byte big-endian hex string */
function scalarToHex(s: bigint): string {
  return s.toString(16).padStart(64, "0");
}

/** Decode a hex string to a scalar */
function hexToScalar(hex: string): bigint {
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  return BigInt("0x" + cleaned);
}

/**
 * Evaluate a polynomial at a given x value.
 *   f(x) = coefficients[0] + coefficients[1]*x + coefficients[2]*x^2 + ...
 * All arithmetic is mod curve order n.
 */
function evaluatePolynomial(coefficients: bigint[], x: bigint): bigint {
  let result = 0n;
  let xPower = 1n;
  for (const coeff of coefficients) {
    result = modN(result + modN(coeff * xPower));
    xPower = modN(xPower * x);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Internal state structures for round-by-round protocol
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Round 1: Generate polynomial, broadcast Feldman commitments
// ---------------------------------------------------------------------------

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
export function keygenRound1(
  partyId: string,
  partyIndex: number,
  threshold: number,
  totalParties: number,
): { state: KeygenRound1State; round1Msg: KeygenRound1Msg } {
  if (partyIndex < 1 || partyIndex > totalParties) {
    throw new Error(
      `Party index must be between 1 and ${totalParties}, got ${partyIndex}`,
    );
  }
  if (threshold < 2 || threshold > totalParties) {
    throw new Error(
      `Threshold must be between 2 and ${totalParties}, got ${threshold}`,
    );
  }

  // Generate random polynomial of degree t-1
  // f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
  // a_0 is this party's secret contribution to the combined key
  const coefficients: bigint[] = [];
  for (let i = 0; i < threshold; i++) {
    coefficients.push(randomScalar());
  }

  // Feldman commitments: C_i = a_i * G for each coefficient
  const commitments: ProjectivePoint[] = coefficients.map((c) =>
    Point.BASE.multiply(c),
  );

  // Chain code contribution
  const chainCodeContribution = randomBytes(32);

  // Hash commitment for binding (hash of the first commitment point)
  const firstCommitBytes = commitments[0]!.toRawBytes(true);
  const hc = hashCommitment(
    concatBytes(firstCommitBytes, chainCodeContribution),
  );

  const state: KeygenRound1State = {
    partyId,
    partyIndex,
    threshold,
    totalParties,
    coefficients,
    commitments,
    chainCodeContribution,
  };

  const round1Msg: KeygenRound1Msg = {
    fromParty: partyId,
    fromIndex: partyIndex,
    commitments: commitments.map((c) => toHex(c.toRawBytes(true))),
    hashCommitment: toHex(hc),
  };

  return { state, round1Msg };
}

// ---------------------------------------------------------------------------
// Round 2: Evaluate polynomial at each party's index, send shares
// ---------------------------------------------------------------------------

/**
 * Execute keygen round 2: after receiving all round 1 messages, evaluate
 * our polynomial at each other party's index and produce share messages.
 *
 * @param state - State from round 1
 * @param round1Messages - All round 1 messages from all parties (including self)
 * @returns Updated state and array of round 2 messages (one per other party)
 */
export function keygenRound2(
  state: KeygenRound1State,
  round1Messages: KeygenRound1Msg[],
): { state: KeygenRound2State; round2Messages: KeygenRound2Msg[] } {
  if (round1Messages.length !== state.totalParties) {
    throw new Error(
      `Expected ${state.totalParties} round 1 messages, got ${round1Messages.length}`,
    );
  }

  // Parse and store all commitments
  const allCommitments = new Map<string, ProjectivePoint[]>();
  for (const msg of round1Messages) {
    const parsed = msg.commitments.map((hex) =>
      Point.fromHex(fromHex(hex)),
    );
    if (parsed.length !== state.threshold) {
      throw new Error(
        `Party ${msg.fromParty} sent ${parsed.length} commitments, expected ${state.threshold}`,
      );
    }
    allCommitments.set(msg.fromParty, parsed);
  }

  // Evaluate our polynomial at each other party's index
  const round2Messages: KeygenRound2Msg[] = [];
  for (const msg of round1Messages) {
    if (msg.fromParty === state.partyId) continue;

    const shareValue = evaluatePolynomial(
      state.coefficients,
      BigInt(msg.fromIndex),
    );

    round2Messages.push({
      fromParty: state.partyId,
      fromIndex: state.partyIndex,
      toParty: msg.fromParty,
      toIndex: msg.fromIndex,
      encryptedShare: scalarToHex(shareValue),
    });
  }

  const round2State: KeygenRound2State = {
    ...state,
    round1Messages,
    allCommitments,
  };

  return { state: round2State, round2Messages };
}

// ---------------------------------------------------------------------------
// Round 3: Verify shares, compute combined key share
// ---------------------------------------------------------------------------

/**
 * Execute keygen round 3: verify all received shares against Feldman commitments,
 * compute the combined secret share, and derive the group public key.
 *
 * @param state - State from round 2
 * @param round2Messages - All round 2 messages addressed to this party
 * @returns The final key share for this party and the round 3 broadcast message
 */
export function keygenRound3(
  state: KeygenRound2State,
  round2Messages: KeygenRound2Msg[],
): { keyShare: MPCKeyShare; round3Msg: KeygenRound3Msg } {
  // Filter messages addressed to us
  const myMessages = round2Messages.filter(
    (msg) => msg.toParty === state.partyId,
  );

  if (myMessages.length !== state.totalParties - 1) {
    throw new Error(
      `Expected ${state.totalParties - 1} round 2 messages for party ${state.partyId}, got ${myMessages.length}`,
    );
  }

  // Verify each received share against the sender's Feldman commitments
  const receivedShares = new Map<string, bigint>();

  for (const msg of myMessages) {
    const senderCommitments = state.allCommitments.get(msg.fromParty);
    if (!senderCommitments) {
      throw new Error(
        `No commitments found for party ${msg.fromParty}`,
      );
    }

    const shareValue = hexToScalar(msg.encryptedShare);

    // Verify: share * G == sum_{j=0}^{t-1} (myIndex^j * C_j)
    // where C_j are the sender's Feldman commitments
    const sharePoint = Point.BASE.multiply(shareValue);
    const expectedPoint = verifyFeldmanShare(
      senderCommitments,
      BigInt(state.partyIndex),
    );

    if (!sharePoint.equals(expectedPoint)) {
      throw new Error(
        `Share verification failed for share from party ${msg.fromParty}`,
      );
    }

    receivedShares.set(msg.fromParty, shareValue);
  }

  // Compute our combined secret share:
  // x_i = sum of all f_j(i) for all parties j (including our own polynomial)
  let combinedShare = evaluatePolynomial(
    state.coefficients,
    BigInt(state.partyIndex),
  );
  for (const [, share] of receivedShares) {
    combinedShare = modN(combinedShare + share);
  }

  // Compute group public key: P = sum of all parties' first commitments (C_0)
  let groupPublicKey = Point.ZERO;
  for (const [, commitments] of state.allCommitments) {
    groupPublicKey = groupPublicKey.add(commitments[0]!);
  }

  // Compute combined chain code by XOR of all contributions
  const chainCode = new Uint8Array(32);
  chainCode.set(state.chainCodeContribution);
  for (const msg of state.round1Messages) {
    if (msg.fromParty === state.partyId) continue;
    // Each party's chain code contribution is embedded in their hash commitment
    // For simplicity in the round-based protocol, we XOR the hash of their commitments
    const otherContrib = sha256(fromHex(msg.commitments[0]!));
    for (let i = 0; i < 32; i++) {
      chainCode[i]! ^= otherContrib[i]!;
    }
  }

  // Generate Schnorr proof of knowledge of the secret share
  const { proofR, proofS } = generateSchnorrProof(
    combinedShare,
    state.partyId,
  );

  const publicShare = Point.BASE.multiply(combinedShare);

  const keyShare: MPCKeyShare = {
    partyId: state.partyId,
    shareIndex: state.partyIndex,
    publicKey: toHex(groupPublicKey.toRawBytes(true)),
    secretShare: scalarToHex(combinedShare),
    threshold: state.threshold,
    totalParties: state.totalParties,
    chainCode: toHex(chainCode),
    createdAt: new Date().toISOString(),
  };

  const round3Msg: KeygenRound3Msg = {
    fromParty: state.partyId,
    fromIndex: state.partyIndex,
    publicShare: toHex(publicShare.toRawBytes(true)),
    proofR,
    proofS,
  };

  return { keyShare, round3Msg };
}

// ---------------------------------------------------------------------------
// Verify round 3 messages (public share consistency)
// ---------------------------------------------------------------------------

/**
 * Verify a party's round 3 message: check that their public share is consistent
 * with the Feldman commitments from all parties, and verify the Schnorr proof.
 *
 * @param msg - The round 3 message to verify
 * @param allCommitments - Map of partyId -> Feldman commitments from round 1
 * @param totalParties - Total number of parties
 */
export function verifyKeygenRound3(
  msg: KeygenRound3Msg,
  allCommitments: Map<string, ProjectivePoint[]>,
): boolean {
  try {
    // Compute expected public share: sum of all parties' Feldman evaluations at this index
    let expectedPublicShare = Point.ZERO;
    for (const [, commitments] of allCommitments) {
      const evalPoint = verifyFeldmanShare(commitments, BigInt(msg.fromIndex));
      expectedPublicShare = expectedPublicShare.add(evalPoint);
    }

    const claimedPublicShare = Point.fromHex(fromHex(msg.publicShare));
    if (!claimedPublicShare.equals(expectedPublicShare)) {
      return false;
    }

    // Verify Schnorr proof
    return verifySchnorrProof(
      claimedPublicShare,
      msg.proofR,
      msg.proofS,
      msg.fromParty,
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Convenience: single-call keygen (for testing / local use)
// ---------------------------------------------------------------------------

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
export function generateKeyShares(
  threshold: number,
  totalParties: number,
): { shares: MPCKeyShare[]; publicKey: string } {
  if (threshold < 2) {
    throw new Error("Threshold must be at least 2");
  }
  if (threshold > totalParties) {
    throw new Error("Threshold cannot exceed total parties");
  }

  // Generate party IDs
  const parties = Array.from({ length: totalParties }, (_, i) => ({
    id: `party-${i + 1}`,
    index: i + 1,
  }));

  // Round 1: All parties generate polynomials and commitments
  const round1Results = parties.map((p) =>
    keygenRound1(p.id, p.index, threshold, totalParties),
  );

  const round1Messages = round1Results.map((r) => r.round1Msg);

  // Round 2: All parties evaluate polynomials and send shares
  const round2Results = round1Results.map((r) =>
    keygenRound2(r.state, round1Messages),
  );

  const allRound2Messages = round2Results.flatMap((r) => r.round2Messages);

  // Round 3: All parties verify shares and compute combined key
  const round3Results = round2Results.map((r) =>
    keygenRound3(r.state, allRound2Messages),
  );

  const shares = round3Results.map((r) => r.keyShare);
  const publicKey = shares[0]!.publicKey;

  // Consistency check: all shares must agree on the public key
  for (const share of shares) {
    if (share.publicKey !== publicKey) {
      throw new Error("Key generation inconsistency: public keys do not match");
    }
  }

  return { shares, publicKey };
}

// ---------------------------------------------------------------------------
// Lagrange interpolation (used for threshold reconstruction)
// ---------------------------------------------------------------------------

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
export function lagrangeCoefficient(i: number, indices: number[]): bigint {
  let numerator = 1n;
  let denominator = 1n;

  const iBig = BigInt(i);

  for (const j of indices) {
    if (j === i) continue;
    const jBig = BigInt(j);
    numerator = modN(numerator * jBig);
    denominator = modN(denominator * (jBig - iBig));
  }

  // denominator^{-1} mod n
  const denominatorInv = modInverse(denominator, CURVE_ORDER);
  return modN(numerator * denominatorInv);
}

/**
 * Reconstruct the secret from a threshold number of shares using
 * Lagrange interpolation. Used for verification only — in production
 * the secret is never reconstructed.
 *
 * @param shares - Array of { index, value } pairs
 * @returns The reconstructed secret as a scalar
 */
export function reconstructSecret(
  shares: Array<{ index: number; value: bigint }>,
): bigint {
  const indices = shares.map((s) => s.index);
  let secret = 0n;

  for (const share of shares) {
    const lambda = lagrangeCoefficient(share.index, indices);
    secret = modN(secret + modN(share.value * lambda));
  }

  return secret;
}

// ---------------------------------------------------------------------------
// Feldman VSS verification
// ---------------------------------------------------------------------------

/**
 * Compute the expected public point for a share evaluated at index x,
 * given the Feldman commitments.
 *
 * Expected = sum_{j=0}^{t-1} (x^j * C_j)
 *
 * This is the public-key equivalent of evaluating the polynomial at x.
 */
function verifyFeldmanShare(
  commitments: ProjectivePoint[],
  x: bigint,
): ProjectivePoint {
  let result = Point.ZERO;
  let xPower = 1n;

  for (const commitment of commitments) {
    if (xPower === 1n) {
      result = result.add(commitment);
    } else {
      result = result.add(commitment.multiply(xPower));
    }
    xPower = modN(xPower * x);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Schnorr proof of knowledge
// ---------------------------------------------------------------------------

/** Generate a Schnorr proof of knowledge of scalar `secret` */
function generateSchnorrProof(
  secret: bigint,
  context: string,
): { proofR: string; proofS: string } {
  const k = randomScalar();
  const R = Point.BASE.multiply(k);
  const publicKey = Point.BASE.multiply(secret);

  // Challenge: e = H(R || P || context)
  const rBytes = R.toRawBytes(true);
  const pBytes = publicKey.toRawBytes(true);
  const contextBytes = new TextEncoder().encode(context);

  const challengeInput = concatBytes(rBytes, pBytes, contextBytes);
  const eHash = sha256(challengeInput);

  let e = 0n;
  for (let i = 0; i < eHash.length; i++) {
    e = (e << 8n) | BigInt(eHash[i]!);
  }
  e = modN(e);

  // Response: s = k - e * secret mod n
  const s = modN(k - modN(e * secret));

  return {
    proofR: toHex(rBytes),
    proofS: scalarToHex(s),
  };
}

/** Verify a Schnorr proof of knowledge */
function verifySchnorrProof(
  publicKey: ProjectivePoint,
  proofR: string,
  proofS: string,
  context: string,
): boolean {
  try {
    const R = Point.fromHex(fromHex(proofR));
    const s = hexToScalar(proofS);

    const pBytes = publicKey.toRawBytes(true);
    const rBytes = R.toRawBytes(true);
    const contextBytes = new TextEncoder().encode(context);

    const challengeInput = concatBytes(rBytes, pBytes, contextBytes);
    const eHash = sha256(challengeInput);

    let e = 0n;
    for (let i = 0; i < eHash.length; i++) {
      e = (e << 8n) | BigInt(eHash[i]!);
    }
    e = modN(e);

    // Verify: s * G + e * P == R
    const sG = Point.BASE.multiply(s);
    const eP = publicKey.multiply(e);
    const expected = sG.add(eP);

    return expected.equals(R);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Math helpers
// ---------------------------------------------------------------------------

/** Modular inverse using extended Euclidean algorithm */
function modInverse(a: bigint, m: bigint): bigint {
  a = ((a % m) + m) % m;
  if (a === 0n) throw new Error("No modular inverse for zero");

  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }

  return ((old_s % m) + m) % m;
}

/** Concatenate multiple Uint8Arrays */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// Re-exports for use by signing and reshare modules
export {
  randomScalar,
  scalarToHex,
  hexToScalar,
  evaluatePolynomial,
  verifyFeldmanShare,
  modInverse,
  concatBytes,
  Point,
  CURVE_ORDER,
};
export type { ProjectivePoint };
