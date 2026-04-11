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
import { toHex, fromHex, modN, } from "./commitment.js";
import { hashCommit, hashVerify } from "./commitment.js";
import { lagrangeCoefficient, Point, CURVE_ORDER, randomScalar, scalarToHex, hexToScalar, } from "./keygen.js";
// ---------------------------------------------------------------------------
// Round 1: Generate nonce, create commitment
// ---------------------------------------------------------------------------
/**
 * Generate a secret nonce k_i, compute R_i = k_i * G, and create
 * a hash commitment H(R_i || randomness).
 */
export function signRound1(share, messageHex, participantIds) {
    if (participantIds.length < share.threshold) {
        throw new Error(`Need at least ${share.threshold} participants, got ${participantIds.length}`);
    }
    if (!participantIds.includes(share.partyId)) {
        throw new Error("This party is not in the participant list");
    }
    const messageHash = fromHex(messageHex);
    if (messageHash.length !== 32) {
        throw new Error("Message must be a 32-byte hash (64 hex chars)");
    }
    const nonce = randomScalar();
    const noncePublic = Point.BASE.multiply(nonce);
    const nonceBytes = noncePublic.toRawBytes(true);
    const { commitment, opening } = hashCommit(nonceBytes);
    const state = {
        share,
        messageHash,
        nonce,
        noncePublic,
        commitmentOpening: opening,
        participantIndices: [], // populated in round 2
    };
    const round1Msg = {
        fromParty: share.partyId,
        fromIndex: share.shareIndex,
        commitment: toHex(commitment),
    };
    return { state, round1Msg };
}
// ---------------------------------------------------------------------------
// Round 2: Reveal nonce point
// ---------------------------------------------------------------------------
/**
 * After receiving all commitments, reveal our nonce point R_i
 * and store the participant indices for Lagrange interpolation.
 */
export function signRound2(state, round1Messages) {
    const participantIndices = round1Messages.map((msg) => msg.fromIndex);
    const round2State = {
        ...state,
        participantIndices,
        round1Messages,
    };
    const round2Msg = {
        fromParty: state.share.partyId,
        fromIndex: state.share.shareIndex,
        noncePublic: toHex(state.noncePublic.toRawBytes(true)),
        opening: toHex(state.commitmentOpening),
    };
    return { state: round2State, round2Msg };
}
// ---------------------------------------------------------------------------
// Round 3: Verify nonces, produce partial signature
// ---------------------------------------------------------------------------
/**
 * Verify all revealed nonces against commitments, compute the combined
 * nonce point R, and produce a partial signature containing both
 * the nonce share k_i and the Lagrange-weighted secret share lambda_i * x_i.
 *
 * The partialSignature field encodes: k_i (64 hex) || lambda_i*x_i (64 hex).
 */
export function signRound3(state, round2Messages) {
    if (round2Messages.length !== state.round1Messages.length) {
        throw new Error(`Mismatch: ${state.round1Messages.length} round 1 msgs vs ${round2Messages.length} round 2 msgs`);
    }
    // Verify each revealed nonce against its round 1 commitment
    for (const r2Msg of round2Messages) {
        const r1Msg = state.round1Messages.find((m) => m.fromParty === r2Msg.fromParty);
        if (!r1Msg) {
            throw new Error(`No round 1 message for party ${r2Msg.fromParty}`);
        }
        const nonceBytes = fromHex(r2Msg.noncePublic);
        const opening = fromHex(r2Msg.opening);
        const commitment = fromHex(r1Msg.commitment);
        if (!hashVerify(commitment, nonceBytes, opening)) {
            throw new Error(`Nonce commitment verification failed for party ${r2Msg.fromParty}`);
        }
    }
    // Compute combined nonce point R = sum(R_i)
    let combinedR = Point.ZERO;
    for (const msg of round2Messages) {
        const Ri = Point.fromHex(fromHex(msg.noncePublic));
        combinedR = combinedR.add(Ri);
    }
    const rAffine = combinedR.toAffine();
    const r = modN(rAffine.x);
    if (r === 0n) {
        throw new Error("Degenerate nonce: r = 0, must restart signing");
    }
    // Compute Lagrange-weighted secret share
    const lambda = lagrangeCoefficient(state.share.shareIndex, state.participantIndices);
    const xi = hexToScalar(state.share.secretShare);
    const weightedShare = modN(lambda * xi);
    // Encode both nonce and weighted share into the partial signature
    const partialSig = scalarToHex(state.nonce) + scalarToHex(weightedShare);
    const round3State = {
        ...state,
        round2Messages,
        combinedR,
    };
    const round3Msg = {
        fromParty: state.share.partyId,
        fromIndex: state.share.shareIndex,
        partialSignature: partialSig,
    };
    return { state: round3State, round3Msg };
}
// ---------------------------------------------------------------------------
// Round 4: Combine into ECDSA signature (TEE combiner)
// ---------------------------------------------------------------------------
/**
 * Combine all partial signatures into a valid ECDSA signature.
 * Executed by the TEE combiner which receives all parties' nonce
 * shares and weighted secret shares.
 *
 * Reconstructs k = sum(k_i) and x = sum(lambda_i * x_i), then
 * computes s = k^{-1} * (e + r * x) mod n.
 */
export function signRound4(state, round3Messages) {
    const rAffine = state.combinedR.toAffine();
    const r = modN(rAffine.x);
    // e = message hash interpreted as big-endian scalar
    let e = 0n;
    for (let i = 0; i < state.messageHash.length; i++) {
        e = (e << 8n) | BigInt(state.messageHash[i]);
    }
    e = modN(e);
    // Reconstruct k and x from partial signatures
    let combinedK = 0n;
    let combinedX = 0n;
    for (const msg of round3Messages) {
        const hex = msg.partialSignature;
        if (hex.length !== 128) {
            throw new Error(`Invalid partial signature length from party ${msg.fromParty}: expected 128 hex chars, got ${hex.length}`);
        }
        const ki = hexToScalar(hex.slice(0, 64));
        const weightedShare = hexToScalar(hex.slice(64, 128));
        combinedK = modN(combinedK + ki);
        combinedX = modN(combinedX + weightedShare);
    }
    // Standard ECDSA: s = k^{-1} * (e + r * x) mod n
    const kInv = modInverse(combinedK, CURVE_ORDER);
    const s = modN(kInv * modN(e + modN(r * combinedX)));
    if (s === 0n) {
        throw new Error("Degenerate signature: s = 0, must restart signing");
    }
    // Normalize to low-S form (required by EVM / BIP-62)
    const halfOrder = CURVE_ORDER >> 1n;
    const finalS = s > halfOrder ? CURVE_ORDER - s : s;
    // Compute recovery ID
    const isYOdd = rAffine.y % 2n !== 0n;
    let recoveryId = isYOdd ? 1 : 0;
    if (s !== finalS) {
        recoveryId ^= 1;
    }
    // DER encode
    const rBytes = bigintToBytes(r, 32);
    const sBytes = bigintToBytes(finalS, 32);
    const derSig = encodeDER(rBytes, sBytes);
    const result = {
        signature: toHex(derSig),
        recoveryId,
        publicKey: state.share.publicKey,
        parties: round3Messages.map((m) => m.fromParty),
    };
    const round4Msg = {
        combinedR: toHex(state.combinedR.toRawBytes(true)),
        combinedS: scalarToHex(finalS),
        recoveryId,
    };
    return { result, round4Msg };
}
// ---------------------------------------------------------------------------
// Convenience: full threshold signing in one call
// ---------------------------------------------------------------------------
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
export function thresholdSign(shares, messageHex) {
    if (shares.length < shares[0].threshold) {
        throw new Error(`Need at least ${shares[0].threshold} shares, got ${shares.length}`);
    }
    const participantIds = shares.map((s) => s.partyId);
    // Round 1
    const round1Results = shares.map((share) => signRound1(share, messageHex, participantIds));
    const round1Messages = round1Results.map((r) => r.round1Msg);
    // Round 2
    const round2Results = round1Results.map((r) => signRound2(r.state, round1Messages));
    const round2Messages = round2Results.map((r) => r.round2Msg);
    // Round 3
    const round3Results = round2Results.map((r) => signRound3(r.state, round2Messages));
    const round3Messages = round3Results.map((r) => r.round3Msg);
    // Round 4 (first party acts as combiner)
    const combinerState = round3Results[0].state;
    const { result } = signRound4(combinerState, round3Messages);
    // Verify the produced signature
    if (!verifySignature(messageHex, result.signature, result.publicKey)) {
        throw new Error("Signature verification failed after combining");
    }
    return result;
}
// ---------------------------------------------------------------------------
// ECDSA signature verification
// ---------------------------------------------------------------------------
/**
 * Verify an ECDSA signature against a public key.
 *
 * @param messageHex - 32-byte message hash (hex)
 * @param signatureHex - DER-encoded signature (hex)
 * @param publicKeyHex - Compressed secp256k1 public key (hex)
 */
export function verifySignature(messageHex, signatureHex, publicKeyHex) {
    try {
        const sigBytes = fromHex(signatureHex);
        const { r, s } = decodeDER(sigBytes);
        const pubKey = Point.fromHex(fromHex(publicKeyHex));
        const msgBytes = fromHex(messageHex);
        let e = 0n;
        for (let i = 0; i < msgBytes.length; i++) {
            e = (e << 8n) | BigInt(msgBytes[i]);
        }
        e = modN(e);
        if (r === 0n || s === 0n)
            return false;
        if (r >= CURVE_ORDER || s >= CURVE_ORDER)
            return false;
        const sInv = modInverse(s, CURVE_ORDER);
        const u1 = modN(e * sInv);
        const u2 = modN(r * sInv);
        const R = Point.BASE.multiply(u1).add(pubKey.multiply(u2));
        if (R.equals(Point.ZERO))
            return false;
        return modN(R.toAffine().x) === r;
    }
    catch {
        return false;
    }
}
// ---------------------------------------------------------------------------
// DER encoding / decoding
// ---------------------------------------------------------------------------
function encodeDER(r, s) {
    const rTrimmed = trimLeadingZeros(r);
    const sTrimmed = trimLeadingZeros(s);
    // Pad with 0x00 if high bit is set (DER signed integer encoding)
    const rFinal = rTrimmed[0] >= 0x80 ? new Uint8Array([0, ...rTrimmed]) : rTrimmed;
    const sFinal = sTrimmed[0] >= 0x80 ? new Uint8Array([0, ...sTrimmed]) : sTrimmed;
    const totalLen = 2 + rFinal.length + 2 + sFinal.length;
    const der = new Uint8Array(2 + totalLen);
    let offset = 0;
    der[offset++] = 0x30; // SEQUENCE
    der[offset++] = totalLen;
    der[offset++] = 0x02; // INTEGER (r)
    der[offset++] = rFinal.length;
    der.set(rFinal, offset);
    offset += rFinal.length;
    der[offset++] = 0x02; // INTEGER (s)
    der[offset++] = sFinal.length;
    der.set(sFinal, offset);
    return der;
}
function decodeDER(der) {
    if (der[0] !== 0x30)
        throw new Error("Invalid DER: expected SEQUENCE");
    let offset = 2;
    if (der[offset] !== 0x02)
        throw new Error("Invalid DER: expected INTEGER for r");
    offset++;
    const rLen = der[offset];
    offset++;
    const rBytes = der.slice(offset, offset + rLen);
    offset += rLen;
    if (der[offset] !== 0x02)
        throw new Error("Invalid DER: expected INTEGER for s");
    offset++;
    const sLen = der[offset];
    offset++;
    const sBytes = der.slice(offset, offset + sLen);
    return { r: bytesToBigint(rBytes), s: bytesToBigint(sBytes) };
}
function trimLeadingZeros(bytes) {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) {
        start++;
    }
    return bytes.slice(start);
}
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function bigintToBytes(value, length) {
    const bytes = new Uint8Array(length);
    let v = value;
    for (let i = length - 1; i >= 0; i--) {
        bytes[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return bytes;
}
function bytesToBigint(bytes) {
    let value = 0n;
    for (let i = 0; i < bytes.length; i++) {
        value = (value << 8n) | BigInt(bytes[i]);
    }
    return value;
}
function modInverse(a, m) {
    a = ((a % m) + m) % m;
    if (a === 0n)
        throw new Error("No modular inverse for zero");
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    return ((old_s % m) + m) % m;
}
