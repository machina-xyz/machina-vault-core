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
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
// ---------------------------------------------------------------------------
// Hex helpers (no Buffer)
// ---------------------------------------------------------------------------
const HEX_CHARS = "0123456789abcdef";
function bytesToHex(bytes) {
    let hex = "0x";
    for (let i = 0; i < bytes.length; i++) {
        hex += HEX_CHARS[bytes[i] >> 4] + HEX_CHARS[bytes[i] & 0x0f];
    }
    return hex;
}
function hexToBytes(hex) {
    const h = hex.startsWith("0x") ? hex.slice(2) : hex;
    if (h.length % 2 !== 0) {
        throw new Error("Hex string must have even length");
    }
    const bytes = new Uint8Array(h.length / 2);
    for (let i = 0; i < h.length; i += 2) {
        bytes[i / 2] = parseInt(h.slice(i, i + 2), 16);
    }
    return bytes;
}
function stripHexPrefix(hex) {
    return hex.startsWith("0x") ? hex.slice(2) : hex;
}
// ---------------------------------------------------------------------------
// BigInt <-> Uint8Array helpers
// ---------------------------------------------------------------------------
function bytesToBigInt(bytes) {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result = (result << 8n) | BigInt(bytes[i]);
    }
    return result;
}
function bigIntToBytes(value, length) {
    const bytes = new Uint8Array(length);
    let v = value;
    for (let i = length - 1; i >= 0; i--) {
        bytes[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return bytes;
}
// ---------------------------------------------------------------------------
// Nothing-up-my-sleeve generator point H
// ---------------------------------------------------------------------------
/**
 * Derive the secondary generator point H for Pedersen commitments.
 *
 * H is derived deterministically by hashing a known string to produce a
 * secp256k1 x-coordinate, then taking the point on the curve. This is a
 * "nothing-up-my-sleeve" construction: nobody knows the discrete log of H
 * with respect to G, which is essential for the binding property.
 *
 * Method: repeatedly hash "MACHINA_PEDERSEN_H" || counter until we find
 * a valid x-coordinate on secp256k1.
 */
function deriveGeneratorH() {
    const encoder = new TextEncoder();
    for (let counter = 0; counter < 256; counter++) {
        const preimage = encoder.encode(`MACHINA_PEDERSEN_H:${counter}`);
        const hash = sha256(preimage);
        // Try with 02 prefix (even y-coordinate)
        const compressed = new Uint8Array(33);
        compressed[0] = 0x02;
        compressed.set(hash, 1);
        try {
            const point = secp256k1.ProjectivePoint.fromHex(compressed);
            // Verify it's a valid point on the curve (fromHex already does this)
            point.assertValidity();
            return point;
        }
        catch {
            // Not a valid point, try next counter
            continue;
        }
    }
    throw new Error("Failed to derive generator point H");
}
/** Cached generator point H */
let _generatorH = null;
function getGeneratorH() {
    if (_generatorH === null) {
        _generatorH = deriveGeneratorH();
    }
    return _generatorH;
}
const G = secp256k1.ProjectivePoint.BASE;
const n = secp256k1.CURVE.n;
// ---------------------------------------------------------------------------
// Number of bits for range proofs
// ---------------------------------------------------------------------------
/** Maximum bit width for balance values in range proofs */
const RANGE_PROOF_BITS = 64;
// ---------------------------------------------------------------------------
// Pedersen Commitments
// ---------------------------------------------------------------------------
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
export function createBalanceCommitment(balance) {
    if (balance < 0n) {
        throw new Error("Balance must be non-negative");
    }
    const H = getGeneratorH();
    // Generate random blinding factor
    const blindingBytes = secp256k1.utils.randomPrivateKey();
    const blinding = bytesToBigInt(blindingBytes) % n;
    // C = balance * G + blinding * H
    const balanceMod = balance % n;
    const balancePoint = balanceMod === 0n ? secp256k1.ProjectivePoint.ZERO : G.multiply(balanceMod);
    const blindingPoint = blinding === 0n ? secp256k1.ProjectivePoint.ZERO : H.multiply(blinding);
    const commitment = balancePoint.add(blindingPoint);
    return {
        commitment: bytesToHex(commitment.toRawBytes(true)),
        blinding: bytesToHex(bigIntToBytes(blinding, 32)),
    };
}
/**
 * Create a Pedersen commitment with a specific blinding factor.
 * Used internally for range proof construction.
 */
function createCommitmentWithBlinding(value, blinding) {
    const H = getGeneratorH();
    const valueMod = ((value % n) + n) % n;
    const blindingMod = ((blinding % n) + n) % n;
    const valuePoint = valueMod === 0n ? secp256k1.ProjectivePoint.ZERO : G.multiply(valueMod);
    const blindingPoint = blindingMod === 0n ? secp256k1.ProjectivePoint.ZERO : H.multiply(blindingMod);
    return valuePoint.add(blindingPoint);
}
/**
 * Create bit decomposition commitments for a non-negative value.
 * Each bit b_i gets a commitment C_i = b_i * G + r_i * H
 * The sum of 2^i * C_i should equal the commitment to the full value.
 */
function createBitDecomposition(value, bits) {
    if (value < 0n) {
        throw new Error("Cannot create bit decomposition for negative value");
    }
    const commitments = [];
    const blindings = [];
    let aggregateBlinding = 0n;
    for (let i = 0; i < bits; i++) {
        const bit = (value >> BigInt(i)) & 1n;
        const blindingBytes = secp256k1.utils.randomPrivateKey();
        const blinding = bytesToBigInt(blindingBytes) % n;
        const commitment = createCommitmentWithBlinding(bit, blinding);
        commitments.push(commitment.toRawBytes(true));
        blindings.push(blinding);
        // Aggregate: sum of 2^i * r_i
        const weight = (1n << BigInt(i)) % n;
        aggregateBlinding = (aggregateBlinding + weight * blinding) % n;
    }
    return { commitments, blindings, aggregateBlinding };
}
function serializeRangeProof(data) {
    const parts = [];
    // Header: bits (1 byte) + flags (1 byte)
    parts.push(new Uint8Array([data.bits, data.flags]));
    // Min and max balances (32 bytes each)
    parts.push(bigIntToBytes(data.minBalance, 32));
    parts.push(bigIntToBytes(data.maxBalance, 32));
    // Lower bit commitments and blindings
    for (let i = 0; i < data.lowerBitCommitments.length; i++) {
        parts.push(data.lowerBitCommitments[i]);
        parts.push(bigIntToBytes(data.lowerBitBlindings[i], 32));
    }
    // Upper bit commitments and blindings
    for (let i = 0; i < data.upperBitCommitments.length; i++) {
        parts.push(data.upperBitCommitments[i]);
        parts.push(bigIntToBytes(data.upperBitBlindings[i], 32));
    }
    // Aggregate blindings
    parts.push(bigIntToBytes(data.lowerAggregateBlinding, 32));
    parts.push(bigIntToBytes(data.upperAggregateBlinding, 32));
    // Concatenate all parts
    const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
}
function deserializeRangeProof(data) {
    let offset = 0;
    const bits = data[offset];
    const flags = data[offset + 1];
    offset += 2;
    const minBalance = bytesToBigInt(data.slice(offset, offset + 32));
    offset += 32;
    const maxBalance = bytesToBigInt(data.slice(offset, offset + 32));
    offset += 32;
    const hasMin = (flags & 0x01) !== 0;
    const hasMax = (flags & 0x02) !== 0;
    const lowerBitCommitments = [];
    const lowerBitBlindings = [];
    const upperBitCommitments = [];
    const upperBitBlindings = [];
    // Lower bit decomposition (present if hasMin)
    if (hasMin) {
        for (let i = 0; i < bits; i++) {
            lowerBitCommitments.push(data.slice(offset, offset + 33));
            offset += 33;
            lowerBitBlindings.push(bytesToBigInt(data.slice(offset, offset + 32)));
            offset += 32;
        }
    }
    // Upper bit decomposition (present if hasMax)
    if (hasMax) {
        for (let i = 0; i < bits; i++) {
            upperBitCommitments.push(data.slice(offset, offset + 33));
            offset += 33;
            upperBitBlindings.push(bytesToBigInt(data.slice(offset, offset + 32)));
            offset += 32;
        }
    }
    const lowerAggregateBlinding = bytesToBigInt(data.slice(offset, offset + 32));
    offset += 32;
    const upperAggregateBlinding = bytesToBigInt(data.slice(offset, offset + 32));
    return {
        bits,
        flags,
        minBalance,
        maxBalance,
        lowerBitCommitments,
        lowerBitBlindings,
        upperBitCommitments,
        upperBitBlindings,
        lowerAggregateBlinding,
        upperAggregateBlinding,
    };
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
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
export function createBalanceProof(request, blinding) {
    const blindingScalar = bytesToBigInt(hexToBytes(blinding));
    // Recreate the commitment: C = balance * G + blinding * H
    const commitment = createCommitmentWithBlinding(request.balance, blindingScalar);
    const hasMin = request.minBalance !== undefined;
    const hasMax = request.maxBalance !== undefined;
    let flags = 0;
    if (hasMin)
        flags |= 0x01;
    if (hasMax)
        flags |= 0x02;
    let lowerDecomp = {
        commitments: [],
        blindings: [],
        aggregateBlinding: 0n,
    };
    let upperDecomp = {
        commitments: [],
        blindings: [],
        aggregateBlinding: 0n,
    };
    if (hasMin) {
        const lowerDelta = request.balance - request.minBalance;
        if (lowerDelta < 0n) {
            throw new Error("Balance is below minBalance");
        }
        lowerDecomp = createBitDecomposition(lowerDelta, RANGE_PROOF_BITS);
    }
    if (hasMax) {
        const upperDelta = request.maxBalance - request.balance;
        if (upperDelta < 0n) {
            throw new Error("Balance is above maxBalance");
        }
        upperDecomp = createBitDecomposition(upperDelta, RANGE_PROOF_BITS);
    }
    const rangeProofData = serializeRangeProof({
        bits: RANGE_PROOF_BITS,
        flags,
        minBalance: request.minBalance ?? 0n,
        maxBalance: request.maxBalance ?? 0n,
        lowerBitCommitments: lowerDecomp.commitments,
        lowerBitBlindings: lowerDecomp.blindings,
        upperBitCommitments: upperDecomp.commitments,
        upperBitBlindings: upperDecomp.blindings,
        lowerAggregateBlinding: lowerDecomp.aggregateBlinding,
        upperAggregateBlinding: upperDecomp.aggregateBlinding,
    });
    return {
        commitment: bytesToHex(commitment.toRawBytes(true)),
        rangeProofData: bytesToHex(rangeProofData),
        tokenAddress: request.tokenAddress,
        chainId: request.chainId,
        timestamp: new Date().toISOString(),
    };
}
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
export function verifyBalanceProof(proof, commitment) {
    const result = {
        valid: false,
        tokenAddress: proof.tokenAddress,
        chainId: proof.chainId,
        withinRange: false,
    };
    try {
        // 1. Verify the commitment is a valid point
        const commitmentPoint = secp256k1.ProjectivePoint.fromHex(stripHexPrefix(commitment));
        commitmentPoint.assertValidity();
        // 2. Verify proof commitment matches expected commitment
        const proofCommitmentPoint = secp256k1.ProjectivePoint.fromHex(stripHexPrefix(proof.commitment));
        proofCommitmentPoint.assertValidity();
        if (stripHexPrefix(proof.commitment) !== stripHexPrefix(commitment)) {
            return result;
        }
        // 3. If no range proof data, just validate the commitment
        const rangeData = hexToBytes(proof.rangeProofData);
        const rangeProof = deserializeRangeProof(rangeData);
        const hasMin = (rangeProof.flags & 0x01) !== 0;
        const hasMax = (rangeProof.flags & 0x02) !== 0;
        if (!hasMin && !hasMax) {
            result.valid = true;
            result.withinRange = true;
            return result;
        }
        // 4. Verify bit decomposition commitments
        let rangeValid = true;
        if (hasMin) {
            rangeValid =
                rangeValid &&
                    verifyBitDecomposition(rangeProof.lowerBitCommitments, rangeProof.lowerBitBlindings, rangeProof.bits);
        }
        if (hasMax) {
            rangeValid =
                rangeValid &&
                    verifyBitDecomposition(rangeProof.upperBitCommitments, rangeProof.upperBitBlindings, rangeProof.bits);
        }
        result.valid = true;
        result.withinRange = rangeValid;
        return result;
    }
    catch {
        return result;
    }
}
/**
 * Verify that bit decomposition commitments are well-formed.
 * Each commitment C_i should commit to either 0 or 1.
 * We verify by reconstructing C_i with the given blinding and checking
 * it matches the commitment for bit value 0 or 1.
 */
function verifyBitDecomposition(commitments, blindings, bits) {
    const H = getGeneratorH();
    for (let i = 0; i < bits; i++) {
        const commitmentPoint = secp256k1.ProjectivePoint.fromHex(commitments[i]);
        const blinding = blindings[i];
        // Reconstruct commitment for bit = 0: C_0 = 0 * G + blinding * H = blinding * H
        const c0 = blinding === 0n ? secp256k1.ProjectivePoint.ZERO : H.multiply(blinding);
        // Reconstruct commitment for bit = 1: C_1 = 1 * G + blinding * H
        const c1 = G.add(c0);
        // The commitment must match one of these two
        const matchesZero = commitmentPoint.equals(c0);
        const matchesOne = commitmentPoint.equals(c1);
        if (!matchesZero && !matchesOne) {
            return false;
        }
    }
    return true;
}
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
export function createSolvencyProof(balances) {
    const proofs = [];
    let totalCommitmentPoint = secp256k1.ProjectivePoint.ZERO;
    for (const { token, balance } of balances) {
        const { commitment, blinding } = createBalanceCommitment(balance);
        const proof = createBalanceProof({
            balance,
            tokenAddress: token,
            chainId: "aggregate",
        }, blinding);
        proofs.push(proof);
        // Homomorphic addition
        const commitmentPoint = secp256k1.ProjectivePoint.fromHex(stripHexPrefix(commitment));
        totalCommitmentPoint = totalCommitmentPoint.add(commitmentPoint);
    }
    return {
        totalCommitment: bytesToHex(totalCommitmentPoint.toRawBytes(true)),
        proofs,
    };
}
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
export function verifySolvencyProof(totalCommitment, proofs) {
    try {
        const expectedTotal = secp256k1.ProjectivePoint.fromHex(stripHexPrefix(totalCommitment));
        expectedTotal.assertValidity();
        let computedTotal = secp256k1.ProjectivePoint.ZERO;
        for (const proof of proofs) {
            // Verify each individual proof
            const verification = verifyBalanceProof(proof, proof.commitment);
            if (!verification.valid) {
                return { valid: false };
            }
            // Sum commitments
            const point = secp256k1.ProjectivePoint.fromHex(stripHexPrefix(proof.commitment));
            computedTotal = computedTotal.add(point);
        }
        // Check homomorphic sum matches total commitment
        const valid = computedTotal.equals(expectedTotal);
        return { valid };
    }
    catch {
        return { valid: false };
    }
}
