/**
 * MACHINA Vault — Pedersen Commitments for MPC protocols
 * MAC-901: Commitment scheme used in keygen and signing rounds
 *
 * Provides both:
 * 1. Pedersen commitments: C = g^v * h^r on secp256k1 (binding + hiding)
 * 2. Hash commitments: SHA-256 based (used for nonce commitments in signing)
 *
 * Cloudflare Workers compatible — Web Crypto API + @noble/curves only.
 */
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
const Point = secp256k1.ProjectivePoint;
// ---------------------------------------------------------------------------
// Hex utilities (no Buffer)
// ---------------------------------------------------------------------------
function toHex(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
}
function fromHex(hex) {
    const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
    const bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2) {
        bytes[i / 2] = parseInt(cleaned.slice(i, i + 2), 16);
    }
    return bytes;
}
// ---------------------------------------------------------------------------
// Nothing-up-my-sleeve second generator h for Pedersen commitments
// ---------------------------------------------------------------------------
/**
 * Derive a second generator point h = HashToCurve("MACHINA_PEDERSEN_H_V1")
 * using the hash-and-increment method on secp256k1.
 *
 * This is a deterministic, publicly verifiable nothing-up-my-sleeve point
 * whose discrete log relative to g is unknown.
 */
function deriveGeneratorH() {
    const tag = new TextEncoder().encode("MACHINA_PEDERSEN_H_V1");
    let counter = 0;
    // eslint-disable-next-line no-constant-condition
    while (true) {
        const counterBytes = new Uint8Array(4);
        counterBytes[0] = (counter >> 24) & 0xff;
        counterBytes[1] = (counter >> 16) & 0xff;
        counterBytes[2] = (counter >> 8) & 0xff;
        counterBytes[3] = counter & 0xff;
        const preimage = new Uint8Array(tag.length + 4);
        preimage.set(tag);
        preimage.set(counterBytes, tag.length);
        const hash = sha256(preimage);
        // Attempt to interpret the hash as an x-coordinate with 02 prefix
        const compressed = new Uint8Array(33);
        compressed[0] = 0x02;
        compressed.set(hash, 1);
        try {
            const point = Point.fromHex(compressed);
            // Ensure the point is not the identity
            if (!point.equals(Point.ZERO)) {
                return point;
            }
        }
        catch {
            // Not a valid x-coordinate, try next counter
        }
        counter++;
    }
}
/** Cached second generator */
let _generatorH = null;
function getGeneratorH() {
    if (_generatorH === null) {
        _generatorH = deriveGeneratorH();
    }
    return _generatorH;
}
// ---------------------------------------------------------------------------
// Random bytes (Web Crypto API)
// ---------------------------------------------------------------------------
function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
}
/**
 * Create a Pedersen commitment to a value.
 *
 * C = v * G + r * H
 *
 * where G is the secp256k1 generator, H is the nothing-up-my-sleeve point,
 * v is the value interpreted as a scalar, and r is the randomness.
 *
 * @param value - The value to commit to (arbitrary bytes, will be reduced mod n)
 * @param randomness - Optional explicit randomness (32 bytes). Generated if omitted.
 * @returns The commitment and opening (randomness).
 */
export function commit(value, randomness) {
    const r = randomness ?? randomBytes(32);
    if (r.length !== 32) {
        throw new Error("Randomness must be exactly 32 bytes");
    }
    const h = getGeneratorH();
    // Reduce value to a scalar mod n
    const vScalar = bytesToScalar(value);
    const rScalar = bytesToScalar(r);
    // C = v * G + r * H
    const vG = Point.BASE.multiply(vScalar);
    const rH = h.multiply(rScalar);
    const commitmentPoint = vG.add(rH);
    return {
        commitment: commitmentPoint.toRawBytes(true),
        opening: r,
    };
}
/**
 * Verify a Pedersen commitment.
 *
 * Checks that commitment == v * G + r * H.
 *
 * @param commitment - The commitment bytes (compressed point)
 * @param value - The claimed value
 * @param opening - The opening randomness
 * @returns true if the commitment is valid
 */
export function verify(commitment, value, opening) {
    try {
        const h = getGeneratorH();
        const vScalar = bytesToScalar(value);
        const rScalar = bytesToScalar(opening);
        const vG = Point.BASE.multiply(vScalar);
        const rH = h.multiply(rScalar);
        const expected = vG.add(rH);
        const actual = Point.fromHex(commitment);
        return actual.equals(expected);
    }
    catch {
        return false;
    }
}
// ---------------------------------------------------------------------------
// Hash commitment (SHA-256 based, simpler scheme for signing nonces)
// ---------------------------------------------------------------------------
/**
 * Create a SHA-256 hash commitment.
 *
 * H(data || randomness)
 *
 * Used in signing protocols where we need a simple commit-reveal scheme
 * for nonce commitments (not requiring the homomorphic properties of
 * Pedersen commitments).
 *
 * @param data - Data to commit to
 * @param randomness - Optional explicit randomness (32 bytes)
 * @returns Object with commitment hash and opening (randomness)
 */
export function hashCommit(data, randomness) {
    const r = randomness ?? randomBytes(32);
    const preimage = new Uint8Array(data.length + r.length);
    preimage.set(data);
    preimage.set(r, data.length);
    return {
        commitment: sha256(preimage),
        opening: r,
    };
}
/**
 * Verify a SHA-256 hash commitment.
 *
 * @param commitment - The commitment hash (32 bytes)
 * @param data - The revealed data
 * @param opening - The opening randomness
 * @returns true if H(data || opening) equals the commitment
 */
export function hashVerify(commitment, data, opening) {
    const preimage = new Uint8Array(data.length + opening.length);
    preimage.set(data);
    preimage.set(opening, data.length);
    const expected = sha256(preimage);
    return constantTimeEqual(commitment, expected);
}
/**
 * Simple SHA-256 hash of data (no randomness).
 * Used for deriving deterministic commitments and challenge hashes.
 */
export function hashCommitment(data) {
    return sha256(data);
}
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
/** Convert arbitrary bytes to a scalar mod n (secp256k1 order) */
function bytesToScalar(bytes) {
    // Interpret bytes as big-endian unsigned integer
    let value = 0n;
    for (let i = 0; i < bytes.length; i++) {
        value = (value << 8n) | BigInt(bytes[i]);
    }
    // Reduce mod n
    return modN(value);
}
/** Reduce a bigint modulo secp256k1 curve order */
function modN(v) {
    const n = secp256k1.CURVE.n;
    const result = ((v % n) + n) % n;
    return result;
}
/** Constant-time comparison of two Uint8Arrays */
function constantTimeEqual(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}
// Re-export hex helpers for use by other MPC modules
export { toHex, fromHex, randomBytes, bytesToScalar, modN, constantTimeEqual };
