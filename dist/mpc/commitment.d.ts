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
declare function toHex(bytes: Uint8Array): string;
declare function fromHex(hex: string): Uint8Array;
declare function randomBytes(length: number): Uint8Array;
export interface PedersenCommitment {
    /** The commitment point C = g^v * h^r (hex, compressed) */
    commitment: Uint8Array;
    /** The opening: randomness r (32 bytes) */
    opening: Uint8Array;
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
export declare function commit(value: Uint8Array, randomness?: Uint8Array): PedersenCommitment;
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
export declare function verify(commitment: Uint8Array, value: Uint8Array, opening: Uint8Array): boolean;
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
export declare function hashCommit(data: Uint8Array, randomness?: Uint8Array): {
    commitment: Uint8Array;
    opening: Uint8Array;
};
/**
 * Verify a SHA-256 hash commitment.
 *
 * @param commitment - The commitment hash (32 bytes)
 * @param data - The revealed data
 * @param opening - The opening randomness
 * @returns true if H(data || opening) equals the commitment
 */
export declare function hashVerify(commitment: Uint8Array, data: Uint8Array, opening: Uint8Array): boolean;
/**
 * Simple SHA-256 hash of data (no randomness).
 * Used for deriving deterministic commitments and challenge hashes.
 */
export declare function hashCommitment(data: Uint8Array): Uint8Array;
/** Convert arbitrary bytes to a scalar mod n (secp256k1 order) */
declare function bytesToScalar(bytes: Uint8Array): bigint;
/** Reduce a bigint modulo secp256k1 curve order */
declare function modN(v: bigint): bigint;
/** Constant-time comparison of two Uint8Arrays */
declare function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean;
export { toHex, fromHex, randomBytes, bytesToScalar, modN, constantTimeEqual };
//# sourceMappingURL=commitment.d.ts.map