/**
 * MACHINA Vault — EVM address derivation from P-256 public key
 *
 * Algorithm: keccak256(x || y) -> take last 20 bytes -> EIP-55 checksum
 * Deterministic: same key always produces the same address.
 */
import { keccak_256 } from "@noble/hashes/sha3";
import { concatBuffers, bufferToHex } from "./utils.js";
/**
 * Derive an EVM vault address from raw P-256 public key coordinates.
 *
 * @param publicKeyX - 32-byte X coordinate of the P-256 public key
 * @param publicKeyY - 32-byte Y coordinate of the P-256 public key
 * @returns 0x-prefixed, EIP-55 checksummed EVM address
 */
export function deriveVaultAddress(publicKeyX, publicKeyY) {
    if (publicKeyX.length !== 32) {
        throw new Error(`Public key X coordinate must be 32 bytes, got ${publicKeyX.length}`);
    }
    if (publicKeyY.length !== 32) {
        throw new Error(`Public key Y coordinate must be 32 bytes, got ${publicKeyY.length}`);
    }
    // keccak256(x || y)
    const uncompressed = concatBuffers(publicKeyX, publicKeyY);
    const hash = keccak_256(uncompressed);
    // Take the last 20 bytes as the address
    const addressBytes = hash.slice(hash.length - 20);
    const rawAddress = bufferToHex(addressBytes);
    return toChecksumAddress(rawAddress);
}
/**
 * Apply EIP-55 mixed-case checksum to an Ethereum address.
 *
 * @param address - Lowercase hex address (with or without 0x prefix)
 * @returns 0x-prefixed checksummed address
 *
 * @see https://eips.ethereum.org/EIPS/eip-55
 */
export function toChecksumAddress(address) {
    const stripped = address.toLowerCase().replace(/^0x/, "");
    if (stripped.length !== 40) {
        throw new Error(`Invalid address length: expected 40 hex chars, got ${stripped.length}`);
    }
    // Hash the lowercase hex address (as ASCII bytes)
    const encoder = new TextEncoder();
    const hash = keccak_256(encoder.encode(stripped));
    const hashHex = bufferToHex(hash);
    let checksummed = "0x";
    for (let i = 0; i < 40; i++) {
        const char = stripped[i];
        // If the corresponding hex nibble of the hash is >= 8, uppercase
        const hashNibble = parseInt(hashHex[i], 16);
        checksummed += hashNibble >= 8 ? char.toUpperCase() : char;
    }
    return checksummed;
}
//# sourceMappingURL=derive-address.js.map