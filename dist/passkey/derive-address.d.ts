/**
 * MACHINA Vault — EVM address derivation from P-256 public key
 *
 * Algorithm: keccak256(x || y) -> take last 20 bytes -> EIP-55 checksum
 * Deterministic: same key always produces the same address.
 */
/**
 * Derive an EVM vault address from raw P-256 public key coordinates.
 *
 * @param publicKeyX - 32-byte X coordinate of the P-256 public key
 * @param publicKeyY - 32-byte Y coordinate of the P-256 public key
 * @returns 0x-prefixed, EIP-55 checksummed EVM address
 */
export declare function deriveVaultAddress(publicKeyX: Uint8Array, publicKeyY: Uint8Array): string;
/**
 * Apply EIP-55 mixed-case checksum to an Ethereum address.
 *
 * @param address - Lowercase hex address (with or without 0x prefix)
 * @returns 0x-prefixed checksummed address
 *
 * @see https://eips.ethereum.org/EIPS/eip-55
 */
export declare function toChecksumAddress(address: string): string;
//# sourceMappingURL=derive-address.d.ts.map