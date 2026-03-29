/**
 * MACHINA Vault — ERC-5564 Stealth Addresses
 * MAC-903: Stealth Addresses using secp256k1 ECDH
 *
 * Implements the ERC-5564 stealth address standard:
 * - Sender generates ephemeral key, derives one-time stealth address
 * - Recipient scans announcements using viewing key (view tag optimisation)
 * - Recipient computes spending private key for matched addresses
 *
 * All EC operations use @noble/curves/secp256k1.
 * Cloudflare Workers V8 compatible — no Node.js APIs.
 */
import type { StealthMetaAddress, StealthAddress, StealthKeyPair, AnnouncementLog } from "./types.js";
/**
 * Generate a stealth key pair: spending key (s) and viewing key (v).
 *
 * - Spending key controls funds at stealth addresses
 * - Viewing key can be shared with scanning services for privacy-preserving
 *   detection of incoming payments
 */
export declare function generateStealthKeyPair(): StealthKeyPair;
/**
 * Compute the stealth meta-address from a key pair.
 * Encoded as: st:eth:0x<spendingPubKey><viewingPubKey>
 */
export declare function computeStealthMetaAddress(keyPair: StealthKeyPair): StealthMetaAddress;
/**
 * Encode a stealth meta-address to the canonical string format.
 * Format: st:eth:0x<spendingPubKey><viewingPubKey>
 */
export declare function encodeStealthMetaAddress(meta: StealthMetaAddress): string;
/**
 * Parse a stealth meta-address from the canonical string format.
 * Expected format: st:eth:0x<66-char spending><66-char viewing>
 */
export declare function parseStealthMetaAddress(encoded: string): StealthMetaAddress;
/**
 * Generate a stealth address for a recipient given their meta-address.
 *
 * ERC-5564 protocol:
 * 1. Generate random ephemeral key r, compute R = r * G
 * 2. Compute shared secret: S_shared = r * V (ECDH with viewing public key)
 * 3. Compute view tag: first byte of SHA-256(S_shared)
 * 4. Compute stealth public key: P_stealth = S + SHA-256(S_shared) * G
 * 5. Derive Ethereum address from P_stealth
 */
export declare function generateStealthAddress(metaAddress: StealthMetaAddress): StealthAddress;
/**
 * Check whether a stealth address announcement belongs to this wallet.
 * Uses the view tag for fast scanning (avoids full derivation for non-matches).
 *
 * @param announcement - On-chain announcement log entry
 * @param viewingKey - Recipient's viewing private key (hex)
 * @returns true if the view tag matches (likely belongs to this wallet)
 */
export declare function checkStealthAddress(announcement: AnnouncementLog, viewingKey: string): boolean;
/**
 * Compute the private key that controls a stealth address.
 *
 * Used after confirming an announcement belongs to this wallet:
 *   stealth_private_key = s + SHA-256(v * R) mod n
 *
 * @param spendingKey - Spending private key (hex)
 * @param viewingKey - Viewing private key (hex)
 * @param ephemeralPubKey - Ephemeral public key R from announcement (hex)
 * @returns Stealth private key (hex)
 */
export declare function computeStealthPrivateKey(spendingKey: string, viewingKey: string, ephemeralPubKey: string): string;
//# sourceMappingURL=stealth-address.d.ts.map