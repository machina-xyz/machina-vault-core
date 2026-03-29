/**
 * MACHINA Vault — Stealth Address Scanning
 * MAC-903: ERC-5564 announcement scanning with view tag optimisation
 *
 * Provides efficient scanning of on-chain announcements to detect stealth
 * addresses belonging to a wallet. Uses the view tag (first byte of the
 * shared secret hash) for fast filtering — only 1/256 announcements require
 * full ECDH computation.
 *
 * Cloudflare Workers V8 compatible — no Node.js APIs.
 */
import type { AnnouncementLog, StealthAddress } from "./types.js";
/**
 * Compute the ERC-5564 view tag from a shared secret.
 *
 * The view tag is the first byte of SHA-256(sharedSecret). It enables
 * scanning optimisation: recipients only need to perform full ECDH
 * derivation for the ~1/256 of announcements whose view tag matches.
 *
 * @param sharedSecret - The raw shared secret bytes (compressed point)
 * @returns View tag value (0-255)
 */
export declare function computeViewTag(sharedSecret: Uint8Array): number;
/**
 * Create a filter function for scanning announcements.
 *
 * Returns a closure that efficiently checks whether an announcement's view
 * tag matches the one derivable from the viewing key. This is the first-pass
 * filter that eliminates ~255/256 of announcements without full derivation.
 *
 * @param viewingKey - Viewing private key (hex)
 * @returns Filter function: true if the announcement might belong to this wallet
 */
export declare function createAnnouncementFilter(viewingKey: string): (announcement: AnnouncementLog) => boolean;
/**
 * Scan a batch of announcements to find stealth addresses belonging to this wallet.
 *
 * Two-phase scanning:
 * 1. View tag filter (fast): eliminates ~255/256 of announcements
 * 2. Full derivation (slow): verifies the stealth address for matches
 *
 * @param announcements - Array of on-chain announcement log entries
 * @param viewingKey - Viewing private key (hex)
 * @returns Array of stealth addresses that belong to this wallet
 */
export declare function scanAnnouncements(announcements: AnnouncementLog[], viewingKey: string): StealthAddress[];
/**
 * Encode announcement metadata for on-chain logging.
 *
 * Metadata format (per ERC-5564):
 * - Byte 0: scheme ID
 * - Bytes 1-20: stealth address (20 bytes)
 * - Remaining: reserved for future use
 *
 * @param data - Metadata components
 * @returns Hex-encoded metadata string
 */
export declare function encodeAnnouncementMetadata(data: {
    schemeId: number;
    stealthAddress: string;
}): string;
//# sourceMappingURL=scanning.d.ts.map