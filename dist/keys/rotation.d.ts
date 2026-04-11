/**
 * MACHINA Vault — Key Rotation
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Supports automatic key rotation based on configured intervals.
 * During rotation, a 5-minute overlap window allows both old and new keys
 * to be valid simultaneously for graceful handoff.
 */
import type { VaultKey } from "./types.js";
/**
 * Check whether a key should be rotated based on its autoRotateInterval.
 *
 * Returns true if:
 * 1. The key has an autoRotateInterval configured
 * 2. The key is currently "active"
 * 3. The interval has elapsed since key creation
 */
export declare function shouldRotate(key: VaultKey): boolean;
export interface RotateKeyParams {
    /** The key being rotated */
    oldKey: VaultKey;
    /** Master seed for deriving the new key */
    masterSeed: Uint8Array;
    /** New derivation index for the replacement key */
    newIndex: number;
}
export interface RotateKeyResult {
    /** The new replacement key */
    newKey: VaultKey;
    /** The new key's private key */
    newPrivateKey: Uint8Array;
    /** The old key updated with "rotating" status */
    oldKeyUpdated: VaultKey;
    /** ISO 8601 timestamp when the overlap window expires */
    overlapExpiresAt: string;
}
/**
 * Rotate a key: generate a new key at the given index and mark the old key
 * as "rotating" with a 5-minute overlap window.
 *
 * During the overlap window, both old and new keys are valid.
 * After the window expires, the old key should be revoked.
 *
 * Only operator and agent keys can be rotated (they are derived).
 * Root keys are rotated via recovery. Session keys just expire.
 */
export declare function rotateKey(params: RotateKeyParams): RotateKeyResult;
