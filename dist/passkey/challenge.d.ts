/**
 * MACHINA Vault — Challenge generation and validation
 * Uses crypto.getRandomValues() for universal runtime compatibility.
 */
import type { VaultChallenge } from "./types.js";
/**
 * Generate a cryptographically random 32-byte challenge with a 5-minute TTL.
 *
 * Uses `crypto.getRandomValues()` which is available in browsers,
 * Cloudflare Workers, Deno, and Node.js 19+.
 */
export declare function generateChallenge(): VaultChallenge;
/**
 * Validate that a challenge is still valid (not expired and not already used).
 */
export declare function validateChallenge(challenge: VaultChallenge): boolean;
/**
 * Mark a challenge as used so it cannot be replayed.
 * Mutates the challenge object in place.
 */
export declare function markChallengeUsed(challenge: VaultChallenge): void;
