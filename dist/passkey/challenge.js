/**
 * MACHINA Vault — Challenge generation and validation
 * Uses crypto.getRandomValues() for universal runtime compatibility.
 */
/** Challenge time-to-live: 5 minutes in milliseconds */
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
/** Challenge size in bytes */
const CHALLENGE_BYTES = 32;
/**
 * Generate a cryptographically random 32-byte challenge with a 5-minute TTL.
 *
 * Uses `crypto.getRandomValues()` which is available in browsers,
 * Cloudflare Workers, Deno, and Node.js 19+.
 */
export function generateChallenge() {
    const challenge = new Uint8Array(CHALLENGE_BYTES);
    crypto.getRandomValues(challenge);
    const now = Date.now();
    return {
        challenge,
        createdAt: now,
        expiresAt: now + CHALLENGE_TTL_MS,
        used: false,
    };
}
/**
 * Validate that a challenge is still valid (not expired and not already used).
 */
export function validateChallenge(challenge) {
    if (challenge.used) {
        return false;
    }
    if (Date.now() > challenge.expiresAt) {
        return false;
    }
    return true;
}
/**
 * Mark a challenge as used so it cannot be replayed.
 * Mutates the challenge object in place.
 */
export function markChallengeUsed(challenge) {
    challenge.used = true;
}
