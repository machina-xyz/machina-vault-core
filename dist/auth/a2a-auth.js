/**
 * MACHINA Vault — Agent-to-Agent (A2A) Authentication
 * Implements mutual authentication between MACHINA agents following
 * the Google A2A Protocol pattern.
 *
 * Uses HMAC-SHA256 for signing (symmetric keys). For production
 * deployments with asymmetric keys, this module can be extended to
 * use ECDSA via crypto.subtle.
 *
 * Cloudflare Workers V8 only — no Node.js APIs.
 */
import { createJWT, verifyJWT, base64urlEncode, } from "./jwt.js";
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function generateId() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return base64urlEncode(bytes);
}
function bytesToHex(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
/** Default A2A token lifetime: 5 minutes */
const A2A_TOKEN_DURATION_MS = 5 * 60 * 1000;
/** Default A2A challenge lifetime: 60 seconds */
const A2A_CHALLENGE_DURATION_MS = 60_000;
/**
 * Generate a mutual authentication challenge for A2A handshake.
 *
 * @param agentId     - Our agent identifier
 * @param peerAgentId - The peer agent we want to authenticate
 * @returns An auth challenge to send to the peer
 */
export function createA2AChallenge(agentId, peerAgentId) {
    const challengeBytes = new Uint8Array(32);
    crypto.getRandomValues(challengeBytes);
    return {
        challengeId: generateId(),
        challenge: bytesToHex(challengeBytes),
        expiresAt: new Date(Date.now() + A2A_CHALLENGE_DURATION_MS).toISOString(),
        origin: agentId,
        type: "a2a",
    };
}
/**
 * Create a signed JWT asserting this agent's identity and capabilities.
 * The token is scoped to a specific peer agent (audience).
 *
 * @param config     - A2A auth configuration
 * @param signingKey - HMAC signing key (shared secret with peer)
 * @returns Signed JWT string
 */
export async function createA2AAuthToken(config, signingKey) {
    const payload = {
        sub: config.agentId,
        iss: `machina:agent:${config.agentId}`,
        aud: config.peerAgentId,
        capabilities: config.capabilities,
        mutualAuth: config.mutualAuth,
    };
    return createJWT(payload, signingKey, A2A_TOKEN_DURATION_MS);
}
/**
 * Verify a peer agent's A2A auth token.
 *
 * @param token         - The JWT received from the peer
 * @param peerSecret    - Shared secret for HMAC verification with this peer
 * @returns Verification result with agent identity and capabilities
 */
export async function verifyA2AAuthToken(token, peerSecret) {
    const result = await verifyJWT(token, peerSecret);
    if (!result.valid || !result.payload) {
        return { valid: false };
    }
    const payload = result.payload;
    if (typeof payload.sub !== "string") {
        return { valid: false };
    }
    const capabilities = Array.isArray(payload.capabilities)
        ? payload.capabilities
        : [];
    return {
        valid: true,
        agentId: payload.sub,
        capabilities,
    };
}
/**
 * Negotiate capabilities between two agents.
 * Returns the intersection of both agents' capabilities, preserving
 * the order from our capability list.
 *
 * @param ourCapabilities  - Capabilities we offer
 * @param peerCapabilities - Capabilities the peer offers
 * @returns Intersection of capabilities
 */
export function negotiateCapabilities(ourCapabilities, peerCapabilities) {
    const peerSet = new Set(peerCapabilities);
    return ourCapabilities.filter((cap) => peerSet.has(cap));
}
