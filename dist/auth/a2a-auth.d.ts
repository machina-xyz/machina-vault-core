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
import type { A2AAuthConfig, AuthChallenge } from "./types.js";
/**
 * Generate a mutual authentication challenge for A2A handshake.
 *
 * @param agentId     - Our agent identifier
 * @param peerAgentId - The peer agent we want to authenticate
 * @returns An auth challenge to send to the peer
 */
export declare function createA2AChallenge(agentId: string, peerAgentId: string): AuthChallenge;
/**
 * Create a signed JWT asserting this agent's identity and capabilities.
 * The token is scoped to a specific peer agent (audience).
 *
 * @param config     - A2A auth configuration
 * @param signingKey - HMAC signing key (shared secret with peer)
 * @returns Signed JWT string
 */
export declare function createA2AAuthToken(config: A2AAuthConfig, signingKey: Uint8Array): Promise<string>;
/**
 * Verify a peer agent's A2A auth token.
 *
 * @param token         - The JWT received from the peer
 * @param peerSecret    - Shared secret for HMAC verification with this peer
 * @returns Verification result with agent identity and capabilities
 */
export declare function verifyA2AAuthToken(token: string, peerSecret: Uint8Array): Promise<{
    valid: boolean;
    agentId?: string;
    capabilities?: string[];
}>;
/**
 * Negotiate capabilities between two agents.
 * Returns the intersection of both agents' capabilities, preserving
 * the order from our capability list.
 *
 * @param ourCapabilities  - Capabilities we offer
 * @param peerCapabilities - Capabilities the peer offers
 * @returns Intersection of capabilities
 */
export declare function negotiateCapabilities(ourCapabilities: string[], peerCapabilities: string[]): string[];
//# sourceMappingURL=a2a-auth.d.ts.map