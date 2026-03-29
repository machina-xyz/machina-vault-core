/**
 * MACHINA Vault — Iframe-based Single Sign-On
 * Allows embedding MACHINA vault UI in partner apps via iframe with
 * origin-bound sessions and postMessage communication.
 *
 * Cloudflare Workers V8 only — no Node.js APIs.
 */
import type { AuthSession, AuthToken, IframeAuthConfig } from "./types.js";
/**
 * Create an iframe-bound auth session.
 *
 * @param config  - Iframe auth configuration (allowed origins, session duration)
 * @param vaultId - The vault this session is scoped to
 * @param origin  - The requesting origin (from the iframe parent)
 * @param secret  - HMAC key for signing the session JWT
 * @returns A new AuthSession bound to the origin
 * @throws If the origin is not in the allowlist
 */
export declare function createIframeSession(config: IframeAuthConfig, vaultId: string, origin: string, secret: Uint8Array): Promise<AuthSession>;
/**
 * Validate that an origin is allowed to embed the vault iframe.
 * Supports exact matches and wildcard subdomain patterns (e.g. "*.example.com").
 *
 * @param config - Iframe auth configuration
 * @param origin - The origin to validate
 * @returns true if the origin is allowed
 */
export declare function validateIframeOrigin(config: IframeAuthConfig, origin: string): boolean;
/**
 * Create a structured payload for window.postMessage communication.
 *
 * @param session - The auth session to communicate
 * @returns Structured message payload
 */
export declare function createPostMessagePayload(session: AuthSession): {
    type: "MACHINA_AUTH";
    sessionId: string;
    token: AuthToken;
    expiresAt: string;
};
/**
 * Parse and validate an incoming postMessage payload.
 *
 * @param data - Raw data from the postMessage event
 * @returns Parsed AuthSession or null if invalid
 */
export declare function parsePostMessagePayload(data: unknown): AuthSession | null;
/**
 * Mark an iframe session as revoked.
 * The actual revocation state is tracked externally (e.g. in D1 or KV).
 * This function is a no-op placeholder that integrators override with
 * their storage backend.
 *
 * @param _sessionId - The session to revoke
 */
export declare function revokeIframeSession(_sessionId: string): void;
//# sourceMappingURL=iframe-sso.d.ts.map