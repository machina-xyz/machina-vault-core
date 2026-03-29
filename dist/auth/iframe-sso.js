/**
 * MACHINA Vault — Iframe-based Single Sign-On
 * Allows embedding MACHINA vault UI in partner apps via iframe with
 * origin-bound sessions and postMessage communication.
 *
 * Cloudflare Workers V8 only — no Node.js APIs.
 */
import { createJWT, base64urlEncode } from "./jwt.js";
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function generateId() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return base64urlEncode(bytes);
}
function nowISO() {
    return new Date().toISOString();
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
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
export async function createIframeSession(config, vaultId, origin, secret) {
    if (!validateIframeOrigin(config, origin)) {
        throw new Error(`Origin not allowed: ${origin}`);
    }
    const sessionId = generateId();
    const now = Date.now();
    const expiresAtMs = now + config.sessionDurationMs;
    const tokenPayload = {
        sub: vaultId,
        iss: "machina:vault",
        aud: origin,
        scope: ["vault:read", "vault:write"],
        vaultId,
        sessionId,
    };
    const jwt = await createJWT(tokenPayload, secret, config.sessionDurationMs);
    const token = {
        sub: vaultId,
        iss: "machina:vault",
        aud: origin,
        exp: Math.floor(expiresAtMs / 1000),
        iat: Math.floor(now / 1000),
        scope: ["vault:read", "vault:write"],
        vaultId,
    };
    return {
        sessionId,
        token,
        expiresAt: new Date(expiresAtMs).toISOString(),
        createdAt: nowISO(),
        origin,
        refreshToken: jwt,
    };
}
/**
 * Validate that an origin is allowed to embed the vault iframe.
 * Supports exact matches and wildcard subdomain patterns (e.g. "*.example.com").
 *
 * @param config - Iframe auth configuration
 * @param origin - The origin to validate
 * @returns true if the origin is allowed
 */
export function validateIframeOrigin(config, origin) {
    for (const allowed of config.allowedOrigins) {
        // Exact match
        if (allowed === origin) {
            return true;
        }
        // Wildcard subdomain match: "*.example.com"
        if (allowed.startsWith("*.")) {
            const suffix = allowed.slice(1); // ".example.com"
            try {
                const originUrl = new URL(origin);
                const allowedBase = new URL(`https://${allowed.slice(2)}`);
                // Host must end with the suffix and use the same protocol scheme pattern
                if (originUrl.hostname.endsWith(suffix) ||
                    originUrl.hostname === allowedBase.hostname) {
                    return true;
                }
            }
            catch {
                // Invalid URL, skip
            }
        }
    }
    return false;
}
/**
 * Create a structured payload for window.postMessage communication.
 *
 * @param session - The auth session to communicate
 * @returns Structured message payload
 */
export function createPostMessagePayload(session) {
    return {
        type: "MACHINA_AUTH",
        sessionId: session.sessionId,
        token: session.token,
        expiresAt: session.expiresAt,
    };
}
/**
 * Parse and validate an incoming postMessage payload.
 *
 * @param data - Raw data from the postMessage event
 * @returns Parsed AuthSession or null if invalid
 */
export function parsePostMessagePayload(data) {
    if (data === null || typeof data !== "object") {
        return null;
    }
    const msg = data;
    if (msg.type !== "MACHINA_AUTH") {
        return null;
    }
    if (typeof msg.sessionId !== "string" || !msg.sessionId) {
        return null;
    }
    if (typeof msg.expiresAt !== "string" || !msg.expiresAt) {
        return null;
    }
    const token = msg.token;
    if (!token || typeof token !== "object") {
        return null;
    }
    // Validate required token fields
    if (typeof token.sub !== "string" ||
        typeof token.iss !== "string" ||
        typeof token.aud !== "string" ||
        typeof token.exp !== "number" ||
        typeof token.iat !== "number" ||
        !Array.isArray(token.scope)) {
        return null;
    }
    return {
        sessionId: msg.sessionId,
        token: token,
        expiresAt: msg.expiresAt,
        createdAt: new Date().toISOString(),
    };
}
/**
 * Mark an iframe session as revoked.
 * The actual revocation state is tracked externally (e.g. in D1 or KV).
 * This function is a no-op placeholder that integrators override with
 * their storage backend.
 *
 * @param _sessionId - The session to revoke
 */
export function revokeIframeSession(_sessionId) {
    // Revocation is tracked externally (D1/KV).
    // This is intentionally a no-op — callers should persist the
    // revocation flag in their storage layer after calling this.
}
//# sourceMappingURL=iframe-sso.js.map