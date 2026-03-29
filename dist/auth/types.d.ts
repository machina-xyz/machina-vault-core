/**
 * MACHINA Vault — Auth Module Types
 * Iframe SSO, MCP authentication, and A2A authentication for the vault.
 */
import type { KeyTier } from "../keys/types.js";
/** JWT-style auth token payload */
export interface AuthToken {
    /** Subject — user, agent, or service identifier */
    sub: string;
    /** Issuer — who created this token */
    iss: string;
    /** Audience — intended recipient */
    aud: string;
    /** Expiration time (Unix seconds) */
    exp: number;
    /** Issued at (Unix seconds) */
    iat: number;
    /** Permission scopes granted to this token */
    scope: string[];
    /** Associated vault ID, if scoped to a vault */
    vaultId?: string;
    /** Associated agent ID, if scoped to an agent */
    agentId?: string;
    /** Key tier used for authentication */
    tier?: KeyTier;
}
/** An authenticated session */
export interface AuthSession {
    /** Unique session identifier */
    sessionId: string;
    /** The auth token for this session */
    token: AuthToken;
    /** Opaque refresh token (shown once) */
    refreshToken?: string;
    /** ISO 8601 session expiry */
    expiresAt: string;
    /** ISO 8601 session creation time */
    createdAt: string;
    /** Origin that initiated this session (for iframe/CORS binding) */
    origin?: string;
}
/** A challenge for interactive authentication flows */
export interface AuthChallenge {
    /** Unique challenge identifier */
    challengeId: string;
    /** Hex-encoded random challenge bytes */
    challenge: string;
    /** ISO 8601 challenge expiry */
    expiresAt: string;
    /** Origin that requested the challenge */
    origin?: string;
    /** Authentication method this challenge is for */
    type: "passkey" | "apikey" | "a2a";
}
/** Configuration for iframe-based SSO */
export interface IframeAuthConfig {
    /** Origins allowed to embed the vault iframe */
    allowedOrigins: string[];
    /** The parent window origin */
    parentOrigin: string;
    /** Session duration in milliseconds */
    sessionDurationMs: number;
}
/** Configuration for MCP tool authentication */
export interface MCPAuthConfig {
    /** MCP server identifier */
    serverId: string;
    /** Tools the server is allowed to invoke */
    allowedTools: string[];
    /** Maximum session duration in milliseconds */
    maxSessionDurationMs: number;
    /** Whether passkey confirmation is required */
    requirePasskey: boolean;
}
/** Configuration for agent-to-agent authentication */
export interface A2AAuthConfig {
    /** Our agent identifier */
    agentId: string;
    /** Peer agent identifier */
    peerAgentId: string;
    /** Whether both sides must authenticate */
    mutualAuth: boolean;
    /** Capabilities offered in this session */
    capabilities: string[];
}
/** API key credential stored in the database (never contains the raw key) */
export interface APIKeyCredential {
    /** Unique key identifier */
    keyId: string;
    /** SHA-256 hash of the raw key (hex-encoded) */
    keyHash: string;
    /** Human-readable name */
    name: string;
    /** Permission scopes */
    scopes: string[];
    /** ISO 8601 creation timestamp */
    createdAt: string;
    /** ISO 8601 last usage timestamp */
    lastUsedAt?: string;
    /** ISO 8601 expiry timestamp */
    expiresAt?: string;
}
/** Structured auth error */
export interface AuthError {
    /** Machine-readable error code */
    code: string;
    /** Human-readable error message */
    message: string;
}
//# sourceMappingURL=types.d.ts.map