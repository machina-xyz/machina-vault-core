/**
 * MACHINA Vault — MCP (Model Context Protocol) Authentication
 * Authenticates MCP tool calls from AI agents with tool-scoped
 * permissions and optional passkey confirmation.
 *
 * Cloudflare Workers V8 only — no Node.js APIs.
 */

import type {
  AuthChallenge,
  AuthSession,
  AuthToken,
  MCPAuthConfig,
} from "./types.js";
import { createJWT, base64urlEncode, textToBytes } from "./jwt.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function nowISO(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create an MCP session with tool-scoped permissions.
 *
 * Filters the requested tools against the server's allowed tools list.
 * If requirePasskey is set, the session is created in a pending state
 * requiring passkey confirmation before use.
 *
 * @param config         - MCP auth configuration
 * @param agentId        - The requesting agent's identifier
 * @param requestedTools - Tools the agent wants to invoke
 * @param secret         - HMAC key for signing the session JWT
 * @returns A new AuthSession scoped to the allowed tools
 */
export async function createMCPSession(
  config: MCPAuthConfig,
  agentId: string,
  requestedTools: string[],
  secret: Uint8Array,
): Promise<AuthSession> {
  // Filter requested tools to only those allowed by the server config
  const grantedTools = requestedTools.filter((tool) =>
    config.allowedTools.includes(tool),
  );

  if (grantedTools.length === 0) {
    throw new Error("No requested tools are allowed by this MCP server");
  }

  const sessionId = generateId();
  const now = Date.now();
  const expiresAtMs = now + config.maxSessionDurationMs;

  // Build scopes from granted tools: "mcp:tool:<toolName>"
  const scope = grantedTools.map((t) => `mcp:tool:${t}`);

  // If passkey is required, add a pending scope marker
  if (config.requirePasskey) {
    scope.push("mcp:pending_passkey");
  }

  const tokenPayload: Record<string, unknown> = {
    sub: agentId,
    iss: `machina:mcp:${config.serverId}`,
    aud: config.serverId,
    scope,
    agentId,
    sessionId,
  };

  const jwt = await createJWT(
    tokenPayload,
    secret,
    config.maxSessionDurationMs,
  );

  const token: AuthToken = {
    sub: agentId,
    iss: `machina:mcp:${config.serverId}`,
    aud: config.serverId,
    exp: Math.floor(expiresAtMs / 1000),
    iat: Math.floor(now / 1000),
    scope,
    agentId,
  };

  return {
    sessionId,
    token,
    refreshToken: jwt,
    expiresAt: new Date(expiresAtMs).toISOString(),
    createdAt: nowISO(),
  };
}

/**
 * Validate whether a session is allowed to invoke a specific MCP tool.
 *
 * @param session  - The active auth session
 * @param toolName - The tool being invoked
 * @returns Whether the call is allowed, with a reason if denied
 */
export function validateMCPToolCall(
  session: AuthSession,
  toolName: string,
): { allowed: boolean; reason?: string } {
  // Check if session has pending passkey requirement
  if (session.token.scope.includes("mcp:pending_passkey")) {
    return { allowed: false, reason: "Passkey confirmation required" };
  }

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (session.token.exp < now) {
    return { allowed: false, reason: "Session expired" };
  }

  // Check tool scope
  const requiredScope = `mcp:tool:${toolName}`;
  if (!session.token.scope.includes(requiredScope)) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" not in session scope`,
    };
  }

  return { allowed: true };
}

/**
 * Generate a challenge for MCP server authentication.
 * The server must respond with an HMAC of the challenge to prove identity.
 *
 * @param serverId - The MCP server identifier
 * @returns A new auth challenge
 */
export function createMCPChallenge(serverId: string): AuthChallenge {
  const challengeBytes = new Uint8Array(32);
  crypto.getRandomValues(challengeBytes);

  const challengeId = generateId();
  const expiresAt = new Date(Date.now() + 60_000).toISOString(); // 60s expiry

  return {
    challengeId,
    challenge: bytesToHex(challengeBytes),
    expiresAt,
    type: "apikey",
  };
}

/**
 * Verify an HMAC response to an MCP challenge.
 *
 * @param challenge    - The original challenge
 * @param response     - Hex-encoded HMAC response from the server
 * @param serverSecret - The shared secret for HMAC verification
 * @returns true if the response is valid
 */
export async function verifyMCPChallenge(
  challenge: AuthChallenge,
  response: string,
  serverSecret: Uint8Array,
): Promise<boolean> {
  // Check expiration
  if (new Date(challenge.expiresAt).getTime() < Date.now()) {
    return false;
  }

  // Compute expected HMAC of the challenge
  const key = await crypto.subtle.importKey(
    "raw",
    serverSecret as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const challengeData = hexToBytes(challenge.challenge);
  const expectedSig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, challengeData as BufferSource),
  );

  // Constant-time comparison
  const responseSig = hexToBytes(response);
  if (expectedSig.length !== responseSig.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < expectedSig.length; i++) {
    diff |= expectedSig[i] ^ responseSig[i];
  }

  return diff === 0;
}
