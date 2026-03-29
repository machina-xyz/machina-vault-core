/**
 * MACHINA Vault — MCP (Model Context Protocol) Authentication
 * Authenticates MCP tool calls from AI agents with tool-scoped
 * permissions and optional passkey confirmation.
 *
 * Cloudflare Workers V8 only — no Node.js APIs.
 */
import type { AuthChallenge, AuthSession, MCPAuthConfig } from "./types.js";
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
export declare function createMCPSession(config: MCPAuthConfig, agentId: string, requestedTools: string[], secret: Uint8Array): Promise<AuthSession>;
/**
 * Validate whether a session is allowed to invoke a specific MCP tool.
 *
 * @param session  - The active auth session
 * @param toolName - The tool being invoked
 * @returns Whether the call is allowed, with a reason if denied
 */
export declare function validateMCPToolCall(session: AuthSession, toolName: string): {
    allowed: boolean;
    reason?: string;
};
/**
 * Generate a challenge for MCP server authentication.
 * The server must respond with an HMAC of the challenge to prove identity.
 *
 * @param serverId - The MCP server identifier
 * @returns A new auth challenge
 */
export declare function createMCPChallenge(serverId: string): AuthChallenge;
/**
 * Verify an HMAC response to an MCP challenge.
 *
 * @param challenge    - The original challenge
 * @param response     - Hex-encoded HMAC response from the server
 * @param serverSecret - The shared secret for HMAC verification
 * @returns true if the response is valid
 */
export declare function verifyMCPChallenge(challenge: AuthChallenge, response: string, serverSecret: Uint8Array): Promise<boolean>;
//# sourceMappingURL=mcp-auth.d.ts.map