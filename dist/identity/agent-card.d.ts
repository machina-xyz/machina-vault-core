/**
 * A2A Agent Card Generator
 *
 * Generates Google A2A-compliant Agent Cards from vault identity.
 * The agent card is the discoverability layer — how other agents find
 * and interact with this vault.
 */
import type { AgentIdentity, A2AAgentCard, A2ASkill } from "./types.js";
/**
 * Generate an A2A Agent Card from a vault identity.
 *
 * The card is served at `/.well-known/agent.json` on the agent's domain,
 * or via the MACHINA discovery API at `/api/agents/{agentId}/card`.
 */
export declare function generateAgentCard(identity: AgentIdentity, options?: {
    baseUrl?: string;
    skills?: A2ASkill[];
    authSchemes?: A2AAgentCard["authentication"]["schemes"];
    capabilities?: Partial<A2AAgentCard["capabilities"]>;
    version?: string;
}): A2AAgentCard;
/**
 * Serialize agent card to JSON for serving at /.well-known/agent.json
 */
export declare function serializeAgentCard(card: A2AAgentCard): string;
/**
 * Validate that an agent card has all required fields.
 */
export declare function validateAgentCard(card: unknown): card is A2AAgentCard;
//# sourceMappingURL=agent-card.d.ts.map