/**
 * A2A Agent Card Generator
 *
 * Generates Google A2A-compliant Agent Cards from vault identity.
 * The agent card is the discoverability layer — how other agents find
 * and interact with this vault.
 */

import type { AgentIdentity, A2AAgentCard, A2ASkill } from "./types.js";

/** Default MACHINA vault capabilities */
const DEFAULT_CAPABILITIES = {
  streaming: false,
  pushNotifications: true,
  stateTransitionHistory: true,
} as const;

/** Standard authentication schemes supported by MACHINA vaults */
const DEFAULT_AUTH_SCHEMES = [
  { scheme: "bearer", description: "Bearer token authentication" },
  { scheme: "x402", description: "x402 payment-based authentication" },
  { scheme: "machina-passkey", description: "WebAuthn passkey-based vault authentication" },
];

/**
 * Generate an A2A Agent Card from a vault identity.
 *
 * The card is served at `/.well-known/agent.json` on the agent's domain,
 * or via the MACHINA discovery API at `/api/agents/{agentId}/card`.
 */
export function generateAgentCard(
  identity: AgentIdentity,
  options?: {
    baseUrl?: string;
    skills?: A2ASkill[];
    authSchemes?: A2AAgentCard["authentication"]["schemes"];
    capabilities?: Partial<A2AAgentCard["capabilities"]>;
    version?: string;
  },
): A2AAgentCard {
  const baseUrl = options?.baseUrl ?? `https://machina.money/agents/${identity.agentId}`;

  // Generate skills from agent capabilities
  const skills: A2ASkill[] = options?.skills ?? generateDefaultSkills(identity.capabilities);

  return {
    name: identity.name,
    description: identity.description,
    url: baseUrl,
    provider: {
      organization: "MACHINA",
      url: "https://machina.money",
    },
    version: options?.version ?? "1.0.0",
    capabilities: {
      ...DEFAULT_CAPABILITIES,
      ...options?.capabilities,
    },
    authentication: {
      schemes: options?.authSchemes ?? DEFAULT_AUTH_SCHEMES,
    },
    defaultInputModes: ["text", "json"],
    defaultOutputModes: ["text", "json"],
    skills,
  };
}

/**
 * Generate default skills based on agent capabilities.
 */
function generateDefaultSkills(capabilities: string[]): A2ASkill[] {
  const skillMap: Record<string, A2ASkill> = {
    payment: {
      id: "machina_payment",
      name: "Process Payment",
      description: "Send and receive payments across supported chains",
      tags: ["payment", "transfer", "send"],
      examples: ["Send 10 USDC to 0x...", "Pay invoice #123"],
      inputModes: ["json"],
      outputModes: ["json"],
    },
    trading: {
      id: "machina_trading",
      name: "Execute Trade",
      description: "Execute token swaps and trades via DEX aggregators",
      tags: ["trade", "swap", "dex"],
      examples: ["Swap 1 ETH for USDC", "Buy $500 of SOL"],
    },
    defi: {
      id: "machina_defi",
      name: "DeFi Operations",
      description: "Supply, borrow, and manage DeFi positions",
      tags: ["defi", "yield", "lending", "staking"],
      examples: ["Supply 1000 USDC to Aave", "Stake 10 ETH"],
    },
    analytics: {
      id: "machina_analytics",
      name: "Portfolio Analytics",
      description: "Analyze portfolio performance and risk metrics",
      tags: ["analytics", "portfolio", "risk"],
      examples: ["Show my portfolio performance", "What's my Sharpe ratio?"],
    },
    compliance: {
      id: "machina_compliance",
      name: "Compliance Check",
      description: "Run compliance checks including sanctions screening",
      tags: ["compliance", "sanctions", "kyc"],
    },
    governance: {
      id: "machina_governance",
      name: "Governance Participation",
      description: "Vote on proposals and participate in DAO governance",
      tags: ["governance", "voting", "dao"],
    },
    identity: {
      id: "machina_identity",
      name: "Identity Verification",
      description: "Verify agent identity and credentials",
      tags: ["identity", "verification", "credentials"],
    },
  };

  const skills: A2ASkill[] = [];

  for (const cap of capabilities) {
    const normalizedCap = cap.toLowerCase().replace(/[^a-z]/g, "");
    for (const [key, skill] of Object.entries(skillMap)) {
      if (normalizedCap.includes(key) || key.includes(normalizedCap)) {
        skills.push(skill);
        break;
      }
    }
  }

  // Always include identity verification
  if (!skills.find((s) => s.id === "machina_identity")) {
    skills.push(skillMap.identity);
  }

  return skills;
}

/**
 * Serialize agent card to JSON for serving at /.well-known/agent.json
 */
export function serializeAgentCard(card: A2AAgentCard): string {
  return JSON.stringify(card, null, 2);
}

/**
 * Validate that an agent card has all required fields.
 */
export function validateAgentCard(card: unknown): card is A2AAgentCard {
  if (!card || typeof card !== "object") return false;
  const c = card as Record<string, unknown>;
  return (
    typeof c.name === "string" &&
    typeof c.description === "string" &&
    typeof c.url === "string" &&
    typeof c.version === "string" &&
    c.provider != null &&
    c.capabilities != null &&
    c.authentication != null &&
    Array.isArray(c.skills)
  );
}
