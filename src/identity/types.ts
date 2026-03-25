/**
 * Vault Identity Types
 *
 * Every MACHINA Vault is a full agent identity — ERC-8004 registration,
 * A2A Agent Card, and KYA (Know Your Agent) metadata.
 */

export type IdentityStatus = "pending" | "registered" | "verified" | "suspended" | "revoked";

export interface AgentIdentity {
  /** Vault address (ERC-8004 agent ID) */
  agentId: string;
  /** Vault ID in MACHINA system */
  vaultId: string;
  /** Display name */
  name: string;
  /** Short description of agent capabilities */
  description: string;
  /** Agent specializations/tags */
  capabilities: string[];
  /** ERC-8004 registration status */
  registrationStatus: IdentityStatus;
  /** On-chain registration tx hash (null if not yet registered) */
  registrationTxHash: string | null;
  /** ERC-721 agent NFT token ID */
  nftTokenId: string | null;
  /** Chain where identity is registered */
  registrationChain: string;
  /** A2A Agent Card URL */
  agentCardUrl: string | null;
  /** KYA metadata hash (IPFS CID or on-chain hash) */
  kyaHash: string | null;
  /** Public signing key for identity assertions */
  signingPublicKey: string;
  /** Reputation score (from MACHINA reputation protocol) */
  reputationScore: number;
  /** Created timestamp */
  createdAt: string;
  /** Last updated */
  updatedAt: string;
}

/**
 * A2A Agent Card — compliant with Google A2A protocol.
 * Describes agent capabilities for discovery and interoperability.
 */
export interface A2AAgentCard {
  /** Agent name */
  name: string;
  /** Agent description */
  description: string;
  /** URL where this card is hosted */
  url: string;
  /** Agent provider info */
  provider: {
    organization: string;
    url: string;
  };
  /** Agent version */
  version: string;
  /** Supported capabilities */
  capabilities: {
    streaming: boolean;
    pushNotifications: boolean;
    stateTransitionHistory: boolean;
  };
  /** Authentication requirements */
  authentication: {
    schemes: Array<{
      scheme: string; // "bearer" | "apiKey" | "x402" | "machina-passkey"
      description?: string;
    }>;
  };
  /** Default input modes */
  defaultInputModes: string[]; // ["text", "json"]
  /** Default output modes */
  defaultOutputModes: string[]; // ["text", "json"]
  /** Skills this agent can perform */
  skills: A2ASkill[];
}

export interface A2ASkill {
  id: string;
  name: string;
  description: string;
  tags: string[];
  examples?: string[];
  inputModes?: string[];
  outputModes?: string[];
}

/**
 * KYA (Know Your Agent) metadata — on-chain verifiable agent profile.
 */
export interface KYAMetadata {
  /** Schema version */
  version: "1.0";
  /** Agent address */
  agentAddress: string;
  /** Agent type classification */
  agentType: "autonomous" | "semi-autonomous" | "human-supervised";
  /** Operating parameters */
  operatingParams: {
    maxTransactionValueUsd: number;
    dailyLimitUsd: number;
    allowedChains: string[];
    allowedProtocols: string[];
    riskTolerance: "conservative" | "moderate" | "aggressive";
  };
  /** Compliance info */
  compliance: {
    sanctionsScreened: boolean;
    sanctionsScreenedAt: string | null;
    jurisdictions: string[];
    policyEngine: "machina-vault" | "custom";
  };
  /** Audit trail */
  audit: {
    createdAt: string;
    lastVerifiedAt: string | null;
    verificationMethod: "on-chain" | "attestation" | "self-declared";
  };
  /** Content hash of full metadata (for on-chain reference) */
  contentHash: string;
}

export interface IdentityRegistrationRequest {
  vaultId: string;
  name: string;
  description: string;
  capabilities: string[];
  chain: string;
  agentType?: KYAMetadata["agentType"];
  operatingParams?: Partial<KYAMetadata["operatingParams"]>;
}
