/**
 * Identity Registration
 *
 * On vault creation, auto-register as ERC-8004 agent identity.
 * Builds the on-chain registration transaction and KYA metadata.
 */
import type { AgentIdentity, IdentityRegistrationRequest, KYAMetadata } from "./types.js";
/**
 * Build the identity record for a new vault.
 * Does NOT execute the on-chain registration — returns the identity object
 * and the calldata needed for registration. The caller (signing engine)
 * handles actual tx execution.
 */
export declare function buildIdentityRegistration(request: IdentityRegistrationRequest, vaultAddress: string, signingPublicKey: string): {
    identity: AgentIdentity;
    kya: KYAMetadata;
    registrationCalldata: string;
};
/**
 * Mark identity as registered after successful on-chain tx.
 */
export declare function confirmRegistration(identity: AgentIdentity, txHash: string, nftTokenId?: string): AgentIdentity;
/**
 * Update KYA metadata after sanctions screening completes.
 */
export declare function updateKYACompliance(kya: KYAMetadata, sanctionsScreened: boolean, jurisdictions: string[]): KYAMetadata;
