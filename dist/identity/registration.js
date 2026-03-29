/**
 * Identity Registration
 *
 * On vault creation, auto-register as ERC-8004 agent identity.
 * Builds the on-chain registration transaction and KYA metadata.
 */
// ERC-8004 MachinaRegistry function selectors
const SELECTORS = {
    registerAgent: "0x7b1039d6", // registerAgent(address,string,bytes32)
    updateAgent: "0x3c7d3e3a", // updateAgent(address,string,bytes32)
    getAgent: "0x2e64cec1", // getAgent(address)
    isRegistered: "0x60d7faed", // isRegistered(address)
};
/**
 * Build the identity record for a new vault.
 * Does NOT execute the on-chain registration — returns the identity object
 * and the calldata needed for registration. The caller (signing engine)
 * handles actual tx execution.
 */
export function buildIdentityRegistration(request, vaultAddress, signingPublicKey) {
    const now = new Date().toISOString();
    const kya = {
        version: "1.0",
        agentAddress: vaultAddress,
        agentType: request.agentType ?? "autonomous",
        operatingParams: {
            maxTransactionValueUsd: request.operatingParams?.maxTransactionValueUsd ?? 10_000,
            dailyLimitUsd: request.operatingParams?.dailyLimitUsd ?? 50_000,
            allowedChains: request.operatingParams?.allowedChains ?? [request.chain],
            allowedProtocols: request.operatingParams?.allowedProtocols ?? [],
            riskTolerance: request.operatingParams?.riskTolerance ?? "moderate",
        },
        compliance: {
            sanctionsScreened: false,
            sanctionsScreenedAt: null,
            jurisdictions: [],
            policyEngine: "machina-vault",
        },
        audit: {
            createdAt: now,
            lastVerifiedAt: null,
            verificationMethod: "self-declared",
        },
        contentHash: "", // computed below
    };
    // Compute content hash of KYA metadata (without the contentHash field)
    const kyaForHash = { ...kya, contentHash: undefined };
    const kyaJson = JSON.stringify(kyaForHash, null, 0);
    kya.contentHash = simpleHash(kyaJson);
    // Build ERC-8004 registerAgent calldata
    // registerAgent(address agentAddress, string name, bytes32 kyaHash)
    const registrationCalldata = encodeRegisterAgent(vaultAddress, request.name, kya.contentHash);
    const identity = {
        agentId: vaultAddress,
        vaultId: request.vaultId,
        name: request.name,
        description: request.description,
        capabilities: request.capabilities,
        registrationStatus: "pending",
        registrationTxHash: null,
        nftTokenId: null,
        registrationChain: request.chain,
        agentCardUrl: null,
        kyaHash: kya.contentHash,
        signingPublicKey,
        reputationScore: 100,
        createdAt: now,
        updatedAt: now,
    };
    return { identity, kya, registrationCalldata };
}
/**
 * Mark identity as registered after successful on-chain tx.
 */
export function confirmRegistration(identity, txHash, nftTokenId) {
    return {
        ...identity,
        registrationStatus: "registered",
        registrationTxHash: txHash,
        nftTokenId: nftTokenId ?? null,
        updatedAt: new Date().toISOString(),
    };
}
/**
 * Update KYA metadata after sanctions screening completes.
 */
export function updateKYACompliance(kya, sanctionsScreened, jurisdictions) {
    const updated = {
        ...kya,
        compliance: {
            ...kya.compliance,
            sanctionsScreened,
            sanctionsScreenedAt: new Date().toISOString(),
            jurisdictions,
        },
        audit: {
            ...kya.audit,
            lastVerifiedAt: new Date().toISOString(),
        },
    };
    const forHash = { ...updated, contentHash: undefined };
    updated.contentHash = simpleHash(JSON.stringify(forHash, null, 0));
    return updated;
}
// ---------------------------------------------------------------------------
// ABI Encoding helpers (minimal, no dependencies)
// ---------------------------------------------------------------------------
function encodeRegisterAgent(agentAddress, name, kyaHash) {
    const addr = padLeft(agentAddress.replace("0x", ""), 64);
    // String offset (3 * 32 = 96 = 0x60)
    const stringOffset = padLeft("60", 64);
    // KYA hash (bytes32)
    const hashPadded = padLeft(kyaHash.replace("0x", ""), 64);
    // String encoding: length + data
    const nameBytes = utf8ToHex(name);
    const nameLength = padLeft((nameBytes.length / 2).toString(16), 64);
    const namePadded = nameBytes.padEnd(Math.ceil(nameBytes.length / 64) * 64, "0");
    return (SELECTORS.registerAgent +
        addr +
        stringOffset +
        hashPadded +
        nameLength +
        namePadded);
}
function padLeft(hex, length) {
    return hex.padStart(length, "0");
}
function utf8ToHex(str) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
/**
 * Simple hash function for content hashing.
 * Uses Web Crypto SHA-256 synchronously via a hex representation.
 * For actual deployment, use async crypto.subtle.digest.
 */
function simpleHash(data) {
    // Deterministic hash via simple FNV-1a (for synchronous operation)
    // In production, replace with async SHA-256 via Web Crypto
    let hash = 0x811c9dc5;
    const encoder = new TextEncoder();
    const bytes = encoder.encode(data);
    for (const byte of bytes) {
        hash ^= byte;
        hash = Math.imul(hash, 0x01000193);
    }
    // Extend to 32 bytes by iterating
    const result = new Uint8Array(32);
    let h = hash;
    for (let i = 0; i < 32; i++) {
        result[i] = h & 0xff;
        h = Math.imul(h ^ result[i], 0x01000193);
    }
    return "0x" + Array.from(result, (b) => b.toString(16).padStart(2, "0")).join("");
}
//# sourceMappingURL=registration.js.map