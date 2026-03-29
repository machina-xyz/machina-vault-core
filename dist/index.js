/**
 * @machina/vault-core
 *
 * Core primitives for MACHINA Vault — keyless secure enclave wallets for
 * autonomous agents. One passkey → one vault → all chains.
 *
 * Modules:
 *   passkey/   — WebAuthn credential creation & verification
 *   keys/      — 4-tier key hierarchy (Root → Operator → Agent → Session)
 *   signing/   — Chain-agnostic transaction signing (EVM, Solana, Sui)
 *   policy/    — TEE-enforced policy evaluation before signing
 *   identity/  — ERC-8004 agent identity + A2A Agent Card
 *   recovery/  — Social recovery & cloud backup
 *   mpc/       — MPC threshold signing (Feldman VSS + threshold Schnorr)
 *   privacy/   — Stealth addresses (ERC-5564) + ZK balance proofs
 *   auth/      — JWT, iframe SSO, MCP auth, A2A auth, API keys
 *   enclave/   — Platform detection, key store, attestation, secure channels
 *
 * For conflicting names, import directly from submodules:
 *   import { reconstructSecret } from "@machina/vault-core/recovery"
 *   import { reconstructSecret } from "@machina/vault-core/mpc"
 *   import { base64urlEncode } from "@machina/vault-core/auth"
 */
// passkey — exports base64urlEncode/base64urlDecode (these win at top level)
export * from "./passkey/index.js";
export * from "./keys/index.js";
export * from "./signing/index.js";
export * from "./policy/index.js";
export * from "./identity/index.js";
// recovery — exports reconstructSecret (conflicts with mpc)
// Consumers should import from submodule directly for disambiguated access
export { splitSecret, reconstructSecret, createRecoveryConfig, initiateRecovery, submitRecoveryShare, } from "./recovery/index.js";
// mpc — reconstructSecret conflicts with recovery, skip it here
export { keygenRound1, keygenRound2, keygenRound3, verifyKeygenRound3, generateKeyShares, thresholdSign, signRound1, signRound2, signRound3, signRound4, verifySignature, reshare, reshareRound1, reshareRound2, proactiveRefresh, commit, hashCommit, hashVerify, verify, toHex, fromHex, randomBytes, bytesToScalar, modN, constantTimeEqual, } from "./mpc/index.js";
export * from "./privacy/index.js";
// auth — base64urlEncode/base64urlDecode conflict with passkey, skip those
export { createJWT, verifyJWT, decodeJWT, textToBytes, bytesToText, createIframeSession, validateIframeOrigin, createMCPSession, verifyMCPChallenge, validateMCPToolCall, createA2AChallenge, createA2AAuthToken, verifyA2AAuthToken, negotiateCapabilities, hasScope, generateAPIKey, validateAPIKey, parseAPIKey, } from "./auth/index.js";
export * from "./enclave/index.js";
//# sourceMappingURL=index.js.map