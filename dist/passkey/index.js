/**
 * MACHINA Vault — WebAuthn Passkey Wallet Module
 * MAC-896: WebAuthn Passkey Wallet Creation + Secure Enclave Key Storage
 *
 * @module @machina/vault-core/passkey
 */
// Challenge management
export { generateChallenge, validateChallenge, markChallengeUsed, } from "./challenge.js";
// Address derivation
export { deriveVaultAddress, toChecksumAddress, } from "./derive-address.js";
// Browser-side credential creation
export { createVaultCredential } from "./create.js";
// Browser-side authentication
export { authenticateVault } from "./authenticate.js";
// Server-side verification
export { verifyRegistration, verifyAuthentication, } from "./verify.js";
// Encoding utilities
export { base64urlEncode, base64urlDecode, bufferToHex, hexToBuffer, concatBuffers, } from "./utils.js";
//# sourceMappingURL=index.js.map