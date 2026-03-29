/**
 * MACHINA Vault — WebAuthn Passkey Wallet Module
 * MAC-896: WebAuthn Passkey Wallet Creation + Secure Enclave Key Storage
 *
 * @module @machina/vault-core/passkey
 */
export type { VaultCredential, CreateVaultOptions, AuthenticateOptions, AuthenticationResult, VaultChallenge, } from "./types.js";
export { generateChallenge, validateChallenge, markChallengeUsed, } from "./challenge.js";
export { deriveVaultAddress, toChecksumAddress, } from "./derive-address.js";
export { createVaultCredential } from "./create.js";
export { authenticateVault } from "./authenticate.js";
export { verifyRegistration, verifyAuthentication, } from "./verify.js";
export { base64urlEncode, base64urlDecode, bufferToHex, hexToBuffer, concatBuffers, } from "./utils.js";
//# sourceMappingURL=index.d.ts.map