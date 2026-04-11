/**
 * MACHINA Vault — WebAuthn credential creation (browser-side)
 *
 * Creates a P-256 passkey credential via the WebAuthn API and derives
 * a deterministic EVM vault address from the public key.
 */
import type { VaultCredential, CreateVaultOptions } from "./types.js";
/**
 * Create a new WebAuthn credential and derive the corresponding vault address.
 *
 * Must be called in a browser context with access to `navigator.credentials`.
 *
 * @throws If the WebAuthn API is unavailable, the user cancels, or the
 *         authenticator response cannot be parsed.
 */
export declare function createVaultCredential(options: CreateVaultOptions): Promise<VaultCredential>;
