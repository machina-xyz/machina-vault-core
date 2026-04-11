/**
 * MACHINA Vault — WebAuthn credential assertion (browser-side)
 *
 * Initiates a WebAuthn authentication ceremony to sign a challenge
 * using a previously registered passkey credential.
 */
import type { AuthenticateOptions, AuthenticationResult } from "./types.js";
/**
 * Authenticate using an existing WebAuthn credential.
 *
 * Must be called in a browser context with access to `navigator.credentials`.
 *
 * @param options - Authentication parameters including rpId, credentialId, and challenge
 * @returns The authentication result with signature and authenticator data
 * @throws If the WebAuthn API is unavailable or the user cancels
 */
export declare function authenticateVault(options: AuthenticateOptions): Promise<AuthenticationResult>;
