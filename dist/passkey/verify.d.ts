/**
 * MACHINA Vault — Server-side verification (Cloudflare Workers compatible)
 *
 * Verifies WebAuthn registration and authentication responses using
 * @noble/curves for P-256 signature verification. No Node.js dependencies.
 */
import type { VaultCredential, VaultChallenge, AuthenticationResult } from "./types.js";
/**
 * Verify a WebAuthn registration response.
 *
 * Checks that the credential was created with the expected challenge and
 * origin. Should be called server-side after receiving the credential
 * from the browser.
 *
 * @param credential - The credential returned from createVaultCredential
 * @param challenge - The challenge that was issued for this registration
 * @param expectedOrigin - The expected origin (e.g. "https://machina.money")
 * @returns true if the registration is valid
 */
export declare function verifyRegistration(credential: VaultCredential, challenge: VaultChallenge, expectedOrigin: string): boolean;
/**
 * Verify a WebAuthn authentication response.
 *
 * Verifies the P-256 ECDSA signature over (authenticatorData || sha256(clientDataJSON))
 * using the stored public key. Also checks sign count for replay protection.
 *
 * @param auth - The authentication result from authenticateVault
 * @param storedCredential - The previously registered credential
 * @param challenge - The challenge that was issued for this authentication
 * @param expectedOrigin - The expected origin (e.g. "https://machina.money")
 * @returns true if the authentication is valid
 */
export declare function verifyAuthentication(auth: AuthenticationResult, storedCredential: VaultCredential, challenge: VaultChallenge, expectedOrigin: string): boolean;
