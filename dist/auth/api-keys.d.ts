/**
 * MACHINA Vault — API Key Management
 * Generate, validate, and manage "mach_" prefixed API keys.
 * Keys are hashed with SHA-256 before storage — raw keys are shown once.
 *
 * Cloudflare Workers V8 only — no Node.js APIs.
 */
import type { APIKeyCredential } from "./types.js";
/**
 * Generate a new API key.
 *
 * Returns both the credential (for database storage) and the raw key
 * (to show to the user once). The raw key is never stored — only its
 * SHA-256 hash is persisted.
 *
 * @param name   - Human-readable name for the key
 * @param scopes - Permission scopes granted to this key
 * @returns The credential for storage and the raw key to display once
 */
export declare function generateAPIKey(name: string, scopes: string[]): Promise<{
    credential: APIKeyCredential;
    rawKey: string;
}>;
/**
 * Validate a raw API key against a stored hash.
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param rawKey     - The raw API key ("mach_...")
 * @param storedHash - The hex-encoded SHA-256 hash from the database
 * @returns true if the key is valid
 */
export declare function validateAPIKey(rawKey: string, storedHash: string): Promise<boolean>;
/**
 * Parse a raw API key into its prefix and key bytes.
 *
 * @param rawKey - The raw API key string
 * @returns Parsed key components, or null if the format is invalid
 */
export declare function parseAPIKey(rawKey: string): {
    prefix: string;
    keyBytes: Uint8Array;
} | null;
/**
 * Check if an API key credential has a required scope.
 * Supports wildcard matching: "vault:*" matches "vault:read", "vault:write", etc.
 *
 * @param credential    - The API key credential
 * @param requiredScope - The scope to check for
 * @returns true if the credential has the required scope
 */
export declare function hasScope(credential: APIKeyCredential, requiredScope: string): boolean;
//# sourceMappingURL=api-keys.d.ts.map