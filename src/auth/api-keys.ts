/**
 * MACHINA Vault — API Key Management
 * Generate, validate, and manage "mach_" prefixed API keys.
 * Keys are hashed with SHA-256 before storage — raw keys are shown once.
 *
 * Cloudflare Workers V8 only — no Node.js APIs.
 */

import type { APIKeyCredential } from "./types.js";
import { base64urlEncode, base64urlDecode } from "./jwt.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** API key prefix for easy identification */
const API_KEY_PREFIX = "mach_";

/** Raw key length in bytes */
const KEY_LENGTH_BYTES = 32;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return new Uint8Array(hash);
}

function nowISO(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

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
export async function generateAPIKey(
  name: string,
  scopes: string[],
): Promise<{ credential: APIKeyCredential; rawKey: string }> {
  // Generate 32 random bytes
  const keyBytes = new Uint8Array(KEY_LENGTH_BYTES);
  crypto.getRandomValues(keyBytes);

  // Hash for storage
  const hash = await sha256(keyBytes);
  const keyHash = bytesToHex(hash);

  // Encode as "mach_" + base64url(bytes)
  const rawKey = API_KEY_PREFIX + base64urlEncode(keyBytes);

  const credential: APIKeyCredential = {
    keyId: generateId(),
    keyHash,
    name,
    scopes,
    createdAt: nowISO(),
  };

  return { credential, rawKey };
}

/**
 * Validate a raw API key against a stored hash.
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param rawKey     - The raw API key ("mach_...")
 * @param storedHash - The hex-encoded SHA-256 hash from the database
 * @returns true if the key is valid
 */
export async function validateAPIKey(
  rawKey: string,
  storedHash: string,
): Promise<boolean> {
  const parsed = parseAPIKey(rawKey);
  if (!parsed) {
    return false;
  }

  const hash = await sha256(parsed.keyBytes);
  const computedHex = bytesToHex(hash);

  // Constant-time comparison
  if (computedHex.length !== storedHash.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < computedHex.length; i++) {
    diff |= computedHex.charCodeAt(i) ^ storedHash.charCodeAt(i);
  }

  return diff === 0;
}

/**
 * Parse a raw API key into its prefix and key bytes.
 *
 * @param rawKey - The raw API key string
 * @returns Parsed key components, or null if the format is invalid
 */
export function parseAPIKey(
  rawKey: string,
): { prefix: string; keyBytes: Uint8Array } | null {
  if (!rawKey.startsWith(API_KEY_PREFIX)) {
    return null;
  }

  const encoded = rawKey.slice(API_KEY_PREFIX.length);
  if (!encoded) {
    return null;
  }

  try {
    const keyBytes = base64urlDecode(encoded);
    if (keyBytes.length !== KEY_LENGTH_BYTES) {
      return null;
    }
    return { prefix: API_KEY_PREFIX, keyBytes };
  } catch {
    return null;
  }
}

/**
 * Check if an API key credential has a required scope.
 * Supports wildcard matching: "vault:*" matches "vault:read", "vault:write", etc.
 *
 * @param credential    - The API key credential
 * @param requiredScope - The scope to check for
 * @returns true if the credential has the required scope
 */
export function hasScope(
  credential: APIKeyCredential,
  requiredScope: string,
): boolean {
  for (const scope of credential.scopes) {
    // Exact match
    if (scope === requiredScope) {
      return true;
    }

    // Wildcard match: "vault:*" matches "vault:read"
    if (scope.endsWith(":*")) {
      const prefix = scope.slice(0, -1); // "vault:"
      if (requiredScope.startsWith(prefix)) {
        return true;
      }
    }
  }

  return false;
}
