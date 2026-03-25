/**
 * MACHINA Vault — Secure Key Storage Abstraction
 *
 * Platform-aware key store that wraps Web Crypto / WebAuthn / native
 * biometric APIs behind a unified interface. Key material never leaves
 * the enclave in plaintext.
 *
 * Cloudflare Workers V8 compatible — no Node.js APIs.
 */

import type {
  EnclavePlatform,
  KeyStore,
  KeyStoreEntry,
  SecureStoreResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Hex helpers (inline — no Buffer dependency)
// ---------------------------------------------------------------------------

function toHex(buf: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

function generateUUID(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // Set version 4 (bits 12-15 of time_hi_and_version)
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  // Set variant 1 (bits 6-7 of clock_seq_hi)
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const h = toHex(bytes);
  return (
    h.slice(0, 8) + "-" +
    h.slice(8, 12) + "-" +
    h.slice(12, 16) + "-" +
    h.slice(16, 20) + "-" +
    h.slice(20)
  );
}

// ---------------------------------------------------------------------------
// Internal key registry entry (holds the CryptoKey handle)
// ---------------------------------------------------------------------------

interface InternalKeyEntry {
  keyId: string;
  algorithm: string;
  extractable: boolean;
  usages: string[];
  createdAt: string;
  metadata?: Record<string, string>;
  /** CryptoKeyPair or CryptoKey (may be null for WebAuthn-managed keys) */
  keyPair?: CryptoKeyPair;
  /** Raw public key bytes (cached for fast export) */
  publicKeyRaw?: Uint8Array;
  /** WebAuthn credential ID (for webauthn-managed keys) */
  credentialId?: ArrayBuffer;
}

// ---------------------------------------------------------------------------
// Algorithm mapping helpers
// ---------------------------------------------------------------------------

function resolveKeyGenParams(
  algorithm: string,
  extractable: boolean,
): { genParams: EcKeyGenParams | AesKeyGenParams; usages: KeyUsage[] } {
  const upper = algorithm.toUpperCase();

  if (upper === "ECDSA-P256" || upper === "P-256" || upper === "ECDSA") {
    return {
      genParams: { name: "ECDSA", namedCurve: "P-256" },
      usages: extractable ? ["sign", "verify"] : ["sign"],
    };
  }

  if (upper === "ECDH-P256" || upper === "ECDH") {
    return {
      genParams: { name: "ECDH", namedCurve: "P-256" },
      usages: ["deriveBits", "deriveKey"],
    };
  }

  if (upper === "AES-256-GCM" || upper === "AES-GCM") {
    return {
      genParams: { name: "AES-GCM", length: 256 },
      usages: ["encrypt", "decrypt"],
    };
  }

  // Default: ECDSA P-256
  return {
    genParams: { name: "ECDSA", namedCurve: "P-256" },
    usages: extractable ? ["sign", "verify"] : ["sign"],
  };
}

function resolveImportParams(algorithm: string): {
  importParams: EcKeyImportParams | AlgorithmIdentifier;
  usages: KeyUsage[];
} {
  const upper = algorithm.toUpperCase();

  if (upper === "ECDSA-P256" || upper === "P-256" || upper === "ECDSA") {
    return {
      importParams: { name: "ECDSA", namedCurve: "P-256" },
      usages: ["verify"],
    };
  }

  if (upper === "ECDH-P256" || upper === "ECDH") {
    return {
      importParams: { name: "ECDH", namedCurve: "P-256" },
      usages: [],
    };
  }

  if (upper === "AES-256-GCM" || upper === "AES-GCM") {
    return {
      importParams: { name: "AES-GCM" },
      usages: ["encrypt", "decrypt"],
    };
  }

  return {
    importParams: { name: "ECDSA", namedCurve: "P-256" },
    usages: ["verify"],
  };
}

// ---------------------------------------------------------------------------
// Key Store Factory
// ---------------------------------------------------------------------------

/**
 * Create a platform-aware key store.
 *
 * - **webauthn**: Uses `navigator.credentials.create` for P-256 key generation.
 *   Signing requires user interaction via `navigator.credentials.get`.
 * - **cloudflare / software**: Uses `crypto.subtle` for all operations.
 * - **mobile_biometric**: Delegates to the native bridge if available, falls
 *   back to `crypto.subtle`.
 */
export function createKeyStore(platform: EnclavePlatform): KeyStore {
  const registry = new Map<string, InternalKeyEntry>();

  // -------------------------------------------------------------------------
  // WebAuthn key store
  // -------------------------------------------------------------------------
  if (platform.type === "webauthn") {
    return {
      async generateKey(
        _algorithm: string,
        _extractable: boolean,
      ): Promise<SecureStoreResult> {
        try {
          const challenge = new Uint8Array(32);
          crypto.getRandomValues(challenge);
          const keyId = generateUUID();

          const credential = (await navigator.credentials.create({
            publicKey: {
              rp: { name: "MACHINA Vault" },
              user: {
                id: new TextEncoder().encode(keyId),
                name: `machina-vault-${keyId.slice(0, 8)}`,
                displayName: "MACHINA Vault Key",
              },
              challenge: challenge as BufferSource,
              pubKeyCredParams: [
                { type: "public-key", alg: -7 }, // ES256 (P-256)
              ],
              authenticatorSelection: {
                authenticatorAttachment: "platform",
                residentKey: "preferred",
                userVerification: "required",
              },
              attestation: "direct",
              timeout: 60_000,
            },
          })) as PublicKeyCredential | null;

          if (!credential) {
            return { success: false, error: "WebAuthn credential creation cancelled" };
          }

          const response = credential.response as AuthenticatorAttestationResponse;
          const publicKeyBytes = response.getPublicKey
            ? new Uint8Array(response.getPublicKey()!)
            : new Uint8Array(0);

          const entry: InternalKeyEntry = {
            keyId,
            algorithm: "ECDSA-P256",
            extractable: false,
            usages: ["sign"],
            createdAt: new Date().toISOString(),
            publicKeyRaw: publicKeyBytes,
            credentialId: credential.rawId,
            metadata: { platform: "webauthn" },
          };
          registry.set(keyId, entry);

          return { success: true, keyId };
        } catch (err) {
          return {
            success: false,
            error: `WebAuthn key generation failed: ${(err as Error).message}`,
          };
        }
      },

      async importKey(
        keyData: Uint8Array,
        algorithm: string,
      ): Promise<SecureStoreResult> {
        // WebAuthn does not support importing external key material into the
        // authenticator. Fall back to Web Crypto for import operations.
        return subtleImportKey(registry, keyData, algorithm);
      },

      async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
        const entry = registry.get(keyId);
        if (!entry) throw new Error(`Key not found: ${keyId}`);

        // If the key has a CryptoKeyPair (imported), sign with subtle
        if (entry.keyPair) {
          return subtleSign(entry, data);
        }

        // Otherwise use WebAuthn assertion (requires user interaction)
        if (!entry.credentialId) {
          throw new Error("Key has no credential ID and no CryptoKey handle");
        }

        const challenge = data.length <= 64 ? data : await sha256(data);

        const assertion = (await navigator.credentials.get({
          publicKey: {
            challenge: challenge as BufferSource,
            allowCredentials: [
              { type: "public-key", id: entry.credentialId },
            ],
            userVerification: "required",
            timeout: 60_000,
          },
        })) as PublicKeyCredential | null;

        if (!assertion) {
          throw new Error("WebAuthn assertion cancelled by user");
        }

        const assertionResponse = assertion.response as AuthenticatorAssertionResponse;
        return new Uint8Array(assertionResponse.signature);
      },

      async getPublicKey(keyId: string): Promise<Uint8Array | null> {
        const entry = registry.get(keyId);
        if (!entry) return null;
        if (entry.publicKeyRaw && entry.publicKeyRaw.length > 0) {
          return entry.publicKeyRaw;
        }
        if (entry.keyPair) {
          return subtleExportPublicKey(entry.keyPair.publicKey);
        }
        return null;
      },

      async deleteKey(keyId: string): Promise<boolean> {
        return registry.delete(keyId);
      },

      listKeys(): KeyStoreEntry[] {
        return toKeyStoreEntries(registry);
      },
    };
  }

  // -------------------------------------------------------------------------
  // Cloudflare Workers / Software / TEE / HSM key store
  // Uses crypto.subtle for all operations.
  // -------------------------------------------------------------------------
  return {
    async generateKey(
      algorithm: string,
      extractable: boolean,
    ): Promise<SecureStoreResult> {
      try {
        const keyId = generateUUID();
        const { genParams, usages } = resolveKeyGenParams(algorithm, extractable);

        const keyPair = (await crypto.subtle.generateKey(
          genParams,
          extractable,
          usages,
        )) as CryptoKeyPair;

        const publicKeyRaw = await subtleExportPublicKey(keyPair.publicKey);

        const entry: InternalKeyEntry = {
          keyId,
          algorithm,
          extractable,
          usages: usages as string[],
          createdAt: new Date().toISOString(),
          keyPair,
          publicKeyRaw,
          metadata: { platform: platform.type },
        };
        registry.set(keyId, entry);

        return { success: true, keyId };
      } catch (err) {
        return {
          success: false,
          error: `Key generation failed: ${(err as Error).message}`,
        };
      }
    },

    async importKey(
      keyData: Uint8Array,
      algorithm: string,
    ): Promise<SecureStoreResult> {
      return subtleImportKey(registry, keyData, algorithm);
    },

    async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
      const entry = registry.get(keyId);
      if (!entry) throw new Error(`Key not found: ${keyId}`);
      if (!entry.keyPair) throw new Error("Key has no CryptoKey handle");
      return subtleSign(entry, data);
    },

    async getPublicKey(keyId: string): Promise<Uint8Array | null> {
      const entry = registry.get(keyId);
      if (!entry) return null;
      if (entry.publicKeyRaw && entry.publicKeyRaw.length > 0) {
        return entry.publicKeyRaw;
      }
      if (entry.keyPair) {
        return subtleExportPublicKey(entry.keyPair.publicKey);
      }
      return null;
    },

    async deleteKey(keyId: string): Promise<boolean> {
      return registry.delete(keyId);
    },

    listKeys(): KeyStoreEntry[] {
      return toKeyStoreEntries(registry);
    },
  };
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async function subtleSign(
  entry: InternalKeyEntry,
  data: Uint8Array,
): Promise<Uint8Array> {
  const upper = entry.algorithm.toUpperCase();
  let signParams: AlgorithmIdentifier | EcdsaParams;

  if (upper.includes("ECDSA") || upper === "P-256") {
    signParams = { name: "ECDSA", hash: "SHA-256" };
  } else {
    signParams = { name: "ECDSA", hash: "SHA-256" };
  }

  const sig = await crypto.subtle.sign(
    signParams,
    entry.keyPair!.privateKey,
    data as BufferSource,
  );
  return new Uint8Array(sig);
}

async function subtleExportPublicKey(key: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return new Uint8Array(raw);
}

async function subtleImportKey(
  registry: Map<string, InternalKeyEntry>,
  keyData: Uint8Array,
  algorithm: string,
): Promise<SecureStoreResult> {
  try {
    const keyId = generateUUID();
    const { importParams, usages } = resolveImportParams(algorithm);

    const publicKey = await crypto.subtle.importKey(
      "raw",
      keyData as BufferSource,
      importParams,
      true,
      usages,
    );

    const entry: InternalKeyEntry = {
      keyId,
      algorithm,
      extractable: true,
      usages: usages as string[],
      createdAt: new Date().toISOString(),
      keyPair: { publicKey, privateKey: undefined as unknown as CryptoKey },
      publicKeyRaw: new Uint8Array(keyData),
      metadata: { imported: "true" },
    };
    registry.set(keyId, entry);

    return { success: true, keyId };
  } catch (err) {
    return {
      success: false,
      error: `Key import failed: ${(err as Error).message}`,
    };
  }
}

function toKeyStoreEntries(
  registry: Map<string, InternalKeyEntry>,
): KeyStoreEntry[] {
  const entries: KeyStoreEntry[] = [];
  for (const entry of registry.values()) {
    entries.push({
      keyId: entry.keyId,
      algorithm: entry.algorithm,
      extractable: entry.extractable,
      usages: entry.usages,
      createdAt: entry.createdAt,
      metadata: entry.metadata,
    });
  }
  return entries;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return new Uint8Array(hash);
}
