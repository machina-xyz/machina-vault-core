/**
 * MACHINA Vault — Encrypted Communication Channel
 *
 * Establishes encrypted channels between enclaves for MPC key exchange
 * and inter-enclave communication using standard ECDH + AES-256-GCM.
 *
 * Cloudflare Workers V8 compatible — crypto.subtle only, no Node.js APIs.
 */

import type { SecureChannel } from "./types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** HKDF info prefix for channel encryption key derivation */
const HKDF_ENC_INFO = "machina-channel-enc-v1";

/** HKDF info prefix for channel MAC key derivation */
const HKDF_MAC_INFO = "machina-channel-mac-v1";

/** AES-GCM nonce size in bytes */
const NONCE_SIZE = 12;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create a secure encrypted channel between two enclaves.
 *
 * Uses ECDH (P-256) key agreement to derive a shared secret, then HKDF
 * to produce AES-256-GCM encryption keys.
 *
 * @param ourKeyPair     - Our ECDH key pair (raw public + private bytes).
 * @param peerPublicKey  - Peer's raw public key bytes (uncompressed P-256).
 */
export async function createSecureChannel(
  ourKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array },
  peerPublicKey: Uint8Array,
): Promise<SecureChannel> {
  // Import our private key for ECDH
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    ourKeyPair.privateKey as BufferSource,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );

  // Import peer public key
  const peerKey = await crypto.subtle.importKey(
    "raw",
    peerPublicKey as BufferSource,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );

  // ECDH key agreement → raw shared secret (32 bytes for P-256)
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerKey },
    privateKey,
    256,
  );
  const sharedSecret = new Uint8Array(sharedBits);

  // Derive channel keys via HKDF
  const { encryptKey } = await deriveChannelKeys(sharedSecret, HKDF_ENC_INFO);

  return {
    async encrypt(plaintext: Uint8Array): Promise<{
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    }> {
      const nonce = new Uint8Array(NONCE_SIZE);
      crypto.getRandomValues(nonce);

      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce as BufferSource },
        encryptKey,
        plaintext as BufferSource,
      );

      return {
        ciphertext: new Uint8Array(ciphertext),
        nonce,
      };
    },

    async decrypt(
      ciphertext: Uint8Array,
      nonce: Uint8Array,
    ): Promise<Uint8Array> {
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce as BufferSource },
        encryptKey,
        ciphertext as BufferSource,
      );

      return new Uint8Array(plaintext);
    },

    getSharedSecret(): Uint8Array {
      // Return a copy to prevent mutation
      return new Uint8Array(sharedSecret);
    },
  };
}

/**
 * Derive encryption and MAC keys from a shared secret using HKDF-SHA256.
 *
 * @param sharedSecret - Raw shared secret bytes (e.g. from ECDH).
 * @param info         - Context string for HKDF key derivation.
 */
export async function deriveChannelKeys(
  sharedSecret: Uint8Array,
  info: string,
): Promise<{ encryptKey: CryptoKey; macKey: CryptoKey }> {
  // Import the shared secret as HKDF key material
  const baseKey = await crypto.subtle.importKey(
    "raw",
    sharedSecret as BufferSource,
    "HKDF",
    false,
    ["deriveKey"],
  );

  // Salt: all-zero (standard for ephemeral ECDH where pre-shared key isn't available)
  const salt = new Uint8Array(32);

  // Derive AES-256-GCM encryption key
  const encryptKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: new TextEncoder().encode(info) as BufferSource,
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  // Derive HMAC-SHA256 MAC key
  const macKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: new TextEncoder().encode(
        info === HKDF_ENC_INFO ? HKDF_MAC_INFO : info + "-mac",
      ) as BufferSource,
    },
    baseKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign", "verify"],
  );

  return { encryptKey, macKey };
}
