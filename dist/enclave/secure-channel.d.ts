/**
 * MACHINA Vault — Encrypted Communication Channel
 *
 * Establishes encrypted channels between enclaves for MPC key exchange
 * and inter-enclave communication using standard ECDH + AES-256-GCM.
 *
 * Cloudflare Workers V8 compatible — crypto.subtle only, no Node.js APIs.
 */
import type { SecureChannel } from "./types.js";
/**
 * Create a secure encrypted channel between two enclaves.
 *
 * Uses ECDH (P-256) key agreement to derive a shared secret, then HKDF
 * to produce AES-256-GCM encryption keys.
 *
 * @param ourKeyPair     - Our ECDH key pair (raw public + private bytes).
 * @param peerPublicKey  - Peer's raw public key bytes (uncompressed P-256).
 */
export declare function createSecureChannel(ourKeyPair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}, peerPublicKey: Uint8Array): Promise<SecureChannel>;
/**
 * Derive encryption and MAC keys from a shared secret using HKDF-SHA256.
 *
 * @param sharedSecret - Raw shared secret bytes (e.g. from ECDH).
 * @param info         - Context string for HKDF key derivation.
 */
export declare function deriveChannelKeys(sharedSecret: Uint8Array, info: string): Promise<{
    encryptKey: CryptoKey;
    macKey: CryptoKey;
}>;
//# sourceMappingURL=secure-channel.d.ts.map