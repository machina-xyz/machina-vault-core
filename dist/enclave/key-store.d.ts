/**
 * MACHINA Vault — Secure Key Storage Abstraction
 *
 * Platform-aware key store that wraps Web Crypto / WebAuthn / native
 * biometric APIs behind a unified interface. Key material never leaves
 * the enclave in plaintext.
 *
 * Cloudflare Workers V8 compatible — no Node.js APIs.
 */
import type { EnclavePlatform, KeyStore } from "./types.js";
/**
 * Create a platform-aware key store.
 *
 * - **webauthn**: Uses `navigator.credentials.create` for P-256 key generation.
 *   Signing requires user interaction via `navigator.credentials.get`.
 * - **cloudflare / software**: Uses `crypto.subtle` for all operations.
 * - **mobile_biometric**: Delegates to the native bridge if available, falls
 *   back to `crypto.subtle`.
 */
export declare function createKeyStore(platform: EnclavePlatform): KeyStore;
//# sourceMappingURL=key-store.d.ts.map