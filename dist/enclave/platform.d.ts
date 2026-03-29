/**
 * MACHINA Vault — Platform Detection
 *
 * Detects the current runtime environment and available secure enclave
 * capabilities. Safe across browser, Cloudflare Workers, mobile, and server.
 */
import type { EnclaveCapability, EnclavePlatform, SecurityLevel } from "./types.js";
/**
 * Detect the current runtime platform and its enclave capabilities.
 *
 * Checks in order:
 *   1. WebAuthn (browser with PublicKeyCredential)
 *   2. Cloudflare Workers (V8 isolate markers)
 *   3. TEE (TPM/SGX attestation APIs)
 *   4. Mobile biometric (native bridge)
 *   5. Software fallback
 */
export declare function detectPlatform(): EnclavePlatform;
/**
 * Get the security level for a platform.
 */
export declare function getSecurityLevel(platform: EnclavePlatform): SecurityLevel;
/**
 * Check whether the platform is backed by dedicated hardware security.
 * Only true for 'hardware' security level — firmware/software return false.
 */
export declare function isHardwareBacked(platform: EnclavePlatform): boolean;
/**
 * Check whether a platform supports a specific capability.
 */
export declare function platformSupportsCapability(platform: EnclavePlatform, capability: EnclaveCapability): boolean;
//# sourceMappingURL=platform.d.ts.map