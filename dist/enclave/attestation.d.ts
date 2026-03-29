/**
 * MACHINA Vault — Remote Attestation
 *
 * Generate and verify attestation reports proving code runs in a secure
 * enclave. Honest about security levels — software attestation is clearly
 * marked as low trust.
 *
 * Cloudflare Workers V8 compatible — no Node.js APIs.
 */
import type { AttestationReport, AttestationVerification, EnclavePlatform } from "./types.js";
/**
 * Generate an attestation report for the current platform.
 *
 * - **webauthn**: Returns authenticator attestation from credential creation.
 * - **cloudflare**: Signs nonce with a platform-derived HMAC key.
 * - **tee**: Returns a pending stub — real TEE attestation requires vendor SDK.
 * - **software**: Returns self-attestation (clearly marked as low trust).
 */
export declare function generateAttestation(platform: EnclavePlatform, nonce: Uint8Array): Promise<AttestationReport>;
/**
 * Verify an attestation report.
 *
 * - **webauthn**: Verifies attestation statement structure and signature.
 * - **cloudflare**: Verifies HMAC signature over the nonce.
 * - **tee**: Returns not-implemented (requires vendor verification).
 * - **software**: Accepted but marked as low trust.
 */
export declare function verifyAttestation(report: AttestationReport): Promise<AttestationVerification>;
/**
 * Create a fresh attestation challenge with nonce and expiry.
 */
export declare function createAttestationChallenge(): {
    nonce: string;
    expiresAt: string;
};
/**
 * Check whether an attestation report is within the acceptable freshness
 * window.
 *
 * @param report  - The attestation report to check.
 * @param maxAgeMs - Maximum acceptable age in milliseconds (default: 5 min).
 */
export declare function isAttestationFresh(report: AttestationReport, maxAgeMs?: number): boolean;
//# sourceMappingURL=attestation.d.ts.map