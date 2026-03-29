/**
 * MACHINA Vault — Enclave Types
 *
 * Type definitions for platform detection, secure key storage abstraction,
 * and attestation across TEE/secure enclave environments.
 */
/** Supported enclave/secure element types */
export type EnclaveType = "webauthn" | "cloudflare" | "tee" | "hsm" | "software" | "mobile_biometric";
/** Security assurance level of the enclave */
export type SecurityLevel = "hardware" | "firmware" | "software" | "unknown";
/** Capabilities a given enclave platform may support */
export type EnclaveCapability = "key_generation" | "signing" | "encryption" | "attestation" | "secure_storage" | "biometric";
/** Describes the detected platform and its capabilities */
export interface EnclavePlatform {
    /** Enclave type identifier */
    type: EnclaveType;
    /** Human-readable platform name */
    name: string;
    /** Security assurance level */
    securityLevel: SecurityLevel;
    /** Available capabilities on this platform */
    capabilities: EnclaveCapability[];
}
/** An entry in the key store registry */
export interface KeyStoreEntry {
    /** Unique key identifier (UUID) */
    keyId: string;
    /** Algorithm used (e.g. "ECDSA-P256", "AES-256-GCM") */
    algorithm: string;
    /** Whether the key material can be exported */
    extractable: boolean;
    /** Permitted key usages */
    usages: string[];
    /** ISO 8601 creation timestamp */
    createdAt: string;
    /** Optional key metadata */
    metadata?: Record<string, string>;
}
/** Remote attestation evidence from an enclave */
export interface AttestationReport {
    /** Platform that produced the attestation */
    platform: EnclaveType;
    /** Attestation evidence (hex-encoded) */
    evidence: string;
    /** ISO 8601 timestamp when attestation was generated */
    timestamp: string;
    /** Challenge nonce (hex-encoded) */
    nonce: string;
    /** Optional certificate chain for hardware attestation */
    certChain?: string[];
    /** Optional platform measurements (e.g. PCR values, MR_ENCLAVE) */
    measurements?: Record<string, string>;
}
/** Result of verifying an attestation report */
export interface AttestationVerification {
    /** Whether the attestation is valid */
    valid: boolean;
    /** Platform that produced the attestation */
    platform: EnclaveType;
    /** Security level of the attesting platform */
    securityLevel: SecurityLevel;
    /** ISO 8601 timestamp when trust was established */
    trustedAt?: string;
    /** Error message if verification failed */
    error?: string;
}
/** Configuration for enclave initialization */
export interface EnclaveConfig {
    /** Preferred enclave type; auto-detected if not specified */
    preferredType?: EnclaveType;
    /** Allow fallback to software-based enclave (default: true) */
    allowSoftwareFallback: boolean;
    /** Require attestation before key operations (default: false) */
    attestationRequired: boolean;
    /** Whether generated keys should be exportable (default: false) */
    keyExportable: boolean;
}
/** Result of a key store operation */
export interface SecureStoreResult {
    /** Whether the operation succeeded */
    success: boolean;
    /** Key identifier (present on success) */
    keyId?: string;
    /** Error message (present on failure) */
    error?: string;
}
/** Interface for platform-specific key store implementations */
export interface KeyStore {
    /** Generate a new key pair */
    generateKey(algorithm: string, extractable: boolean): Promise<SecureStoreResult>;
    /** Import key material */
    importKey(keyData: Uint8Array, algorithm: string): Promise<SecureStoreResult>;
    /** Sign data using a stored key */
    sign(keyId: string, data: Uint8Array): Promise<Uint8Array>;
    /** Export a stored key's public component */
    getPublicKey(keyId: string): Promise<Uint8Array | null>;
    /** Remove a key from storage */
    deleteKey(keyId: string): Promise<boolean>;
    /** List all stored keys */
    listKeys(): KeyStoreEntry[];
}
/** Encrypted channel for inter-enclave communication */
export interface SecureChannel {
    /** Encrypt a plaintext message */
    encrypt(plaintext: Uint8Array): Promise<{
        ciphertext: Uint8Array;
        nonce: Uint8Array;
    }>;
    /** Decrypt a ciphertext message */
    decrypt(ciphertext: Uint8Array, nonce: Uint8Array): Promise<Uint8Array>;
    /** Get the derived shared secret */
    getSharedSecret(): Uint8Array;
}
//# sourceMappingURL=types.d.ts.map