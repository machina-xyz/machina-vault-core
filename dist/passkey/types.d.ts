/**
 * MACHINA Vault — WebAuthn Passkey Types
 * MAC-896: WebAuthn Passkey Wallet Creation + Secure Enclave Key Storage
 */
export interface VaultCredential {
    /** base64url-encoded credential ID */
    credentialId: string;
    /** COSE-encoded P-256 public key */
    publicKey: Uint8Array;
    /** Raw X coordinate (32 bytes) */
    publicKeyX: Uint8Array;
    /** Raw Y coordinate (32 bytes) */
    publicKeyY: Uint8Array;
    /** Derived EVM address (0x-prefixed, EIP-55 checksummed) */
    vaultAddress: string;
    /** Whether the authenticator is platform-bound or roaming */
    attestationType: "platform" | "cross-platform";
    /** Whether the credential is backed by secure hardware */
    hardwareBacked: boolean;
    /** Relying party domain */
    rpId: string;
    /** ISO 8601 creation timestamp */
    createdAt: string;
    /** Monotonic sign counter for replay protection */
    signCount: number;
}
export interface CreateVaultOptions {
    /** Relying party domain, e.g. "machina.money" */
    rpId: string;
    /** Relying party display name, e.g. "MACHINA Vault" */
    rpName: string;
    /** User display name */
    userName: string;
    /** Unique user identifier */
    userId: string;
    /** Attestation conveyance preference */
    attestation?: AttestationConveyancePreference;
    /** Authenticator attachment constraint */
    authenticatorAttachment?: AuthenticatorAttachment;
    /** Whether to require a resident (discoverable) key */
    requireResidentKey?: boolean;
    /** Timeout in milliseconds (default: 300000 = 5 min) */
    timeout?: number;
}
export interface AuthenticateOptions {
    /** Relying party domain */
    rpId: string;
    /** base64url-encoded credential ID to authenticate with */
    credentialId: string;
    /** 32-byte random challenge */
    challenge: Uint8Array;
    /** Timeout in milliseconds (default: 300000 = 5 min) */
    timeout?: number;
}
export interface AuthenticationResult {
    /** base64url-encoded credential ID */
    credentialId: string;
    /** DER-encoded ECDSA signature */
    signature: Uint8Array;
    /** Raw authenticator data */
    authenticatorData: Uint8Array;
    /** Raw client data JSON */
    clientDataJSON: Uint8Array;
    /** Whether the authentication was verified */
    verified: boolean;
}
export interface VaultChallenge {
    /** 32-byte random challenge */
    challenge: Uint8Array;
    /** Creation timestamp in Unix milliseconds */
    createdAt: number;
    /** Expiration timestamp in Unix milliseconds (5 min TTL) */
    expiresAt: number;
    /** Whether this challenge has been consumed */
    used: boolean;
}
//# sourceMappingURL=types.d.ts.map