/**
 * MACHINA Vault — BIP-44 Key Derivation
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Uses @noble/curves and @noble/hashes exclusively (Cloudflare Workers compatible).
 * Implements simplified BIP-32 hardened-only derivation for secp256k1.
 */
/** BIP-44 coin types */
export declare const COIN_TYPE: {
    readonly EVM: 60;
    readonly SOLANA: 501;
    readonly SUI: 784;
};
/** Standard derivation paths (BIP-44) */
export declare const DERIVATION_PATHS: {
    /** EVM: m/44'/60'/0'/0/{index} */
    readonly evm: (index: number) => string;
    /** Solana: m/44'/501'/0'/0' */
    readonly solana: () => string;
    /** Sui: m/44'/784'/0'/0'/0' */
    readonly sui: () => string;
};
/** Operator keys live under account 1 */
export declare const OPERATOR_PATH: (index: number) => string;
/** Agent keys live under account 2 */
export declare const AGENT_PATH: (index: number) => string;
/**
 * Derive a 64-byte master seed from root entropy using HKDF-SHA256.
 * The root entropy typically comes from a passkey or secure random source.
 */
export declare function deriveMasterSeed(rootEntropy: Uint8Array): Uint8Array;
/**
 * Derive a secp256k1 key pair at the given BIP-44 hardened path.
 * Returns the raw 32-byte private key and 33-byte compressed public key.
 */
export declare function deriveKeyAtPath(masterSeed: Uint8Array, path: string): {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
};
/**
 * Derive an EVM address from a compressed secp256k1 public key.
 * address = "0x" + keccak256(uncompressedPublicKeyWithoutPrefix)[12:]
 */
export declare function publicKeyToEvmAddress(compressedPubKey: Uint8Array): string;
/**
 * Derive an operator key at the given index.
 * Path: m/44'/60'/1'/0'/{index}'
 */
export declare function deriveOperatorKey(masterSeed: Uint8Array, index: number): {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    address: string;
};
/**
 * Derive an agent key at the given index.
 * Path: m/44'/60'/2'/0'/{index}'
 */
export declare function deriveAgentKey(masterSeed: Uint8Array, index: number): {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    address: string;
};
/**
 * Generate an ephemeral session key (NOT derived from master seed).
 * Uses cryptographically secure random bytes.
 */
export declare function generateSessionKey(): {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    address: string;
};
