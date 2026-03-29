/**
 * MACHINA Vault — Open Wallet Standard (OWS) Compatibility Layer
 * MAC-962: Read OWS vault files and wrap OWS signing with MACHINA's policy engine.
 *
 * OWS uses Ethereum Keystore v3 format (AES-256-GCM, scrypt KDF).
 * This layer provides: vault reading, address derivation, MACHINA import,
 * and policy-wrapped signing on top of OWS keys.
 *
 * NOTE: This module is Node.js-only (not Workers-compatible). It requires
 * @types/node in devDependencies for type-checking.
 */
import type { VaultKey } from "../keys/types.js";
import type { PolicyRule } from "../policy/types.js";
export interface OwsWallet {
    /** Wallet name from OWS metadata */
    name: string;
    /** chain (CAIP-2) -> address (CAIP-10 format) */
    addresses: Record<string, string>;
    /** Supported chain identifiers (CAIP-2) */
    chains: string[];
    /** ISO 8601 creation timestamp */
    createdAt: string;
    /** Decrypted mnemonic (held in memory only, never persisted by MACHINA) */
    mnemonic: string;
}
export interface OwsVaultInfo {
    /** Wallet name */
    name: string;
    /** Absolute path to the wallet directory */
    path: string;
    /** Supported chain identifiers */
    chains: string[];
    /** ISO 8601 creation timestamp */
    createdAt: string;
}
export interface PolicyWrappedSigner {
    /** Sign a message after MACHINA policy evaluation passes */
    sign(chainId: string, message: Uint8Array): Promise<{
        signature: Uint8Array;
        publicKey: string;
    }>;
    /** Get the address for a specific chain */
    getAddress(chainId: string): string;
}
/**
 * Read and decrypt an OWS vault, returning a fully-hydrated OwsWallet.
 *
 * Steps:
 *  1. Parse keystore.json and decrypt the mnemonic via scrypt + AES-256-GCM.
 *  2. Parse config.json for chain configs and derivation paths.
 *  3. Derive addresses for each configured chain using BIP-44 paths.
 *  4. Parse metadata.json for wallet name and creation timestamp.
 */
export declare function readOwsVault(vaultPath: string, password: string): OwsWallet;
/**
 * List all OWS vaults found in the standard OWS directory.
 * Scans ~/.ows/wallets/ (or a custom basePath) and reads metadata.json from
 * each subdirectory.
 */
export declare function listOwsVaults(basePath?: string): OwsVaultInfo[];
/**
 * Import an OWS wallet into MACHINA's key hierarchy as an agent-tier VaultKey.
 *
 * The OWS wallet's primary EVM address becomes the VaultKey's address. The key
 * is scoped to the chains the OWS wallet supports, and a placeholder public key
 * is derived from the mnemonic.
 */
export declare function importOwsToMachina(owsWallet: OwsWallet, machinaAgentId: string): VaultKey;
/**
 * Wrap an OWS wallet with MACHINA's policy engine so that every signing
 * request is evaluated against the provided policy rules before the
 * underlying OWS key material is used.
 *
 * Returns a PolicyWrappedSigner compatible with MACHINA's signing pipeline.
 */
export declare function wrapOwsSigning(owsWallet: OwsWallet, policyRules: PolicyRule[]): PolicyWrappedSigner;
//# sourceMappingURL=index.d.ts.map