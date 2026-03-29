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
/// <reference types="node" />
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import { PolicyEngine } from "../policy/engine.js";
// ---------------------------------------------------------------------------
// Constants — BIP-44 derivation paths per chain family
// ---------------------------------------------------------------------------
const DEFAULT_DERIVATION_PATHS = {
    evm: "m/44'/60'/0'/0/0",
    solana: "m/44'/501'/0'/0'",
    bitcoin: "m/84'/0'/0'/0/0",
    sui: "m/44'/784'/0'/0'/0'",
};
// ---------------------------------------------------------------------------
// OWS Vault Reader
// ---------------------------------------------------------------------------
/**
 * Read and decrypt an OWS vault, returning a fully-hydrated OwsWallet.
 *
 * Steps:
 *  1. Parse keystore.json and decrypt the mnemonic via scrypt + AES-256-GCM.
 *  2. Parse config.json for chain configs and derivation paths.
 *  3. Derive addresses for each configured chain using BIP-44 paths.
 *  4. Parse metadata.json for wallet name and creation timestamp.
 */
export function readOwsVault(vaultPath, password) {
    // --- Read raw files ---
    const keystorePath = path.join(vaultPath, "keystore.json");
    const configPath = path.join(vaultPath, "config.json");
    const metadataPath = path.join(vaultPath, "metadata.json");
    if (!fs.existsSync(keystorePath)) {
        throw new Error(`OWS keystore not found: ${keystorePath}`);
    }
    const keystore = JSON.parse(fs.readFileSync(keystorePath, "utf-8"));
    if (keystore.version !== 3) {
        throw new Error(`Unsupported OWS keystore version: ${keystore.version} (expected 3)`);
    }
    const config = fs.existsSync(configPath)
        ? JSON.parse(fs.readFileSync(configPath, "utf-8"))
        : { chains: [{ chainId: "eip155:1", family: "evm" }] };
    const metadata = fs.existsSync(metadataPath)
        ? JSON.parse(fs.readFileSync(metadataPath, "utf-8"))
        : { name: path.basename(vaultPath), createdAt: new Date().toISOString(), chains: [] };
    // --- Decrypt mnemonic ---
    const mnemonic = decryptKeystore(keystore, password);
    // --- Derive addresses per chain ---
    const addresses = {};
    const chains = [];
    for (const chain of config.chains) {
        const derivationPath = chain.derivationPath ?? DEFAULT_DERIVATION_PATHS[chain.family] ?? DEFAULT_DERIVATION_PATHS["evm"];
        const address = deriveAddress(mnemonic, derivationPath, chain.family);
        // Store in CAIP-10 format: <chain_id>:<address>
        addresses[chain.chainId] = `${chain.chainId}:${address}`;
        chains.push(chain.chainId);
    }
    return {
        name: metadata.name,
        addresses,
        chains,
        createdAt: metadata.createdAt,
        mnemonic,
    };
}
/**
 * List all OWS vaults found in the standard OWS directory.
 * Scans ~/.ows/wallets/ (or a custom basePath) and reads metadata.json from
 * each subdirectory.
 */
export function listOwsVaults(basePath) {
    const walletsDir = basePath ?? path.join(os.homedir(), ".ows", "wallets");
    if (!fs.existsSync(walletsDir)) {
        return [];
    }
    const entries = fs.readdirSync(walletsDir, { withFileTypes: true });
    const vaults = [];
    for (const entry of entries) {
        if (!entry.isDirectory())
            continue;
        const walletDir = path.join(walletsDir, entry.name);
        const metadataPath = path.join(walletDir, "metadata.json");
        const keystorePath = path.join(walletDir, "keystore.json");
        // Must have at least a keystore.json to be a valid vault
        if (!fs.existsSync(keystorePath))
            continue;
        let metadata;
        if (fs.existsSync(metadataPath)) {
            metadata = JSON.parse(fs.readFileSync(metadataPath, "utf-8"));
        }
        else {
            // Fallback: derive name from directory, no chain info
            metadata = {
                name: entry.name,
                createdAt: new Date().toISOString(),
                chains: [],
            };
        }
        vaults.push({
            name: metadata.name,
            path: walletDir,
            chains: metadata.chains,
            createdAt: metadata.createdAt,
        });
    }
    return vaults;
}
// ---------------------------------------------------------------------------
// MACHINA Integration
// ---------------------------------------------------------------------------
/**
 * Import an OWS wallet into MACHINA's key hierarchy as an agent-tier VaultKey.
 *
 * The OWS wallet's primary EVM address becomes the VaultKey's address. The key
 * is scoped to the chains the OWS wallet supports, and a placeholder public key
 * is derived from the mnemonic.
 */
export function importOwsToMachina(owsWallet, machinaAgentId) {
    const keyId = `ows-${owsWallet.name}-${Date.now()}`;
    // Use the first available address as the primary
    const primaryChain = owsWallet.chains[0];
    const primaryCaip10 = owsWallet.addresses[primaryChain] ?? "";
    // CAIP-10 format is "chainId:address" — extract the address portion
    const primaryAddress = primaryCaip10.includes(":")
        ? primaryCaip10.split(":").slice(-1)[0]
        : primaryCaip10;
    // Derive a deterministic public key placeholder from the mnemonic hash
    // (real implementation would use BIP-32 derivation)
    const publicKeyHash = crypto
        .createHash("sha256")
        .update(owsWallet.mnemonic)
        .digest();
    const publicKey = new Uint8Array(publicKeyHash.subarray(0, 33));
    const now = new Date().toISOString();
    const today = now.slice(0, 10);
    const month = now.slice(0, 7);
    const scope = {
        allowedChains: owsWallet.chains,
        allowedContracts: [],
        allowedFunctions: [],
        spendingLimits: [],
        expiry: null,
        autoRotateInterval: null,
    };
    const permissions = {
        // Agent tier: sign transactions, view balances
        mask: (1n << 6n) | (1n << 8n), // SIGN_TRANSACTION | VIEW_BALANCES
    };
    const vaultKey = {
        id: keyId,
        vaultId: machinaAgentId,
        tier: "agent",
        name: `OWS Import: ${owsWallet.name}`,
        publicKey,
        address: primaryAddress,
        parentKeyId: null, // Set by caller when attaching to key hierarchy
        permissions,
        scope,
        status: "active",
        signCount: 0,
        createdAt: now,
        expiresAt: null,
        revokedAt: null,
        lastUsedAt: null,
        spentToday: {},
        spentThisMonth: {},
        lastResetDay: today,
        lastResetMonth: month,
    };
    return vaultKey;
}
/**
 * Wrap an OWS wallet with MACHINA's policy engine so that every signing
 * request is evaluated against the provided policy rules before the
 * underlying OWS key material is used.
 *
 * Returns a PolicyWrappedSigner compatible with MACHINA's signing pipeline.
 */
export function wrapOwsSigning(owsWallet, policyRules) {
    const engine = new PolicyEngine(policyRules);
    return {
        sign: async (chainId, message) => {
            // --- Policy evaluation ---
            const evalRequest = {
                keyId: `ows-${owsWallet.name}`,
                keyTier: "agent",
                vaultId: `ows-vault-${owsWallet.name}`,
                chain: chainId,
                to: "", // Raw message signing — no specific recipient
                value: 0n,
                valueUsd: 0,
                timestamp: Date.now(),
            };
            const policyContext = {
                recentTxCount: 0,
                lastTxTimestamp: null,
                dailySpendUsd: 0,
                monthlySpendUsd: 0,
            };
            const result = engine.evaluate(evalRequest, policyContext);
            if (!result.allowed) {
                const reasons = result.matchedRules
                    .map((r) => `[${r.action}] ${r.ruleName}: ${r.reason}`)
                    .join("; ");
                throw new Error(`MACHINA policy denied OWS signing on chain ${chainId}: ${reasons || result.action}`);
            }
            // --- Sign using OWS key material ---
            const derivationPath = getDerivationPathForChain(chainId) ?? DEFAULT_DERIVATION_PATHS["evm"];
            const { privateKey, publicKey } = deriveKeyPair(owsWallet.mnemonic, derivationPath);
            const signature = signMessage(privateKey, message);
            return {
                signature,
                publicKey: Buffer.from(publicKey).toString("hex"),
            };
        },
        getAddress: (chainId) => {
            const caip10 = owsWallet.addresses[chainId];
            if (!caip10) {
                throw new Error(`OWS wallet "${owsWallet.name}" has no address for chain: ${chainId}`);
            }
            // Return the address portion of CAIP-10
            return caip10.includes(":") ? caip10.split(":").slice(-1)[0] : caip10;
        },
    };
}
// ---------------------------------------------------------------------------
// Crypto Helpers (Node.js native crypto + placeholder HD derivation)
// ---------------------------------------------------------------------------
/**
 * Decrypt an Ethereum Keystore v3 encrypted mnemonic.
 * Supports scrypt KDF with AES-256-GCM cipher.
 */
function decryptKeystore(keystore, password) {
    const { crypto: ks } = keystore;
    const salt = Buffer.from(ks.kdfparams.salt, "hex");
    const iv = Buffer.from(ks.cipherparams.iv, "hex");
    const ciphertext = Buffer.from(ks.ciphertext, "hex");
    // Derive decryption key via scrypt
    let derivedKey;
    if (ks.kdf === "scrypt") {
        const n = ks.kdfparams.n ?? 262144;
        const r = ks.kdfparams.r ?? 8;
        const p = ks.kdfparams.p ?? 1;
        derivedKey = crypto.scryptSync(password, salt, ks.kdfparams.dklen, {
            N: n,
            r,
            p,
            maxmem: 256 * 1024 * 1024,
        });
    }
    else if (ks.kdf === "pbkdf2") {
        const c = ks.kdfparams.c ?? 262144;
        const prf = ks.kdfparams.prf ?? "hmac-sha256";
        const digest = prf.replace("hmac-", "");
        derivedKey = crypto.pbkdf2Sync(password, salt, c, ks.kdfparams.dklen, digest);
    }
    else {
        throw new Error(`Unsupported KDF: ${ks.kdf}`);
    }
    // Verify MAC: keccak256(derivedKey[16..32] + ciphertext)
    // OWS uses SHA-256 MAC for broader compatibility
    const macInput = Buffer.concat([derivedKey.subarray(16, 32), ciphertext]);
    const computedMac = crypto.createHash("sha256").update(macInput).digest("hex");
    if (computedMac !== ks.mac) {
        throw new Error("OWS keystore decryption failed: invalid password or corrupted keystore");
    }
    // Decrypt
    const encryptionKey = derivedKey.subarray(0, 32);
    if (ks.cipher === "aes-256-gcm") {
        // For GCM, last 16 bytes of ciphertext are the auth tag
        const authTagLength = 16;
        const actualCiphertext = ciphertext.subarray(0, ciphertext.length - authTagLength);
        const authTag = ciphertext.subarray(ciphertext.length - authTagLength);
        const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([
            decipher.update(actualCiphertext),
            decipher.final(),
        ]);
        return decrypted.toString("utf-8");
    }
    // Fallback: aes-128-ctr (standard Ethereum Keystore v3)
    const decipher = crypto.createDecipheriv("aes-128-ctr", encryptionKey.subarray(0, 16), iv);
    const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]);
    return decrypted.toString("utf-8");
}
/**
 * Derive an address from a mnemonic for a given chain family.
 *
 * NOTE: Full BIP-32/BIP-39 HD derivation requires a dedicated library
 * (e.g. @scure/bip32, @scure/bip39). This placeholder uses deterministic
 * hashing so the module compiles and runs without external dependencies.
 * Replace with real HD key derivation before production use.
 */
function deriveAddress(mnemonic, derivationPath, chainFamily) {
    // Deterministic placeholder: HMAC-SHA256(mnemonic, derivationPath)
    const derived = crypto
        .createHmac("sha256", mnemonic)
        .update(derivationPath)
        .digest();
    switch (chainFamily) {
        case "evm":
            // 20-byte EVM address (0x-prefixed)
            return `0x${derived.subarray(0, 20).toString("hex")}`;
        case "solana":
            // 32-byte base58 address (hex placeholder)
            return derived.subarray(0, 32).toString("hex");
        case "bitcoin":
            // bech32 placeholder
            return `bc1q${derived.subarray(0, 20).toString("hex")}`;
        case "sui":
            // 32-byte hex address with 0x prefix
            return `0x${derived.subarray(0, 32).toString("hex")}`;
        default:
            return `0x${derived.subarray(0, 20).toString("hex")}`;
    }
}
/**
 * Derive a key pair from a mnemonic and derivation path.
 *
 * Requires @scure/bip32 and @noble/curves for real HD key derivation.
 * Throws if these dependencies are not installed — NEVER falls back to
 * HMAC-based placeholders, as those produce keys that don't correspond
 * to real on-chain addresses.
 */
function deriveKeyPair(_mnemonic, _derivationPath) {
    throw new Error("OWS key derivation requires @scure/bip32 and @noble/curves for real BIP-32 HD derivation. " +
        "HMAC-based placeholder keys are NOT valid on-chain. " +
        "Install: npm i @scure/bip32 @scure/bip39 @noble/curves");
}
/**
 * Sign a message with a private key.
 *
 * Requires @noble/curves for real ECDSA/EdDSA signing.
 * Throws if not installed — NEVER produces HMAC-based pseudo-signatures,
 * as those look real but will NOT validate on-chain.
 */
function signMessage(_privateKey, _message) {
    throw new Error("OWS signing requires @noble/curves for real ECDSA (secp256k1) or EdDSA (Ed25519) signatures. " +
        "HMAC-based pseudo-signatures are NOT valid on-chain and will fail verification. " +
        "Install: npm i @noble/curves @noble/hashes");
}
/**
 * Map a CAIP-2 chain ID to the appropriate BIP-44 derivation path.
 */
function getDerivationPathForChain(chainId) {
    // CAIP-2 format: namespace:reference (e.g. "eip155:1", "solana:mainnet")
    const namespace = chainId.split(":")[0];
    switch (namespace) {
        case "eip155":
            return DEFAULT_DERIVATION_PATHS["evm"];
        case "solana":
            return DEFAULT_DERIVATION_PATHS["solana"];
        case "bip122":
            return DEFAULT_DERIVATION_PATHS["bitcoin"];
        case "sui":
            return DEFAULT_DERIVATION_PATHS["sui"];
        default:
            return undefined;
    }
}
//# sourceMappingURL=index.js.map