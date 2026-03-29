/**
 * MACHINA Vault — BIP-44 Key Derivation
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Uses @noble/curves and @noble/hashes exclusively (Cloudflare Workers compatible).
 * Implements simplified BIP-32 hardened-only derivation for secp256k1.
 */
import { secp256k1 } from "@noble/curves/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";
import { keccak_256 } from "@noble/hashes/sha3";
// ---------------------------------------------------------------------------
// Derivation path constants
// ---------------------------------------------------------------------------
/** BIP-44 coin types */
export const COIN_TYPE = {
    EVM: 60,
    SOLANA: 501,
    SUI: 784,
};
/** Standard derivation paths (BIP-44) */
export const DERIVATION_PATHS = {
    /** EVM: m/44'/60'/0'/0/{index} */
    evm: (index) => `m/44'/60'/0'/0'/${index}'`,
    /** Solana: m/44'/501'/0'/0' */
    solana: () => `m/44'/501'/0'/0'`,
    /** Sui: m/44'/784'/0'/0'/0' */
    sui: () => `m/44'/784'/0'/0'/0'`,
};
/** Operator keys live under account 1 */
export const OPERATOR_PATH = (index) => `m/44'/60'/1'/0'/${index}'`;
/** Agent keys live under account 2 */
export const AGENT_PATH = (index) => `m/44'/60'/2'/0'/${index}'`;
// ---------------------------------------------------------------------------
// BIP-32 hardened derivation (simplified, hardened-only)
// ---------------------------------------------------------------------------
const HARDENED_OFFSET = 0x80000000;
/** secp256k1 curve order */
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
/**
 * Derive the master node from a seed using HMAC-SHA512 with "Bitcoin seed".
 * This is the standard BIP-32 master key generation.
 */
function masterNodeFromSeed(seed) {
    const I = hmac(sha512, new TextEncoder().encode("Bitcoin seed"), seed);
    return {
        key: I.slice(0, 32),
        chainCode: I.slice(32, 64),
    };
}
/**
 * Derive a hardened child key from a parent node (BIP-32 compliant).
 *
 * data = 0x00 || parentKey(32) || uint32BE(index + 0x80000000)
 * I = HMAC-SHA512(key=parentChainCode, data)
 * IL = I[0:32], IR = I[32:64]
 * childKey = (parse256(IL) + parentKey) mod n
 * childChainCode = IR
 */
function deriveHardenedChild(parentKey, parentChainCode, index) {
    const data = new Uint8Array(1 + 32 + 4);
    // 0x00 prefix
    data[0] = 0x00;
    // parent key (32 bytes)
    data.set(parentKey, 1);
    // index + hardened offset as uint32 big-endian
    const hardenedIndex = (index + HARDENED_OFFSET) >>> 0;
    data[33] = (hardenedIndex >>> 24) & 0xff;
    data[34] = (hardenedIndex >>> 16) & 0xff;
    data[35] = (hardenedIndex >>> 8) & 0xff;
    data[36] = hardenedIndex & 0xff;
    const I = hmac(sha512, parentChainCode, data);
    // BIP-32: childKey = (parse256(IL) + parentKey) mod n
    const IL = I.slice(0, 32);
    const IR = I.slice(32, 64);
    const ilBigInt = bytesToBigInt(IL);
    const parentKeyBigInt = bytesToBigInt(parentKey);
    const childKeyBigInt = (ilBigInt + parentKeyBigInt) % SECP256K1_N;
    // Per BIP-32 spec: if IL >= n or childKey === 0, the key is invalid.
    // In practice this is astronomically unlikely (~1 in 2^128).
    if (ilBigInt >= SECP256K1_N || childKeyBigInt === 0n) {
        throw new Error("BIP-32 child key derivation produced invalid key (IL >= n or result is zero). " +
            "This is astronomically unlikely — try the next index.");
    }
    const childKey = bigIntToBytes(childKeyBigInt, 32);
    return {
        key: childKey,
        chainCode: IR,
    };
}
/**
 * Parse a BIP-44 derivation path into an array of child indices.
 * All path components MUST be hardened (suffixed with ').
 *
 * Example: "m/44'/60'/0'/0'/0'" → [44, 60, 0, 0, 0]
 */
function parsePath(path) {
    if (!path.startsWith("m/")) {
        throw new Error(`Invalid derivation path: must start with "m/"`);
    }
    const segments = path.slice(2).split("/");
    return segments.map((seg) => {
        const hardened = seg.endsWith("'");
        const indexStr = hardened ? seg.slice(0, -1) : seg;
        const index = parseInt(indexStr, 10);
        if (!Number.isFinite(index) || index < 0) {
            throw new Error(`Invalid path segment: "${seg}"`);
        }
        if (!hardened) {
            throw new Error(`Non-hardened derivation not supported for security: "${seg}"`);
        }
        return index;
    });
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
/**
 * Derive a 64-byte master seed from root entropy using HKDF-SHA256.
 * The root entropy typically comes from a passkey or secure random source.
 */
export function deriveMasterSeed(rootEntropy) {
    return hkdf(sha256, rootEntropy, undefined, "MACHINA-Vault-v1", 64);
}
/**
 * Derive a secp256k1 key pair at the given BIP-44 hardened path.
 * Returns the raw 32-byte private key and 33-byte compressed public key.
 */
export function deriveKeyAtPath(masterSeed, path) {
    const indices = parsePath(path);
    let node = masterNodeFromSeed(masterSeed);
    for (const index of indices) {
        node = deriveHardenedChild(node.key, node.chainCode, index);
    }
    // Ensure the derived key is a valid secp256k1 private key
    // If it's zero or >= curve order, we hash it again (extremely unlikely)
    let privateKey = node.key;
    const n = secp256k1.CURVE.n;
    let keyBigInt = bytesToBigInt(privateKey);
    if (keyBigInt === 0n || keyBigInt >= n) {
        // Rehash — practically impossible but required for correctness
        const rehashed = hmac(sha512, node.chainCode, privateKey);
        privateKey = rehashed.slice(0, 32);
        keyBigInt = bytesToBigInt(privateKey);
        if (keyBigInt === 0n || keyBigInt >= n) {
            throw new Error("Key derivation failed: invalid private key");
        }
    }
    const publicKey = secp256k1.getPublicKey(privateKey, true); // compressed
    return { privateKey, publicKey };
}
/**
 * Derive an EVM address from a compressed secp256k1 public key.
 * address = "0x" + keccak256(uncompressedPublicKeyWithoutPrefix)[12:]
 */
export function publicKeyToEvmAddress(compressedPubKey) {
    // Get uncompressed point (65 bytes: 0x04 || x || y)
    const point = secp256k1.ProjectivePoint.fromHex(compressedPubKey);
    const uncompressed = point.toRawBytes(false); // 65 bytes
    // keccak256 of the 64-byte public key (skip 0x04 prefix)
    const hash = keccak_256(uncompressed.slice(1));
    // Take last 20 bytes
    const addressBytes = hash.slice(12);
    return "0x" + bytesToHex(addressBytes);
}
/**
 * Derive an operator key at the given index.
 * Path: m/44'/60'/1'/0'/{index}'
 */
export function deriveOperatorKey(masterSeed, index) {
    const path = OPERATOR_PATH(index);
    const { privateKey, publicKey } = deriveKeyAtPath(masterSeed, path);
    const address = publicKeyToEvmAddress(publicKey);
    return { privateKey, publicKey, address };
}
/**
 * Derive an agent key at the given index.
 * Path: m/44'/60'/2'/0'/{index}'
 */
export function deriveAgentKey(masterSeed, index) {
    const path = AGENT_PATH(index);
    const { privateKey, publicKey } = deriveKeyAtPath(masterSeed, path);
    const address = publicKeyToEvmAddress(publicKey);
    return { privateKey, publicKey, address };
}
/**
 * Generate an ephemeral session key (NOT derived from master seed).
 * Uses cryptographically secure random bytes.
 */
export function generateSessionKey() {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    const address = publicKeyToEvmAddress(publicKey);
    return { privateKey, publicKey, address };
}
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function bytesToBigInt(bytes) {
    let result = 0n;
    for (const byte of bytes) {
        result = (result << 8n) | BigInt(byte);
    }
    return result;
}
function bigIntToBytes(value, length) {
    const bytes = new Uint8Array(length);
    let remaining = value;
    for (let i = length - 1; i >= 0; i--) {
        bytes[i] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return bytes;
}
function bytesToHex(bytes) {
    let hex = "";
    for (const byte of bytes) {
        hex += byte.toString(16).padStart(2, "0");
    }
    return hex;
}
//# sourceMappingURL=derivation.js.map