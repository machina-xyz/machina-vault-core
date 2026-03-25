/**
 * MACHINA Vault — ERC-5564 Stealth Addresses
 * MAC-903: Stealth Addresses using secp256k1 ECDH
 *
 * Implements the ERC-5564 stealth address standard:
 * - Sender generates ephemeral key, derives one-time stealth address
 * - Recipient scans announcements using viewing key (view tag optimisation)
 * - Recipient computes spending private key for matched addresses
 *
 * All EC operations use @noble/curves/secp256k1.
 * Cloudflare Workers V8 compatible — no Node.js APIs.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";
import type {
  StealthMetaAddress,
  StealthAddress,
  StealthKeyPair,
  AnnouncementLog,
} from "./types.js";
import { SCHEME_ID_SECP256K1 } from "./types.js";

// ---------------------------------------------------------------------------
// Hex helpers (no Buffer)
// ---------------------------------------------------------------------------

const HEX_CHARS = "0123456789abcdef";

function bytesToHex(bytes: Uint8Array): string {
  let hex = "0x";
  for (let i = 0; i < bytes.length; i++) {
    hex += HEX_CHARS[bytes[i]! >> 4] + HEX_CHARS[bytes[i]! & 0x0f];
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) {
    throw new Error("Hex string must have even length");
  }
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < h.length; i += 2) {
    bytes[i / 2] = parseInt(h.slice(i, i + 2), 16);
  }
  return bytes;
}

function stripHexPrefix(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}

// ---------------------------------------------------------------------------
// Ethereum address derivation
// ---------------------------------------------------------------------------

/**
 * Derive an Ethereum address from an uncompressed secp256k1 public key point.
 * address = 0x + last 20 bytes of keccak256(pubkey_without_04_prefix)
 */
function pubKeyToAddress(uncompressedPubKey: Uint8Array): string {
  // Remove the 0x04 prefix byte (uncompressed marker)
  const pubKeyBody = uncompressedPubKey.slice(1);
  const hash = keccak_256(pubKeyBody);
  const addressBytes = hash.slice(12); // last 20 bytes
  return checksumAddress(bytesToHex(addressBytes));
}

/**
 * EIP-55 checksum encoding for an Ethereum address.
 */
function checksumAddress(address: string): string {
  const addr = stripHexPrefix(address).toLowerCase();
  const hash = keccak_256(new TextEncoder().encode(addr));
  const hashHex = bytesToHex(hash).slice(2);

  let checksummed = "0x";
  for (let i = 0; i < addr.length; i++) {
    const c = addr[i]!;
    if (parseInt(hashHex[i]!, 16) >= 8) {
      checksummed += c.toUpperCase();
    } else {
      checksummed += c;
    }
  }
  return checksummed;
}

// ---------------------------------------------------------------------------
// Core Stealth Address Operations
// ---------------------------------------------------------------------------

/**
 * Generate a stealth key pair: spending key (s) and viewing key (v).
 *
 * - Spending key controls funds at stealth addresses
 * - Viewing key can be shared with scanning services for privacy-preserving
 *   detection of incoming payments
 */
export function generateStealthKeyPair(): StealthKeyPair {
  const spendingKeyBytes = secp256k1.utils.randomPrivateKey();
  const viewingKeyBytes = secp256k1.utils.randomPrivateKey();

  const spendingPubKey = secp256k1.getPublicKey(spendingKeyBytes, true);
  const viewingPubKey = secp256k1.getPublicKey(viewingKeyBytes, true);

  return {
    spendingKey: bytesToHex(spendingKeyBytes),
    viewingKey: bytesToHex(viewingKeyBytes),
    spendingPubKey: bytesToHex(spendingPubKey),
    viewingPubKey: bytesToHex(viewingPubKey),
  };
}

/**
 * Compute the stealth meta-address from a key pair.
 * Encoded as: st:eth:0x<spendingPubKey><viewingPubKey>
 */
export function computeStealthMetaAddress(
  keyPair: StealthKeyPair,
): StealthMetaAddress {
  return {
    spendingPubKey: keyPair.spendingPubKey,
    viewingPubKey: keyPair.viewingPubKey,
    prefix: SCHEME_ID_SECP256K1,
  };
}

/**
 * Encode a stealth meta-address to the canonical string format.
 * Format: st:eth:0x<spendingPubKey><viewingPubKey>
 */
export function encodeStealthMetaAddress(meta: StealthMetaAddress): string {
  return `st:eth:0x${stripHexPrefix(meta.spendingPubKey)}${stripHexPrefix(meta.viewingPubKey)}`;
}

/**
 * Parse a stealth meta-address from the canonical string format.
 * Expected format: st:eth:0x<66-char spending><66-char viewing>
 */
export function parseStealthMetaAddress(encoded: string): StealthMetaAddress {
  const prefix = "st:eth:0x";
  if (!encoded.startsWith(prefix)) {
    throw new Error(
      `Invalid stealth meta-address format: must start with "${prefix}"`,
    );
  }

  const payload = encoded.slice(prefix.length);
  // Two compressed public keys: 33 bytes each = 66 hex chars each = 132 total
  if (payload.length !== 132) {
    throw new Error(
      `Invalid stealth meta-address length: expected 132 hex chars, got ${payload.length}`,
    );
  }

  const spendingPubKey = "0x" + payload.slice(0, 66);
  const viewingPubKey = "0x" + payload.slice(66, 132);

  // Validate that both are valid secp256k1 points
  try {
    secp256k1.ProjectivePoint.fromHex(stripHexPrefix(spendingPubKey));
    secp256k1.ProjectivePoint.fromHex(stripHexPrefix(viewingPubKey));
  } catch {
    throw new Error(
      "Invalid stealth meta-address: public keys are not valid secp256k1 points",
    );
  }

  return {
    spendingPubKey,
    viewingPubKey,
    prefix: SCHEME_ID_SECP256K1,
  };
}

/**
 * Generate a stealth address for a recipient given their meta-address.
 *
 * ERC-5564 protocol:
 * 1. Generate random ephemeral key r, compute R = r * G
 * 2. Compute shared secret: S_shared = r * V (ECDH with viewing public key)
 * 3. Compute view tag: first byte of SHA-256(S_shared)
 * 4. Compute stealth public key: P_stealth = S + SHA-256(S_shared) * G
 * 5. Derive Ethereum address from P_stealth
 */
export function generateStealthAddress(
  metaAddress: StealthMetaAddress,
): StealthAddress {
  // 1. Generate ephemeral key pair
  const ephemeralKey = secp256k1.utils.randomPrivateKey();
  const ephemeralPubKey = secp256k1.getPublicKey(ephemeralKey, true);

  // 2. ECDH: shared secret = r * V
  const viewingPoint = secp256k1.ProjectivePoint.fromHex(
    stripHexPrefix(metaAddress.viewingPubKey),
  );
  const sharedSecretPoint = viewingPoint.multiply(
    bytesToBigInt(ephemeralKey),
  );
  const sharedSecretBytes = sharedSecretPoint.toRawBytes(true);

  // 3. Hash the shared secret
  const sharedSecretHash = sha256(sharedSecretBytes);

  // 4. View tag: first byte of the hash
  const viewTag = sharedSecretHash[0]!;

  // 5. Compute stealth public key: P = S + hash(S_shared) * G
  const spendingPoint = secp256k1.ProjectivePoint.fromHex(
    stripHexPrefix(metaAddress.spendingPubKey),
  );
  const hashScalar = bytesToBigInt(sharedSecretHash) % secp256k1.CURVE.n;
  const offsetPoint = secp256k1.ProjectivePoint.BASE.multiply(hashScalar);
  const stealthPubKeyPoint = spendingPoint.add(offsetPoint);

  // 6. Derive Ethereum address from uncompressed stealth public key
  const stealthPubKeyUncompressed = stealthPubKeyPoint.toRawBytes(false);
  const address = pubKeyToAddress(stealthPubKeyUncompressed);

  return {
    address,
    ephemeralPubKey: bytesToHex(ephemeralPubKey),
    viewTag,
  };
}

/**
 * Check whether a stealth address announcement belongs to this wallet.
 * Uses the view tag for fast scanning (avoids full derivation for non-matches).
 *
 * @param announcement - On-chain announcement log entry
 * @param viewingKey - Recipient's viewing private key (hex)
 * @returns true if the view tag matches (likely belongs to this wallet)
 */
export function checkStealthAddress(
  announcement: AnnouncementLog,
  viewingKey: string,
): boolean {
  // 1. Compute shared secret: S_shared = v * R
  const ephemeralPoint = secp256k1.ProjectivePoint.fromHex(
    stripHexPrefix(announcement.ephemeralPubKey),
  );
  const viewingKeyScalar = bytesToBigInt(
    hexToBytes(viewingKey),
  );
  const sharedSecretPoint = ephemeralPoint.multiply(viewingKeyScalar);
  const sharedSecretBytes = sharedSecretPoint.toRawBytes(true);

  // 2. Hash and check view tag
  const sharedSecretHash = sha256(sharedSecretBytes);
  const computedViewTag = sharedSecretHash[0]!;

  return computedViewTag === announcement.viewTag;
}

/**
 * Compute the private key that controls a stealth address.
 *
 * Used after confirming an announcement belongs to this wallet:
 *   stealth_private_key = s + SHA-256(v * R) mod n
 *
 * @param spendingKey - Spending private key (hex)
 * @param viewingKey - Viewing private key (hex)
 * @param ephemeralPubKey - Ephemeral public key R from announcement (hex)
 * @returns Stealth private key (hex)
 */
export function computeStealthPrivateKey(
  spendingKey: string,
  viewingKey: string,
  ephemeralPubKey: string,
): string {
  const n = secp256k1.CURVE.n;

  // 1. Compute shared secret: S_shared = v * R
  const ephemeralPoint = secp256k1.ProjectivePoint.fromHex(
    stripHexPrefix(ephemeralPubKey),
  );
  const viewingKeyScalar = bytesToBigInt(hexToBytes(viewingKey));
  const sharedSecretPoint = ephemeralPoint.multiply(viewingKeyScalar);
  const sharedSecretBytes = sharedSecretPoint.toRawBytes(true);

  // 2. Hash the shared secret
  const sharedSecretHash = sha256(sharedSecretBytes);
  const hashScalar = bytesToBigInt(sharedSecretHash) % n;

  // 3. stealth_private_key = (s + hash(S_shared)) mod n
  const spendingKeyScalar = bytesToBigInt(hexToBytes(spendingKey));
  const stealthKey = (spendingKeyScalar + hashScalar) % n;

  // Encode as 32-byte hex
  const stealthKeyBytes = bigIntToBytes(stealthKey, 32);
  return bytesToHex(stealthKeyBytes);
}

// ---------------------------------------------------------------------------
// BigInt <-> Uint8Array helpers
// ---------------------------------------------------------------------------

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]!);
  }
  return result;
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}
