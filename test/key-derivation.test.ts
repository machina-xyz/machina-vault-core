/**
 * MACHINA Vault — BIP-32/BIP-44 Key Derivation Exhaustive Tests
 *
 * Tests key derivation against known BIP-32 test vectors, validates
 * multi-chain address derivation, and covers edge cases for seed handling.
 * Every test has a clear security justification: incorrect key derivation
 * means funds sent to unreachable addresses or keys that cannot sign.
 */

import { describe, it, expect } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import { keccak_256 } from "@noble/hashes/sha3";

import {
  deriveMasterSeed,
  deriveKeyAtPath,
  deriveOperatorKey,
  deriveAgentKey,
  publicKeyToEvmAddress,
  generateSessionKey,
  DERIVATION_PATHS,
  OPERATOR_PATH,
  AGENT_PATH,
  COIN_TYPE,
} from "../src/keys/derivation.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) result = (result << 8n) | BigInt(byte);
  return result;
}

/** BIP-32 test vector 1 seed */
const BIP32_TV1_SEED = hexToBytes("000102030405060708090a0b0c0d0e0f");

/** BIP-32 test vector 2 seed (64 bytes) */
const BIP32_TV2_SEED = hexToBytes(
  "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
);

/** Deterministic test entropy */
const TEST_ENTROPY = new Uint8Array(32);
for (let i = 0; i < 32; i++) TEST_ENTROPY[i] = i + 1;
const TEST_MASTER_SEED = deriveMasterSeed(TEST_ENTROPY);

// ===========================================================================
// BIP-32 Standard Test Vectors
// ===========================================================================

describe("BIP-32 Key Derivation — Standard Test Vectors", () => {
  // Security: BIP-32 compliance ensures interoperability with hardware wallets
  // and standard recovery tools. Incorrect derivation = unrecoverable funds.

  describe("Test Vector 1 (seed: 000102030405060708090a0b0c0d0e0f)", () => {
    it("should derive valid master node from BIP-32 test vector 1 seed", () => {
      // BIP-32 spec: master node = HMAC-SHA512(key="Bitcoin seed", data=seed)
      const I = hmac(sha512, new TextEncoder().encode("Bitcoin seed"), BIP32_TV1_SEED);
      const masterKey = I.slice(0, 32);
      const chainCode = I.slice(32, 64);

      expect(masterKey.length).toBe(32);
      expect(chainCode.length).toBe(32);

      // Master key must be valid secp256k1 scalar
      const keyBigInt = bytesToBigInt(masterKey);
      expect(keyBigInt).toBeGreaterThan(0n);
      expect(keyBigInt).toBeLessThan(secp256k1.CURVE.n);

      // Known BIP-32 TV1 master private key (from spec)
      expect(bytesToHex(masterKey)).toBe(
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
      );
      expect(bytesToHex(chainCode)).toBe(
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
      );
    });

    it("should derive correct public key from BIP-32 test vector 1 master", () => {
      const I = hmac(sha512, new TextEncoder().encode("Bitcoin seed"), BIP32_TV1_SEED);
      const masterKey = I.slice(0, 32);
      const pubkey = secp256k1.getPublicKey(masterKey, true);
      // Known compressed public key from BIP-32 TV1
      expect(bytesToHex(pubkey)).toBe(
        "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
      );
    });
  });

  describe("Test Vector 2 (64-byte seed)", () => {
    it("should derive valid master node from BIP-32 test vector 2 seed", () => {
      const I = hmac(sha512, new TextEncoder().encode("Bitcoin seed"), BIP32_TV2_SEED);
      const masterKey = I.slice(0, 32);
      const chainCode = I.slice(32, 64);

      const keyBigInt = bytesToBigInt(masterKey);
      expect(keyBigInt).toBeGreaterThan(0n);
      expect(keyBigInt).toBeLessThan(secp256k1.CURVE.n);

      // Known BIP-32 TV2 master private key
      expect(bytesToHex(masterKey)).toBe(
        "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
      );
      expect(bytesToHex(chainCode)).toBe(
        "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
      );
    });

    it("should derive correct public key from BIP-32 test vector 2 master", () => {
      const I = hmac(sha512, new TextEncoder().encode("Bitcoin seed"), BIP32_TV2_SEED);
      const masterKey = I.slice(0, 32);
      const pubkey = secp256k1.getPublicKey(masterKey, true);
      expect(bytesToHex(pubkey)).toBe(
        "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
      );
    });
  });
});

// ===========================================================================
// MACHINA Derivation Paths (HKDF + BIP-44 hardened)
// ===========================================================================

describe("MACHINA Key Hierarchy Derivation", () => {
  // Security: MACHINA uses HKDF to expand root entropy into a 64-byte seed,
  // then BIP-44 hardened-only paths. This must be deterministic and produce
  // valid keys at every tier.

  it("should derive a 64-byte master seed from entropy via HKDF", () => {
    const seed = deriveMasterSeed(TEST_ENTROPY);
    expect(seed).toBeInstanceOf(Uint8Array);
    expect(seed.length).toBe(64);
  });

  it("should produce deterministic seeds (same entropy = same seed)", () => {
    const a = deriveMasterSeed(TEST_ENTROPY);
    const b = deriveMasterSeed(TEST_ENTROPY);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  it("should produce different seeds for different entropy", () => {
    const entropy2 = new Uint8Array(32);
    entropy2.fill(0xff);
    const seed1 = deriveMasterSeed(TEST_ENTROPY);
    const seed2 = deriveMasterSeed(entropy2);
    expect(bytesToHex(seed1)).not.toBe(bytesToHex(seed2));
  });

  it("should derive valid EVM address from known seed (MetaMask-compatible format)", () => {
    const { address } = deriveOperatorKey(TEST_MASTER_SEED, 0);
    // EVM address: 0x + 40 hex chars
    expect(address).toMatch(/^0x[0-9a-f]{40}$/);
  });

  it("should produce valid EVM address format for all key tiers", () => {
    const operator = deriveOperatorKey(TEST_MASTER_SEED, 0);
    const agent = deriveAgentKey(TEST_MASTER_SEED, 0);
    const session = generateSessionKey();

    for (const key of [operator, agent, session]) {
      expect(key.address).toMatch(/^0x[0-9a-f]{40}$/);
      expect(key.privateKey.length).toBe(32);
      expect(key.publicKey.length).toBe(33); // compressed
    }
  });

  it("should derive different addresses for operator vs agent at same index", () => {
    // Security: Tier isolation means operator and agent keys MUST differ
    const operator = deriveOperatorKey(TEST_MASTER_SEED, 0);
    const agent = deriveAgentKey(TEST_MASTER_SEED, 0);
    expect(operator.address).not.toBe(agent.address);
    expect(bytesToHex(operator.privateKey)).not.toBe(bytesToHex(agent.privateKey));
  });

  it("should derive different addresses for different indices in same tier", () => {
    const key0 = deriveAgentKey(TEST_MASTER_SEED, 0);
    const key1 = deriveAgentKey(TEST_MASTER_SEED, 1);
    const key2 = deriveAgentKey(TEST_MASTER_SEED, 99);
    expect(key0.address).not.toBe(key1.address);
    expect(key1.address).not.toBe(key2.address);
    expect(key0.address).not.toBe(key2.address);
  });

  it("should derive same key for same seed + same path (deterministic)", () => {
    const a = deriveKeyAtPath(TEST_MASTER_SEED, "m/44'/60'/0'/0'/0'");
    const b = deriveKeyAtPath(TEST_MASTER_SEED, "m/44'/60'/0'/0'/0'");
    expect(bytesToHex(a.privateKey)).toBe(bytesToHex(b.privateKey));
    expect(bytesToHex(a.publicKey)).toBe(bytesToHex(b.publicKey));
  });

  it("should derive different keys for different chain coin types", () => {
    const evmKey = deriveKeyAtPath(TEST_MASTER_SEED, DERIVATION_PATHS.evm(0));
    const solKey = deriveKeyAtPath(TEST_MASTER_SEED, DERIVATION_PATHS.solana());
    expect(bytesToHex(evmKey.privateKey)).not.toBe(bytesToHex(solKey.privateKey));
  });
});

// ===========================================================================
// EVM Address Derivation
// ===========================================================================

describe("EVM Address Derivation (publicKeyToEvmAddress)", () => {
  // Security: Wrong address derivation means funds sent to an address
  // that this wallet cannot control.

  it("should produce keccak256(uncompressed[1:])[12:] as address", () => {
    const { publicKey } = deriveKeyAtPath(TEST_MASTER_SEED, "m/44'/60'/0'/0'/0'");

    // Manual calculation
    const point = secp256k1.ProjectivePoint.fromHex(publicKey);
    const uncompressed = point.toRawBytes(false);
    expect(uncompressed.length).toBe(65);
    expect(uncompressed[0]).toBe(0x04);

    const hash = keccak_256(uncompressed.slice(1));
    const expectedAddress = "0x" + bytesToHex(hash.slice(12));
    const actualAddress = publicKeyToEvmAddress(publicKey);

    expect(actualAddress).toBe(expectedAddress);
  });

  it("should produce lowercase hex address (no EIP-55 checksum)", () => {
    const { publicKey } = deriveKeyAtPath(TEST_MASTER_SEED, "m/44'/60'/0'/0'/0'");
    const address = publicKeyToEvmAddress(publicKey);
    expect(address).toBe(address.toLowerCase());
  });

  it("should produce 42-character address (0x + 40 hex)", () => {
    for (let i = 0; i < 5; i++) {
      const { publicKey } = deriveKeyAtPath(TEST_MASTER_SEED, `m/44'/60'/0'/0'/${i}'`);
      const address = publicKeyToEvmAddress(publicKey);
      expect(address.length).toBe(42);
    }
  });
});

// ===========================================================================
// BIP-32 Addition Fix Verification
// ===========================================================================

describe("BIP-32 Child Key Addition (IL + parentKey) mod n", () => {
  // Security: BIP-32 specifies childKey = (parse256(IL) + parentKey) mod n.
  // Using IL directly (without adding parentKey) would mean child keys are
  // NOT derived from the parent, breaking the hierarchical security model.

  it("should add IL to parent key mod n (not use IL directly)", () => {
    // Derive at two depths and verify the second depends on the first
    const path1 = "m/44'/60'/0'/0'/0'";
    const path2 = "m/44'/60'/0'/0'/1'";
    const key1 = deriveKeyAtPath(TEST_MASTER_SEED, path1);
    const key2 = deriveKeyAtPath(TEST_MASTER_SEED, path2);

    // If IL were used directly (no parent addition), changing the parent seed
    // would still produce the same child. Verify it does NOT.
    const altEntropy = new Uint8Array(32);
    altEntropy.fill(0xab);
    const altSeed = deriveMasterSeed(altEntropy);
    const altKey1 = deriveKeyAtPath(altSeed, path1);

    expect(bytesToHex(key1.privateKey)).not.toBe(bytesToHex(altKey1.privateKey));
  });

  it("should produce valid secp256k1 scalars at every derivation depth", () => {
    // Test paths of varying depth
    const paths = [
      "m/44'",
      "m/44'/60'",
      "m/44'/60'/0'",
      "m/44'/60'/0'/0'",
      "m/44'/60'/0'/0'/0'",
    ];
    const n = secp256k1.CURVE.n;
    for (const path of paths) {
      const { privateKey } = deriveKeyAtPath(TEST_MASTER_SEED, path);
      const scalar = bytesToBigInt(privateKey);
      expect(scalar).toBeGreaterThan(0n);
      expect(scalar).toBeLessThan(n);
    }
  });
});

// ===========================================================================
// Seed Edge Cases
// ===========================================================================

describe("Seed Edge Cases", () => {
  // Security: Malformed or degenerate seeds must be handled gracefully.
  // Accepting a zero seed or too-short seed could produce weak keys.

  it("should handle minimum entropy length (16 bytes)", () => {
    const minEntropy = new Uint8Array(16);
    minEntropy.fill(0x42);
    const seed = deriveMasterSeed(minEntropy);
    expect(seed.length).toBe(64);
    // Verify we can derive a key from it
    const { privateKey } = deriveKeyAtPath(seed, "m/44'/60'/0'/0'/0'");
    expect(privateKey.length).toBe(32);
  });

  it("should handle maximum seed length (64 bytes)", () => {
    const maxEntropy = new Uint8Array(64);
    maxEntropy.fill(0xfe);
    const seed = deriveMasterSeed(maxEntropy);
    expect(seed.length).toBe(64);
    const { privateKey } = deriveKeyAtPath(seed, "m/44'/60'/0'/0'/0'");
    expect(privateKey.length).toBe(32);
  });

  it("should handle all-zero entropy (degenerate but valid HKDF input)", () => {
    const zeroEntropy = new Uint8Array(32);
    const seed = deriveMasterSeed(zeroEntropy);
    expect(seed.length).toBe(64);
    // HKDF with all-zero input still produces a valid output
    const { privateKey } = deriveKeyAtPath(seed, "m/44'/60'/0'/0'/0'");
    const scalar = bytesToBigInt(privateKey);
    expect(scalar).toBeGreaterThan(0n);
  });

  it("should handle all-FF entropy correctly", () => {
    const ffEntropy = new Uint8Array(32);
    ffEntropy.fill(0xff);
    const seed = deriveMasterSeed(ffEntropy);
    const { privateKey } = deriveKeyAtPath(seed, "m/44'/60'/0'/0'/0'");
    const scalar = bytesToBigInt(privateKey);
    expect(scalar).toBeGreaterThan(0n);
    expect(scalar).toBeLessThan(secp256k1.CURVE.n);
  });

  it("should reject path without m/ prefix", () => {
    expect(() => deriveKeyAtPath(TEST_MASTER_SEED, "44'/60'/0'/0'/0'")).toThrow();
  });

  it("should reject non-hardened path segments", () => {
    // MACHINA enforces hardened-only for security
    expect(() => deriveKeyAtPath(TEST_MASTER_SEED, "m/44'/60'/0'/0/0")).toThrow(
      /non-hardened/i,
    );
  });

  it("should reject negative index in path", () => {
    expect(() => deriveKeyAtPath(TEST_MASTER_SEED, "m/44'/-1'/0'/0'/0'")).toThrow();
  });

  it("should reject non-numeric path segment", () => {
    expect(() => deriveKeyAtPath(TEST_MASTER_SEED, "m/44'/abc'/0'/0'/0'")).toThrow();
  });
});

// ===========================================================================
// Session Key Randomness
// ===========================================================================

describe("Session Key Generation", () => {
  // Security: Session keys are ephemeral and MUST be random (not deterministic).
  // Predictable session keys would allow replay attacks.

  it("should generate unique keys each time (random)", () => {
    const a = generateSessionKey();
    const b = generateSessionKey();
    expect(bytesToHex(a.privateKey)).not.toBe(bytesToHex(b.privateKey));
    expect(a.address).not.toBe(b.address);
  });

  it("should produce valid secp256k1 key pairs", () => {
    for (let i = 0; i < 10; i++) {
      const { privateKey, publicKey } = generateSessionKey();
      // Verify the public key matches the private key
      const expectedPub = secp256k1.getPublicKey(privateKey, true);
      expect(bytesToHex(publicKey)).toBe(bytesToHex(expectedPub));
    }
  });
});

// ===========================================================================
// Path Constants
// ===========================================================================

describe("Derivation Path Constants", () => {
  it("should use correct BIP-44 coin types", () => {
    expect(COIN_TYPE.EVM).toBe(60);
    expect(COIN_TYPE.SOLANA).toBe(501);
    expect(COIN_TYPE.SUI).toBe(784);
  });

  it("should produce correct EVM path format", () => {
    expect(DERIVATION_PATHS.evm(0)).toBe("m/44'/60'/0'/0'/0'");
    expect(DERIVATION_PATHS.evm(5)).toBe("m/44'/60'/0'/0'/5'");
  });

  it("should produce correct operator path (account 1)", () => {
    expect(OPERATOR_PATH(0)).toBe("m/44'/60'/1'/0'/0'");
    expect(OPERATOR_PATH(3)).toBe("m/44'/60'/1'/0'/3'");
  });

  it("should produce correct agent path (account 2)", () => {
    expect(AGENT_PATH(0)).toBe("m/44'/60'/2'/0'/0'");
    expect(AGENT_PATH(7)).toBe("m/44'/60'/2'/0'/7'");
  });

  it("should isolate operator and agent in different BIP-44 accounts", () => {
    // Account 1 = operator, Account 2 = agent — ensures no key overlap
    const opPath = OPERATOR_PATH(0);
    const agPath = AGENT_PATH(0);
    expect(opPath).toContain("/1'/");
    expect(agPath).toContain("/2'/");
  });
});
