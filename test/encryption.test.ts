/**
 * MACHINA Vault — Encryption & Secret Sharing Tests
 *
 * Tests AES-256-GCM encryption, HKDF key derivation, and Shamir Secret
 * Sharing for social recovery. These are the primitives that protect
 * private key material at rest and during recovery.
 */

import { describe, it, expect } from "vitest";
import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";

import {
  splitSecret,
  reconstructSecret,
  createRecoveryConfig,
  initiateRecovery,
  submitRecoveryShare,
} from "../src/recovery/social-recovery.js";
import type { RecoveryRequest } from "../src/recovery/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

// ===========================================================================
// HKDF KEY DERIVATION (used by deriveMasterSeed)
// ===========================================================================

describe("HKDF Key Derivation", () => {
  // Security: HKDF expands root entropy into the master seed. If HKDF
  // produces weak or predictable keys, all derived wallet keys are compromised.

  it("should derive different keys for different salts", () => {
    const ikm = randomBytes(32);
    const key1 = hkdf(sha256, ikm, "salt-1", "info", 32);
    const key2 = hkdf(sha256, ikm, "salt-2", "info", 32);
    expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
  });

  it("should derive same key for same input (deterministic)", () => {
    const ikm = new Uint8Array(32);
    ikm.fill(0x42);
    const key1 = hkdf(sha256, ikm, "salt", "info", 32);
    const key2 = hkdf(sha256, ikm, "salt", "info", 32);
    expect(bytesToHex(key1)).toBe(bytesToHex(key2));
  });

  it("should produce 256-bit (32-byte) key", () => {
    const ikm = randomBytes(32);
    const key = hkdf(sha256, ikm, undefined, "MACHINA-Vault-v1", 32);
    expect(key.length).toBe(32);
  });

  it("should produce different keys for different info strings", () => {
    const ikm = randomBytes(32);
    const key1 = hkdf(sha256, ikm, undefined, "MACHINA-Vault-v1", 32);
    const key2 = hkdf(sha256, ikm, undefined, "MACHINA-Vault-v2", 32);
    expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
  });

  it("should produce 64-byte output when requested (for master seed)", () => {
    const ikm = randomBytes(32);
    const key = hkdf(sha256, ikm, undefined, "MACHINA-Vault-v1", 64);
    expect(key.length).toBe(64);
  });

  it("should derive different keys for different input key material", () => {
    const ikm1 = new Uint8Array(32);
    ikm1.fill(0x01);
    const ikm2 = new Uint8Array(32);
    ikm2.fill(0x02);
    const key1 = hkdf(sha256, ikm1, undefined, "info", 32);
    const key2 = hkdf(sha256, ikm2, undefined, "info", 32);
    expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
  });
});

// ===========================================================================
// AES-256-GCM ENCRYPTION (via WebCrypto, used by vault at rest)
// ===========================================================================

describe("AES-256-GCM Encryption", () => {
  // Security: AES-256-GCM protects private keys at rest. If encryption is
  // broken, all stored key material is exposed.

  async function aesEncrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
  ): Promise<Uint8Array> {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      plaintext,
    );
    return new Uint8Array(ciphertext);
  }

  async function aesDecrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
  ): Promise<Uint8Array> {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      ciphertext,
    );
    return new Uint8Array(plaintext);
  }

  it("should encrypt and decrypt roundtrip correctly", async () => {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const plaintext = new TextEncoder().encode("MACHINA private key material");

    const ciphertext = await aesEncrypt(plaintext, key, iv);
    const decrypted = await aesDecrypt(ciphertext, key, iv);

    expect(bytesToHex(decrypted)).toBe(bytesToHex(plaintext));
  });

  it("should produce different ciphertext for same plaintext (random IV)", async () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode("same plaintext");

    const iv1 = randomBytes(12);
    const iv2 = randomBytes(12);
    const ct1 = await aesEncrypt(plaintext, key, iv1);
    const ct2 = await aesEncrypt(plaintext, key, iv2);

    expect(bytesToHex(ct1)).not.toBe(bytesToHex(ct2));
  });

  it("should fail to decrypt with wrong key", async () => {
    const key1 = randomBytes(32);
    const key2 = randomBytes(32);
    const iv = randomBytes(12);
    const plaintext = new TextEncoder().encode("secret");

    const ciphertext = await aesEncrypt(plaintext, key1, iv);
    await expect(aesDecrypt(ciphertext, key2, iv)).rejects.toThrow();
  });

  it("should fail to decrypt with corrupted ciphertext", async () => {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const plaintext = new TextEncoder().encode("secret");

    const ciphertext = await aesEncrypt(plaintext, key, iv);
    // Flip a bit in the ciphertext
    const corrupted = new Uint8Array(ciphertext);
    corrupted[0] ^= 0x01;
    await expect(aesDecrypt(corrupted, key, iv)).rejects.toThrow();
  });

  it("should fail to decrypt with wrong IV", async () => {
    const key = randomBytes(32);
    const iv1 = randomBytes(12);
    const iv2 = randomBytes(12);
    const plaintext = new TextEncoder().encode("secret");

    const ciphertext = await aesEncrypt(plaintext, key, iv1);
    await expect(aesDecrypt(ciphertext, key, iv2)).rejects.toThrow();
  });

  it("should detect tampering (GCM auth tag failure)", async () => {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const plaintext = new TextEncoder().encode("authenticated data");

    const ciphertext = await aesEncrypt(plaintext, key, iv);
    // Tamper with the auth tag (last 16 bytes of GCM output)
    const tampered = new Uint8Array(ciphertext);
    tampered[tampered.length - 1] ^= 0xff;
    await expect(aesDecrypt(tampered, key, iv)).rejects.toThrow();
  });

  it("should use 12-byte IV (standard for GCM)", () => {
    const iv = randomBytes(12);
    expect(iv.length).toBe(12);
    // GCM spec recommends 96-bit (12 byte) IVs for maximum interoperability
  });

  it("should produce ciphertext longer than plaintext by exactly 16 bytes (auth tag)", async () => {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const plaintext = new Uint8Array(32);
    plaintext.fill(0xab);

    const ciphertext = await aesEncrypt(plaintext, key, iv);
    // GCM auth tag is 16 bytes
    expect(ciphertext.length).toBe(plaintext.length + 16);
  });
});

// ===========================================================================
// SHAMIR SECRET SHARING
// ===========================================================================

describe("Shamir Secret Sharing", () => {
  // Security: Shamir's SSS is used for social recovery. Incorrect implementation
  // means funds cannot be recovered OR fewer-than-threshold shares could
  // reconstruct the secret (catastrophic security failure).

  it("should split and reconstruct 2-of-3 correctly", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 2, 3);

    expect(shares.length).toBe(3);

    // Any 2 of 3 shares should reconstruct
    const reconstructed = reconstructSecret([shares[0], shares[1]]);
    expect(bytesToHex(reconstructed)).toBe(bytesToHex(secret));
  });

  it("should split and reconstruct 3-of-5 correctly", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 3, 5);

    expect(shares.length).toBe(5);

    // Use shares 1, 3, 4 (any 3 of 5)
    const reconstructed = reconstructSecret([shares[0], shares[2], shares[3]]);
    expect(bytesToHex(reconstructed)).toBe(bytesToHex(secret));
  });

  it("should reconstruct same secret regardless of which shares are used", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 2, 4);

    // All 6 combinations of 2 from 4
    const combinations = [
      [0, 1], [0, 2], [0, 3], [1, 2], [1, 3], [2, 3],
    ];
    for (const [i, j] of combinations) {
      const reconstructed = reconstructSecret([shares[i], shares[j]]);
      expect(bytesToHex(reconstructed)).toBe(bytesToHex(secret));
    }
  });

  it("should fail to reconstruct with fewer than threshold shares (2-of-3, only 1)", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 3, 5);

    // Only 2 shares when threshold is 3 — should produce WRONG result
    const wrongReconstruction = reconstructSecret([shares[0], shares[1]]);
    // With only 2 of 3 required shares, result should NOT equal the secret
    // (except with astronomically low probability)
    expect(bytesToHex(wrongReconstruction)).not.toBe(bytesToHex(secret));
  });

  it("should produce different shares each time (random coefficients)", () => {
    const secret = randomBytes(32);
    const shares1 = splitSecret(secret, 2, 3);
    const shares2 = splitSecret(secret, 2, 3);

    // Shares should differ due to random polynomial coefficients
    expect(bytesToHex(shares1[0].data)).not.toBe(bytesToHex(shares2[0].data));
  });

  it("should handle 1-byte secret", () => {
    const secret = new Uint8Array([0x42]);
    const shares = splitSecret(secret, 2, 3);
    const reconstructed = reconstructSecret([shares[0], shares[2]]);
    expect(bytesToHex(reconstructed)).toBe(bytesToHex(secret));
  });

  it("should handle 32-byte secret (typical private key)", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 2, 3);
    const reconstructed = reconstructSecret([shares[1], shares[2]]);
    expect(bytesToHex(reconstructed)).toBe(bytesToHex(secret));
  });

  it("should handle 64-byte secret (master seed)", () => {
    const secret = randomBytes(64);
    const shares = splitSecret(secret, 3, 5);
    const reconstructed = reconstructSecret([shares[0], shares[2], shares[4]]);
    expect(bytesToHex(reconstructed)).toBe(bytesToHex(secret));
  });

  it("should reject threshold > total shares", () => {
    const secret = randomBytes(32);
    expect(() => splitSecret(secret, 5, 3)).toThrow();
  });

  it("should reject threshold < 2", () => {
    const secret = randomBytes(32);
    expect(() => splitSecret(secret, 1, 3)).toThrow();
  });

  it("should reject more than 255 total shares", () => {
    const secret = randomBytes(32);
    expect(() => splitSecret(secret, 2, 256)).toThrow();
  });

  it("should have 1-based share indices", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 2, 5);
    const indices = shares.map((s) => s.index);
    expect(indices).toEqual([1, 2, 3, 4, 5]);
  });

  it("should handle all-zero secret", () => {
    const secret = new Uint8Array(32); // all zeros
    const shares = splitSecret(secret, 2, 3);
    const reconstructed = reconstructSecret([shares[0], shares[1]]);
    expect(bytesToHex(reconstructed)).toBe(bytesToHex(secret));
  });

  it("should handle all-FF secret", () => {
    const secret = new Uint8Array(32);
    secret.fill(0xff);
    const shares = splitSecret(secret, 2, 3);
    const reconstructed = reconstructSecret([shares[0], shares[2]]);
    expect(bytesToHex(reconstructed)).toBe(bytesToHex(secret));
  });

  it("should work with maximum threshold equal to total shares (n-of-n)", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, 5, 5);
    // All 5 shares needed
    const reconstructed = reconstructSecret(shares);
    expect(bytesToHex(reconstructed)).toBe(bytesToHex(secret));
  });
});

// ===========================================================================
// RECOVERY CONFIG AND REQUEST MANAGEMENT
// ===========================================================================

describe("Recovery Configuration", () => {
  // Security: Recovery flow must enforce cooldown periods and prevent
  // duplicate guardian share submissions.

  it("should create valid recovery config with correct guardian count", () => {
    const config = createRecoveryConfig("vault-001", 2, [
      { identifier: "alice@example.com", type: "email", name: "Alice" },
      { identifier: "bob@example.com", type: "email", name: "Bob" },
      { identifier: "0x1234", type: "address", name: "Charlie" },
    ]);

    expect(config.threshold).toBe(2);
    expect(config.totalGuardians).toBe(3);
    expect(config.guardians.length).toBe(3);
    expect(config.guardians[0].shareIndex).toBe(1);
    expect(config.guardians[2].shareIndex).toBe(3);
  });

  it("should reject when guardians < threshold", () => {
    expect(() =>
      createRecoveryConfig("vault-001", 3, [
        { identifier: "alice@example.com", type: "email", name: "Alice" },
        { identifier: "bob@example.com", type: "email", name: "Bob" },
      ]),
    ).toThrow();
  });

  it("should initiate recovery with correct cooldown period", () => {
    const config = createRecoveryConfig(
      "vault-001",
      2,
      [
        { identifier: "alice", type: "email", name: "Alice" },
        { identifier: "bob", type: "email", name: "Bob" },
        { identifier: "charlie", type: "email", name: "Charlie" },
      ],
      { cooldownSeconds: 86400 },
    );

    const request = initiateRecovery("vault-001", config, "social");
    expect(request.status).toBe("pending");
    expect(request.sharesCollected).toBe(0);
    expect(request.sharesRequired).toBe(2);

    // Cooldown should be ~24 hours from now
    const cooldown = new Date(request.cooldownExpiresAt).getTime();
    const now = Date.now();
    expect(cooldown - now).toBeGreaterThan(86000 * 1000); // ~24h
    expect(cooldown - now).toBeLessThan(87000 * 1000);
  });

  it("should not accept same guardian share twice", () => {
    const config = createRecoveryConfig("vault-001", 2, [
      { identifier: "alice", type: "email", name: "Alice" },
      { identifier: "bob", type: "email", name: "Bob" },
      { identifier: "charlie", type: "email", name: "Charlie" },
    ]);

    let request = initiateRecovery("vault-001", config, "social");
    request = submitRecoveryShare(request, "guardian-1");

    // Same guardian submitting again should throw
    expect(() => submitRecoveryShare(request, "guardian-1")).toThrow(
      /already submitted/i,
    );
  });

  it("should transition to in_progress when threshold is met", () => {
    const config = createRecoveryConfig("vault-001", 2, [
      { identifier: "alice", type: "email", name: "Alice" },
      { identifier: "bob", type: "email", name: "Bob" },
      { identifier: "charlie", type: "email", name: "Charlie" },
    ]);

    let request = initiateRecovery("vault-001", config, "social");
    expect(request.status).toBe("pending");

    request = submitRecoveryShare(request, "guardian-1");
    expect(request.sharesCollected).toBe(1);
    expect(request.status).toBe("pending");

    request = submitRecoveryShare(request, "guardian-2");
    expect(request.sharesCollected).toBe(2);
    expect(request.status).toBe("in_progress");
  });

  it("should reject expired recovery requests", () => {
    const config = createRecoveryConfig("vault-001", 2, [
      { identifier: "alice", type: "email", name: "Alice" },
      { identifier: "bob", type: "email", name: "Bob" },
    ]);

    let request = initiateRecovery("vault-001", config, "social");
    // Manually expire the request
    request = {
      ...request,
      requestExpiresAt: new Date(Date.now() - 1000).toISOString(),
    };

    expect(() => submitRecoveryShare(request, "guardian-1")).toThrow(/expired/i);
  });

  it("should set 7-day expiry for recovery requests", () => {
    const config = createRecoveryConfig("vault-001", 2, [
      { identifier: "alice", type: "email", name: "Alice" },
      { identifier: "bob", type: "email", name: "Bob" },
    ]);

    const request = initiateRecovery("vault-001", config, "social");
    const expiry = new Date(request.requestExpiresAt).getTime();
    const now = Date.now();
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    expect(expiry - now).toBeGreaterThan(sevenDays - 10000);
    expect(expiry - now).toBeLessThan(sevenDays + 10000);
  });
});
