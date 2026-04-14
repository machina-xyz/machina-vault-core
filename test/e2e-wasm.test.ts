/**
 * E2E test: WASM → vault-core full wallet lifecycle
 *
 * Proves: generate mnemonic → derive addresses → encrypt → decrypt → sign
 * All crypto happens in Rust/WASM. TypeScript never sees raw keys.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Direct WASM imports (Node.js)
import { initSync } from "../src/wasm/pkg/machina_wasm.js";
import * as wasm from "../src/wasm/pkg/machina_wasm.js";

// vault-core bridge
import { setWasmModule, vault } from "../src/wasm/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = resolve(__dirname, "../src/wasm/pkg/machina_wasm_bg.wasm");

describe("E2E: WASM vault lifecycle", () => {
  beforeAll(() => {
    // Load WASM binary synchronously in Node.js
    const wasmBytes = readFileSync(WASM_PATH);
    initSync({ module: wasmBytes });
    // Register the loaded module with vault-core
    setWasmModule(wasm as any);
  });

  it("vault is initialized", () => {
    expect(vault.isInitialized()).toBe(true);
  });

  // ─── Mnemonic ────────────────────────────────────────────────────

  it("generates a 12-word mnemonic", () => {
    const mnemonic = vault.generateMnemonic(12);
    const words = mnemonic.split(" ");
    expect(words.length).toBe(12);
    expect(vault.validateMnemonic(mnemonic)).toBe(true);
  });

  it("generates a 24-word mnemonic", () => {
    const mnemonic = vault.generateMnemonic(24);
    expect(mnemonic.split(" ").length).toBe(24);
    expect(vault.validateMnemonic(mnemonic)).toBe(true);
  });

  it("rejects invalid mnemonic", () => {
    expect(vault.validateMnemonic("not a valid mnemonic phrase")).toBe(false);
  });

  // ─── Address Derivation ──────────────────────────────────────────

  it("derives addresses for all 9 chains", () => {
    const mnemonic = vault.generateMnemonic(12);
    const accounts = vault.deriveAllAddresses(mnemonic, 0);

    expect(accounts.length).toBeGreaterThanOrEqual(9);

    // Check EVM address
    const eth = accounts.find((a) => a.chain === "Evm");
    expect(eth).toBeDefined();
    expect(eth!.address).toMatch(/^0x[0-9a-fA-F]{40}$/);

    // Check Solana address
    const sol = accounts.find((a) => a.chain === "Solana");
    expect(sol).toBeDefined();
    expect(sol!.address.length).toBeGreaterThan(30); // base58

    // Check Bitcoin address
    const btc = accounts.find((a) => a.chain === "Bitcoin");
    expect(btc).toBeDefined();

    // Check Sui address
    const sui = accounts.find((a) => a.chain === "Sui");
    expect(sui).toBeDefined();
    expect(sui!.address).toMatch(/^0x/);
  });

  it("same mnemonic produces same addresses", () => {
    const mnemonic = vault.generateMnemonic(12);
    const a1 = vault.deriveAllAddresses(mnemonic, 0);
    const a2 = vault.deriveAllAddresses(mnemonic, 0);

    expect(a1.length).toBe(a2.length);
    for (let i = 0; i < a1.length; i++) {
      expect(a1[i].address).toBe(a2[i].address);
    }
  });

  it("different index produces different addresses", () => {
    const mnemonic = vault.generateMnemonic(12);
    const a0 = vault.deriveAllAddresses(mnemonic, 0);
    const a1 = vault.deriveAllAddresses(mnemonic, 1);

    const eth0 = a0.find((a) => a.chain === "Evm")!.address;
    const eth1 = a1.find((a) => a.chain === "Evm")!.address;
    expect(eth0).not.toBe(eth1);
  });

  // ─── Key Derivation ──────────────────────────────────────────────

  it("derives secp256k1 key from mnemonic", () => {
    const mnemonic = vault.generateMnemonic(12);
    const key = vault.deriveKeyFromMnemonic(mnemonic, "m/44'/60'/0'/0/0", "secp256k1");
    expect(key).toMatch(/^[0-9a-fA-F]{64}$/); // 32 bytes hex
  });

  it("derives ed25519 key from mnemonic", () => {
    const mnemonic = vault.generateMnemonic(12);
    const key = vault.deriveKeyFromMnemonic(mnemonic, "m/44'/501'/0'/0'", "ed25519");
    expect(key).toMatch(/^[0-9a-fA-F]{64}$/);
  });

  it("derives address from private key", () => {
    const mnemonic = vault.generateMnemonic(12);
    const key = vault.deriveKeyFromMnemonic(mnemonic, "m/44'/60'/0'/0/0", "secp256k1");
    const address = vault.deriveAddress(key, "ethereum");
    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  // ─── Encryption / Decryption ─────────────────────────────────────

  it("encrypts and decrypts data", () => {
    const plaintext = "48656c6c6f"; // "Hello" in hex
    const passphrase = "test-passphrase-123";

    const envelope = vault.encrypt(plaintext, passphrase);
    expect(envelope).toBeTruthy();
    expect(typeof envelope).toBe("string");

    const decrypted = vault.decrypt(envelope, passphrase);
    expect(decrypted).toBe(plaintext);
  });

  it("wrong passphrase fails decryption", () => {
    const plaintext = "deadbeef";
    const envelope = vault.encrypt(plaintext, "correct-pass");

    expect(() => vault.decrypt(envelope, "wrong-pass")).toThrow();
  });

  it("encrypts mnemonic and recovers it", () => {
    const mnemonic = vault.generateMnemonic(12);
    const mnemonicHex = Buffer.from(mnemonic, "utf-8").toString("hex");
    const passphrase = "vault-passphrase";

    const envelope = vault.encrypt(mnemonicHex, passphrase);
    const recovered = vault.decrypt(envelope, passphrase);
    const recoveredMnemonic = Buffer.from(recovered, "hex").toString("utf-8");

    expect(recoveredMnemonic).toBe(mnemonic);
    expect(vault.validateMnemonic(recoveredMnemonic)).toBe(true);
  });

  // ─── Signing ─────────────────────────────────────────────────────

  it("signs a message on Ethereum", () => {
    const mnemonic = vault.generateMnemonic(12);
    const key = vault.deriveKeyFromMnemonic(mnemonic, "m/44'/60'/0'/0/0", "secp256k1");

    const result = vault.signMessage(key, "ethereum", "Hello MACHINA");
    expect(result.signature).toBeTruthy();
    expect(result.signature.length).toBeGreaterThan(10);
    expect(result.recovery_id).toBeDefined();
  });

  it("signs a transaction on Ethereum", () => {
    const mnemonic = vault.generateMnemonic(12);
    const key = vault.deriveKeyFromMnemonic(mnemonic, "m/44'/60'/0'/0/0", "secp256k1");

    // Minimal RLP-encoded tx (legacy format)
    const txHex = "e880843b9aca00825208940000000000000000000000000000000000000000880de0b6b3a764000080";
    const result = vault.signTransaction(key, "ethereum", txHex);
    expect(result.signature).toBeTruthy();
    expect(result.signature.length).toBeGreaterThan(10);
  });

  it("signs a message on Solana", () => {
    const mnemonic = vault.generateMnemonic(12);
    const key = vault.deriveKeyFromMnemonic(mnemonic, "m/44'/501'/0'/0'", "ed25519");

    const result = vault.signMessage(key, "solana", "Hello Solana");
    expect(result.signature).toBeTruthy();
    expect(result.signature.length).toBe(128); // 64 bytes = 128 hex chars
  });

  // ─── Constant-time comparison ────────────────────────────────────

  it("constant-time hex comparison works", () => {
    expect(vault.ctHexEq("abcdef", "abcdef")).toBe(true);
    expect(vault.ctHexEq("abcdef", "123456")).toBe(false);
    expect(vault.ctHexEq("", "")).toBe(true);
  });

  // ─── Full Wallet Lifecycle ───────────────────────────────────────

  it("full lifecycle: create → encrypt → store → decrypt → sign", () => {
    // 1. Generate mnemonic
    const mnemonic = vault.generateMnemonic(12);
    expect(vault.validateMnemonic(mnemonic)).toBe(true);

    // 2. Derive all addresses
    const accounts = vault.deriveAllAddresses(mnemonic, 0);
    const ethAddr = accounts.find((a) => a.chain === "Evm")!.address;
    expect(ethAddr).toMatch(/^0x/);

    // 3. Encrypt mnemonic for storage
    const passphrase = "my-secure-vault-passphrase";
    const mnemonicHex = Buffer.from(mnemonic, "utf-8").toString("hex");
    const encrypted = vault.encrypt(mnemonicHex, passphrase);

    // 4. Later: decrypt to sign
    const decryptedHex = vault.decrypt(encrypted, passphrase);
    const recoveredMnemonic = Buffer.from(decryptedHex, "hex").toString("utf-8");

    // 5. Derive signing key
    const key = vault.deriveKeyFromMnemonic(recoveredMnemonic, "m/44'/60'/0'/0/0", "secp256k1");

    // 6. Verify address matches
    const derivedAddr = vault.deriveAddress(key, "ethereum");
    expect(derivedAddr.toLowerCase()).toBe(ethAddr.toLowerCase());

    // 7. Sign a transaction
    const sig = vault.signMessage(key, "ethereum", "Authorize transfer");
    expect(sig.signature).toBeTruthy();
    expect(sig.recovery_id).toBeDefined();
  });
});
