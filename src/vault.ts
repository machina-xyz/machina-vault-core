/**
 * MACHINA Vault — the main entry point.
 *
 * One passkey → one vault → all chains.
 *
 * Usage:
 *   import { MachinaVault } from "@machina-xyz/vault-core";
 *
 *   const vault = new MachinaVault();
 *   await vault.init();
 *
 *   // Create a new vault with passkey
 *   const walletId = await vault.createWallet("my-wallet", "passphrase");
 *
 *   // Get all addresses
 *   const addresses = await vault.getAddresses(walletId);
 *
 *   // Sign a transaction
 *   const sig = await vault.signTransaction(walletId, "ethereum", txHex, "passphrase");
 */

import { vault as wasmVault, initVault, type ChainAccount, type SignResult } from "./wasm/index.js";
import { type VaultStore, MemoryVaultStore, IndexedDBVaultStore } from "./storage/index.js";

export interface VaultConfig {
  /** Storage backend. Defaults to IndexedDB in browser, memory in Node. */
  store?: VaultStore;
  /** URL or path to the WASM binary. */
  wasmUrl?: string;
}

export interface WalletRecord {
  id: string;
  name: string;
  encryptedMnemonic: string; // CryptoEnvelope JSON — encrypted by WASM
  accounts: ChainAccount[];
  createdAt: string;
}

export class MachinaVault {
  private store: VaultStore;
  private wasmUrl?: string;
  private initialized = false;

  constructor(config: VaultConfig = {}) {
    this.store = config.store ?? (
      typeof indexedDB !== "undefined"
        ? new IndexedDBVaultStore()
        : new MemoryVaultStore()
    );
    this.wasmUrl = config.wasmUrl;
  }

  /** Initialize the WASM crypto core. Must be called once. */
  async init(): Promise<void> {
    if (this.initialized) return;
    await initVault(this.wasmUrl);
    this.initialized = true;
  }

  private requireInit() {
    if (!this.initialized) throw new Error("Vault not initialized. Call init() first.");
  }

  // ─── Wallet Lifecycle ────────────────────────────────────────────

  /** Create a new wallet: generate mnemonic → derive all addresses → encrypt → store. */
  async createWallet(name: string, passphrase: string, words: 12 | 24 = 12): Promise<string> {
    this.requireInit();

    // 1. Generate mnemonic in WASM (entropy from crypto.getRandomValues via getrandom)
    const mnemonic = wasmVault.generateMnemonic(words);

    // 2. Derive addresses for all 9 chains in WASM
    const accounts = wasmVault.deriveAllAddresses(mnemonic, 0);

    // 3. Encrypt mnemonic in WASM (scrypt + AES-256-GCM)
    const mnemonicHex = toHex(mnemonic);
    const encryptedMnemonic = wasmVault.encrypt(mnemonicHex, passphrase);

    // 4. Store encrypted wallet (mnemonic NEVER stored in plaintext)
    const id = crypto.randomUUID();
    const record: WalletRecord = {
      id,
      name,
      encryptedMnemonic,
      accounts,
      createdAt: new Date().toISOString(),
    };

    await this.store.set(`wallet:${id}`, JSON.stringify(record));
    await this.store.set(`wallet-name:${name}`, id);

    return id;
  }

  /** Import a wallet from an existing mnemonic. */
  async importWallet(name: string, mnemonic: string, passphrase: string): Promise<string> {
    this.requireInit();

    if (!wasmVault.validateMnemonic(mnemonic)) {
      throw new Error("Invalid mnemonic phrase");
    }

    const accounts = wasmVault.deriveAllAddresses(mnemonic, 0);
    const mnemonicHex = toHex(mnemonic);
    const encryptedMnemonic = wasmVault.encrypt(mnemonicHex, passphrase);

    const id = crypto.randomUUID();
    const record: WalletRecord = {
      id,
      name,
      encryptedMnemonic,
      accounts,
      createdAt: new Date().toISOString(),
    };

    await this.store.set(`wallet:${id}`, JSON.stringify(record));
    await this.store.set(`wallet-name:${name}`, id);

    return id;
  }

  /** List all wallets in the vault. */
  async listWallets(): Promise<Array<{ id: string; name: string; accounts: ChainAccount[]; createdAt: string }>> {
    this.requireInit();
    const keys = await this.store.list();
    const wallets = [];
    for (const key of keys) {
      if (!key.startsWith("wallet:")) continue;
      const json = await this.store.get(key);
      if (!json) continue;
      const record: WalletRecord = JSON.parse(json);
      wallets.push({
        id: record.id,
        name: record.name,
        accounts: record.accounts,
        createdAt: record.createdAt,
      });
    }
    return wallets;
  }

  /** Get a wallet by ID or name. */
  async getWallet(idOrName: string): Promise<WalletRecord | null> {
    this.requireInit();
    // Try by ID first
    let json = await this.store.get(`wallet:${idOrName}`);
    if (json) return JSON.parse(json);
    // Try by name
    const id = await this.store.get(`wallet-name:${idOrName}`);
    if (!id) return null;
    json = await this.store.get(`wallet:${id}`);
    return json ? JSON.parse(json) : null;
  }

  /** Delete a wallet from the vault. */
  async deleteWallet(idOrName: string): Promise<void> {
    const wallet = await this.getWallet(idOrName);
    if (!wallet) throw new Error(`Wallet not found: ${idOrName}`);
    await this.store.delete(`wallet:${wallet.id}`);
    await this.store.delete(`wallet-name:${wallet.name}`);
  }

  /** Get all chain addresses for a wallet. */
  async getAddresses(idOrName: string): Promise<ChainAccount[]> {
    const wallet = await this.getWallet(idOrName);
    if (!wallet) throw new Error(`Wallet not found: ${idOrName}`);
    return wallet.accounts;
  }

  // ─── Signing ─────────────────────────────────────────────────────

  /** Sign a transaction. Decrypts key material in WASM, signs, returns signature. */
  async signTransaction(
    idOrName: string,
    chain: string,
    txHex: string,
    passphrase: string,
    index: number = 0,
  ): Promise<SignResult> {
    this.requireInit();
    const privateKeyHex = await this.deriveSigningKey(idOrName, chain, passphrase, index);
    return wasmVault.signTransaction(privateKeyHex, chain, txHex);
  }

  /** Sign a message with chain-specific prefixing. */
  async signMessage(
    idOrName: string,
    chain: string,
    message: string,
    passphrase: string,
    index: number = 0,
  ): Promise<SignResult> {
    this.requireInit();
    const privateKeyHex = await this.deriveSigningKey(idOrName, chain, passphrase, index);
    return wasmVault.signMessage(privateKeyHex, chain, message);
  }

  /** Sign EIP-712 typed structured data. */
  async signTypedData(
    idOrName: string,
    typedDataJson: string,
    passphrase: string,
    index: number = 0,
  ): Promise<SignResult> {
    this.requireInit();
    const privateKeyHex = await this.deriveSigningKey(idOrName, "ethereum", passphrase, index);
    return wasmVault.signTypedData(privateKeyHex, typedDataJson);
  }

  // ─── Export (dangerous) ──────────────────────────────────────────

  /** Export the mnemonic. Returns plaintext — handle with extreme care. */
  async exportMnemonic(idOrName: string, passphrase: string): Promise<string> {
    this.requireInit();
    const wallet = await this.getWallet(idOrName);
    if (!wallet) throw new Error(`Wallet not found: ${idOrName}`);
    const mnemonicHex = wasmVault.decrypt(wallet.encryptedMnemonic, passphrase);
    return fromHex(mnemonicHex);
  }

  // ─── Internal ────────────────────────────────────────────────────

  /**
   * Derive a chain-specific signing key from encrypted mnemonic.
   * The mnemonic is decrypted in WASM, the key is derived in WASM,
   * and the hex key is returned. The mnemonic is never exposed to JS.
   */
  private async deriveSigningKey(
    idOrName: string,
    chain: string,
    passphrase: string,
    index: number,
  ): Promise<string> {
    const wallet = await this.getWallet(idOrName);
    if (!wallet) throw new Error(`Wallet not found: ${idOrName}`);

    // Decrypt mnemonic in WASM
    const mnemonicHex = wasmVault.decrypt(wallet.encryptedMnemonic, passphrase);
    const mnemonic = fromHex(mnemonicHex);

    // Find the matching account to get the derivation path and curve
    const account = wallet.accounts.find(
      (a) => a.chain.toLowerCase() === chain.toLowerCase(),
    );
    if (!account) throw new Error(`No account for chain: ${chain}`);

    // Determine curve from chain
    const curve = ["Solana", "Sui", "Ton"].includes(account.chain) ? "ed25519" : "secp256k1";

    // Derive signing key in WASM
    return wasmVault.deriveKeyFromMnemonic(mnemonic, account.derivation_path, curve);
  }
}

// ─── Hex utilities ─────────────────────────────────────────────────

function toHex(str: string): string {
  return Array.from(new TextEncoder().encode(str))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(hex: string): string {
  const bytes = new Uint8Array(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
  return new TextDecoder().decode(bytes);
}
