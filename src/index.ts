/**
 * @machina-xyz/vault-core
 *
 * Institutional-grade crypto vault powered by Rust/WASM.
 * One passkey → one vault → all chains.
 */

// Main vault class — the primary interface
export { MachinaVault, type VaultConfig, type WalletRecord } from "./vault.js";

// WASM bridge (low-level access to Rust crypto)
export { vault, initVault, type SignResult, type ChainAccount } from "./wasm/index.js";

// Storage backends
export { type VaultStore, IndexedDBVaultStore, MemoryVaultStore } from "./storage/index.js";
