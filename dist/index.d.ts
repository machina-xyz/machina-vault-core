/**
 * @machina-xyz/vault-core
 *
 * Institutional-grade crypto vault powered by Rust/WASM.
 * One passkey → one vault → all chains.
 */
export { MachinaVault, type VaultConfig, type WalletRecord } from "./vault.js";
export { vault, initVault, type SignResult, type ChainAccount } from "./wasm/index.js";
export { type VaultStore, IndexedDBVaultStore, MemoryVaultStore } from "./storage/index.js";
