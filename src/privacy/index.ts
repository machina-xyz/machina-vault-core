/**
 * MACHINA Vault — Privacy Module
 * MAC-903: Stealth Addresses (ERC-5564) & ZK Balance Proofs
 *
 * Provides:
 * - ERC-5564 stealth address generation, scanning, and key derivation
 * - Pedersen commitment based balance proofs with simplified range proofs
 * - Efficient announcement scanning with view tag optimisation
 *
 * All operations are Cloudflare Workers V8 compatible (Web Crypto + @noble/curves).
 */

export * from "./types.js";
export * from "./stealth-address.js";
export * from "./balance-proofs.js";
export * from "./scanning.js";
