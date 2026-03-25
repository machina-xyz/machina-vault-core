/**
 * MAC-898: Chain-Agnostic Signing Engine
 * Module exports for @machina/vault-core/signing
 */

// Core types
export type {
  ChainFamily,
  ChainConfig,
  SignRequest,
  SignedTransaction,
  BroadcastResult,
  BalanceResult,
  ChainSigner,
} from "./types.js";

// Signing engine
export { SigningEngine } from "./engine.js";

// Chain router
export { getChainSigner } from "./router.js";

// Chain-specific signers
export { EvmSigner, rlpEncode } from "./chains/evm.js";
export type { RLPInput } from "./chains/evm.js";
export { SolanaSigner } from "./chains/solana.js";
export { SuiSigner } from "./chains/sui.js";

// RPC utilities
export { rpcCall, rpcCallWithRetry, RpcError } from "./rpc.js";
