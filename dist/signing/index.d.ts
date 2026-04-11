/**
 * MAC-898: Chain-Agnostic Signing Engine
 * Module exports for @machina/vault-core/signing
 */
export type { ChainFamily, ChainConfig, SignRequest, SignedTransaction, BroadcastResult, BalanceResult, ChainSigner, } from "./types.js";
export { SigningEngine } from "./engine.js";
export { getChainSigner } from "./router.js";
export { EvmSigner, rlpEncode } from "./chains/evm.js";
export type { RLPInput } from "./chains/evm.js";
export { SolanaSigner } from "./chains/solana.js";
export { SuiSigner } from "./chains/sui.js";
export { rpcCall, rpcCallWithRetry, RpcError } from "./rpc.js";
