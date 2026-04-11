/**
 * MAC-898: Sui chain signer.
 * Real ed25519 signing with Sui transaction serialization.
 * Uses @noble/curves for signing, @noble/hashes for blake2b — zero Sui SDK dependencies.
 *
 * Implements:
 * - BCS (Binary Canonical Serialization) for transaction encoding
 * - Intent signing (3-byte intent prefix before hashing)
 * - blake2b-256 transaction digest
 * - Sui signature scheme: flag || signature || publicKey
 */
import type { BalanceResult, BroadcastResult, ChainSigner, SignedTransaction, SignRequest } from "../types.js";
export declare class SuiSigner implements ChainSigner {
    /**
     * Sign a Sui transaction.
     *
     * Uses the `unsafe_moveCall` or `unsafe_transferSui` RPC to build
     * the transaction bytes server-side, then signs locally.
     * This avoids reimplementing the full Sui transaction builder in JS.
     */
    sign(request: SignRequest, privateKey: Uint8Array): Promise<SignedTransaction>;
    broadcast(rawTx: string, rpcUrl: string): Promise<BroadcastResult>;
    estimateGas(request: SignRequest): Promise<bigint>;
    getBalance(address: string, rpcUrl: string): Promise<BalanceResult>;
}
