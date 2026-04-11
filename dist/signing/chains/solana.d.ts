/**
 * MAC-898: Solana chain signer.
 * Real ed25519 signing with Solana transaction serialization.
 * Uses @noble/curves for signing — zero Solana SDK dependencies.
 *
 * Implements the Solana transaction wire format:
 * - Compact-u16 encoding for array lengths
 * - SystemProgram.transfer instruction layout
 * - Transaction message v0 (legacy) format
 * - Recent blockhash integration via RPC
 */
import type { BalanceResult, BroadcastResult, ChainSigner, SignedTransaction, SignRequest } from "../types.js";
export declare class SolanaSigner implements ChainSigner {
    /**
     * Build and sign a Solana transaction.
     * Supports SOL transfers via SystemProgram.transfer.
     * For program calls, pass `data` as hex-encoded instruction data.
     */
    sign(request: SignRequest, privateKey: Uint8Array): Promise<SignedTransaction>;
    broadcast(rawTx: string, rpcUrl: string): Promise<BroadcastResult>;
    estimateGas(request: SignRequest): Promise<bigint>;
    getBalance(address: string, rpcUrl: string): Promise<BalanceResult>;
}
