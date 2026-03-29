/**
 * MAC-898: EVM chain signer.
 * Fully functional EIP-1559 (Type 2) transaction signing.
 * Uses @noble/curves for secp256k1 and @noble/hashes for keccak256.
 * Custom RLP encoder — zero external dependencies for encoding.
 */
import type { BalanceResult, BroadcastResult, ChainSigner, SignedTransaction, SignRequest } from "../types.js";
export type RLPInput = Uint8Array | bigint | string | number | RLPInput[];
export declare function rlpEncode(input: RLPInput): Uint8Array;
export declare class EvmSigner implements ChainSigner {
    sign(request: SignRequest, privateKey: Uint8Array): Promise<SignedTransaction>;
    broadcast(rawTx: string, rpcUrl: string): Promise<BroadcastResult>;
    estimateGas(request: SignRequest): Promise<bigint>;
    getBalance(address: string, rpcUrl: string): Promise<BalanceResult>;
    private getNonce;
}
//# sourceMappingURL=evm.d.ts.map