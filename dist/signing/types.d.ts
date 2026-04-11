/**
 * MAC-898: Chain-Agnostic Signing Engine
 * Type definitions for multi-chain transaction signing.
 */
export type ChainFamily = "evm" | "solana" | "sui" | "aptos" | "cosmos";
export interface ChainConfig {
    chainId: string;
    family: ChainFamily;
    name: string;
    rpcUrl: string;
    nativeCurrency: {
        name: string;
        symbol: string;
        decimals: number;
    };
    blockExplorerUrl?: string;
}
export interface SignRequest {
    keyId: string;
    chain: ChainConfig;
    to: string;
    data?: string;
    value?: bigint;
    gasLimit?: bigint;
    maxFeePerGas?: bigint;
    maxPriorityFeePerGas?: bigint;
    nonce?: number;
}
export interface SignedTransaction {
    rawTx: string;
    txHash: string;
    from: string;
    to: string;
    chain: string;
}
export interface BroadcastResult {
    txHash: string;
    chain: string;
    status: "submitted" | "confirmed" | "failed";
    blockNumber?: number;
    error?: string;
}
export interface BalanceResult {
    chain: string;
    address: string;
    native: {
        balance: bigint;
        symbol: string;
        decimals: number;
    };
    tokens: Array<{
        address: string;
        symbol: string;
        balance: bigint;
        decimals: number;
    }>;
}
/**
 * Chain-specific signer interface.
 * Each chain family implements this to handle its signing, broadcasting,
 * gas estimation, and balance queries.
 */
export interface ChainSigner {
    sign(request: SignRequest, privateKey: Uint8Array): Promise<SignedTransaction>;
    broadcast(rawTx: string, rpcUrl: string): Promise<BroadcastResult>;
    estimateGas(request: SignRequest): Promise<bigint>;
    getBalance(address: string, rpcUrl: string): Promise<BalanceResult>;
}
