/**
 * MAC-898: Main signing orchestrator.
 * Routes signing requests to chain-specific signers and provides
 * a unified API for multi-chain transaction management.
 */
import type { BalanceResult, BroadcastResult, ChainConfig, SignedTransaction, SignRequest } from "./types.js";
export declare class SigningEngine {
    private readonly chains;
    constructor(chains: ChainConfig[]);
    /**
     * Sign a transaction for the target chain.
     * Routes to the appropriate chain-specific signer based on the chain family.
     */
    sign(request: SignRequest, privateKey: Uint8Array): Promise<SignedTransaction>;
    /**
     * Sign and immediately broadcast a transaction.
     */
    signAndBroadcast(request: SignRequest, privateKey: Uint8Array): Promise<BroadcastResult>;
    /**
     * Query native balances across one or more chains.
     * If `chainIds` is not provided, queries all configured chains.
     */
    getBalances(address: string, chainIds?: string[]): Promise<BalanceResult[]>;
    /**
     * Estimate gas/fees for a transaction on the target chain.
     */
    estimateGas(request: SignRequest): Promise<bigint>;
    /**
     * Return all configured chains.
     */
    getSupportedChains(): ChainConfig[];
    /**
     * Look up a chain config by ID.
     */
    getChain(chainId: string): ChainConfig | undefined;
}
//# sourceMappingURL=engine.d.ts.map