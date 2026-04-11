/**
 * MAC-898: Main signing orchestrator.
 * Routes signing requests to chain-specific signers and provides
 * a unified API for multi-chain transaction management.
 */
import { getChainSigner } from "./router.js";
export class SigningEngine {
    chains;
    constructor(chains) {
        this.chains = new Map();
        for (const chain of chains) {
            this.chains.set(chain.chainId, chain);
        }
    }
    /**
     * Sign a transaction for the target chain.
     * Routes to the appropriate chain-specific signer based on the chain family.
     */
    async sign(request, privateKey) {
        const signer = getChainSigner(request.chain.family);
        return signer.sign(request, privateKey);
    }
    /**
     * Sign and immediately broadcast a transaction.
     */
    async signAndBroadcast(request, privateKey) {
        const signer = getChainSigner(request.chain.family);
        const signed = await signer.sign(request, privateKey);
        return signer.broadcast(signed.rawTx, request.chain.rpcUrl);
    }
    /**
     * Query native balances across one or more chains.
     * If `chainIds` is not provided, queries all configured chains.
     */
    async getBalances(address, chainIds) {
        const targetChains = chainIds
            ? chainIds
                .map((id) => this.chains.get(id))
                .filter((c) => c !== undefined)
            : Array.from(this.chains.values());
        const results = await Promise.allSettled(targetChains.map(async (chain) => {
            const signer = getChainSigner(chain.family);
            const result = await signer.getBalance(address, chain.rpcUrl);
            // Override with chain-specific currency info
            return {
                ...result,
                chain: chain.chainId,
                native: {
                    ...result.native,
                    symbol: chain.nativeCurrency.symbol,
                    decimals: chain.nativeCurrency.decimals,
                },
            };
        }));
        return results
            .filter((r) => r.status === "fulfilled")
            .map((r) => r.value);
    }
    /**
     * Estimate gas/fees for a transaction on the target chain.
     */
    async estimateGas(request) {
        const signer = getChainSigner(request.chain.family);
        return signer.estimateGas(request);
    }
    /**
     * Return all configured chains.
     */
    getSupportedChains() {
        return Array.from(this.chains.values());
    }
    /**
     * Look up a chain config by ID.
     */
    getChain(chainId) {
        return this.chains.get(chainId);
    }
}
