/**
 * MAC-898: Main signing orchestrator.
 * Routes signing requests to chain-specific signers and provides
 * a unified API for multi-chain transaction management.
 */

import type {
  BalanceResult,
  BroadcastResult,
  ChainConfig,
  SignedTransaction,
  SignRequest,
} from "./types.js";
import { getChainSigner } from "./router.js";

export class SigningEngine {
  private readonly chains: Map<string, ChainConfig>;

  constructor(chains: ChainConfig[]) {
    this.chains = new Map();
    for (const chain of chains) {
      this.chains.set(chain.chainId, chain);
    }
  }

  /**
   * Sign a transaction for the target chain.
   * Routes to the appropriate chain-specific signer based on the chain family.
   */
  async sign(
    request: SignRequest,
    privateKey: Uint8Array,
  ): Promise<SignedTransaction> {
    const signer = getChainSigner(request.chain.family);
    return signer.sign(request, privateKey);
  }

  /**
   * Sign and immediately broadcast a transaction.
   */
  async signAndBroadcast(
    request: SignRequest,
    privateKey: Uint8Array,
  ): Promise<BroadcastResult> {
    const signer = getChainSigner(request.chain.family);
    const signed = await signer.sign(request, privateKey);
    return signer.broadcast(signed.rawTx, request.chain.rpcUrl);
  }

  /**
   * Query native balances across one or more chains.
   * If `chainIds` is not provided, queries all configured chains.
   */
  async getBalances(
    address: string,
    chainIds?: string[],
  ): Promise<BalanceResult[]> {
    const targetChains = chainIds
      ? chainIds
          .map((id) => this.chains.get(id))
          .filter((c): c is ChainConfig => c !== undefined)
      : Array.from(this.chains.values());

    const results = await Promise.allSettled(
      targetChains.map(async (chain) => {
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
      }),
    );

    return results
      .filter(
        (r): r is PromiseFulfilledResult<BalanceResult> =>
          r.status === "fulfilled",
      )
      .map((r) => r.value);
  }

  /**
   * Estimate gas/fees for a transaction on the target chain.
   */
  async estimateGas(request: SignRequest): Promise<bigint> {
    const signer = getChainSigner(request.chain.family);
    return signer.estimateGas(request);
  }

  /**
   * Return all configured chains.
   */
  getSupportedChains(): ChainConfig[] {
    return Array.from(this.chains.values());
  }

  /**
   * Look up a chain config by ID.
   */
  getChain(chainId: string): ChainConfig | undefined {
    return this.chains.get(chainId);
  }
}
