/**
 * MAC-898: Chain router.
 * Maps chain families to their concrete signer implementations.
 */

import type { ChainFamily, ChainSigner } from "./types.js";
import { EvmSigner } from "./chains/evm.js";
import { SolanaSigner } from "./chains/solana.js";
import { SuiSigner } from "./chains/sui.js";

const signers: Record<string, ChainSigner> = {
  evm: new EvmSigner(),
  solana: new SolanaSigner(),
  sui: new SuiSigner(),
};

/**
 * Resolve a ChainSigner for the given chain family.
 * Throws if the family is not supported.
 */
export function getChainSigner(family: ChainFamily): ChainSigner {
  const signer = signers[family];
  if (!signer) {
    throw new Error(
      `Unsupported chain family: "${family}". Supported: ${Object.keys(signers).join(", ")}`,
    );
  }
  return signer;
}
