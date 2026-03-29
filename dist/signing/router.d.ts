/**
 * MAC-898: Chain router.
 * Maps chain families to their concrete signer implementations.
 */
import type { ChainFamily, ChainSigner } from "./types.js";
/**
 * Resolve a ChainSigner for the given chain family.
 * Throws if the family is not supported.
 */
export declare function getChainSigner(family: ChainFamily): ChainSigner;
//# sourceMappingURL=router.d.ts.map