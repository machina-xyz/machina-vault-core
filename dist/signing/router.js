/**
 * MAC-898: Chain router.
 * Maps chain families to their concrete signer implementations.
 */
import { EvmSigner } from "./chains/evm.js";
import { SolanaSigner } from "./chains/solana.js";
import { SuiSigner } from "./chains/sui.js";
const signers = {
    evm: new EvmSigner(),
    solana: new SolanaSigner(),
    sui: new SuiSigner(),
};
/**
 * Resolve a ChainSigner for the given chain family.
 * Throws if the family is not supported.
 */
export function getChainSigner(family) {
    const signer = signers[family];
    if (!signer) {
        throw new Error(`Unsupported chain family: "${family}". Supported: ${Object.keys(signers).join(", ")}`);
    }
    return signer;
}
