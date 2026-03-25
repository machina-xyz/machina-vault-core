/**
 * MAC-898: EVM chain signer.
 * Fully functional EIP-1559 (Type 2) transaction signing.
 * Uses @noble/curves for secp256k1 and @noble/hashes for keccak256.
 * Custom RLP encoder — zero external dependencies for encoding.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import type {
  BalanceResult,
  BroadcastResult,
  ChainSigner,
  SignedTransaction,
  SignRequest,
} from "../types.js";
import { rpcCallWithRetry } from "../rpc.js";

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length === 0) return new Uint8Array(0);
  if (clean.length % 2 !== 0) {
    throw new Error(`Invalid hex string: odd length`);
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "0x";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function bigintToBytes(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array(0);
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = "0" + hex;
  return hexToBytes(hex);
}

function numberToBytes(value: number): Uint8Array {
  return bigintToBytes(BigInt(value));
}

// ---------------------------------------------------------------------------
// Minimal RLP Encoder (EIP-2718 compatible)
// ---------------------------------------------------------------------------

export type RLPInput = Uint8Array | bigint | string | number | RLPInput[];

function encodeLength(len: number, offset: number): Uint8Array {
  if (len < 56) {
    return new Uint8Array([offset + len]);
  }
  const lenBytes = bigintToBytes(BigInt(len));
  const result = new Uint8Array(1 + lenBytes.length);
  result[0] = offset + 55 + lenBytes.length;
  result.set(lenBytes, 1);
  return result;
}

export function rlpEncode(input: RLPInput): Uint8Array {
  if (input instanceof Uint8Array) {
    // Single byte in [0x00, 0x7f] range
    if (input.length === 1 && input[0] < 0x80) {
      return input;
    }
    // Short string (0-55 bytes)
    if (input.length <= 55) {
      const result = new Uint8Array(1 + input.length);
      result[0] = 0x80 + input.length;
      result.set(input, 1);
      return result;
    }
    // Long string (>55 bytes)
    const lenBytes = bigintToBytes(BigInt(input.length));
    const result = new Uint8Array(1 + lenBytes.length + input.length);
    result[0] = 0xb7 + lenBytes.length;
    result.set(lenBytes, 1);
    result.set(input, 1 + lenBytes.length);
    return result;
  }

  if (typeof input === "bigint") {
    if (input === 0n) return new Uint8Array([0x80]); // empty string = 0
    return rlpEncode(bigintToBytes(input));
  }

  if (typeof input === "number") {
    if (input === 0) return new Uint8Array([0x80]);
    return rlpEncode(numberToBytes(input));
  }

  if (typeof input === "string") {
    const bytes = hexToBytes(input);
    return rlpEncode(bytes);
  }

  if (Array.isArray(input)) {
    const encoded = input.map((item) => rlpEncode(item));
    let totalLength = 0;
    for (const e of encoded) totalLength += e.length;

    const prefix = encodeLength(totalLength, 0xc0);
    const result = new Uint8Array(prefix.length + totalLength);
    result.set(prefix, 0);
    let offset = prefix.length;
    for (const e of encoded) {
      result.set(e, offset);
      offset += e.length;
    }
    return result;
  }

  throw new Error(`Unsupported RLP input type: ${typeof input}`);
}

// ---------------------------------------------------------------------------
// Address derivation
// ---------------------------------------------------------------------------

function privateKeyToAddress(privateKey: Uint8Array): string {
  const pubkey = secp256k1.getPublicKey(privateKey, false); // uncompressed
  // Remove the 0x04 prefix, hash the remaining 64 bytes
  const hash = keccak_256(pubkey.slice(1));
  // Take last 20 bytes
  return bytesToHex(hash.slice(12));
}

// ---------------------------------------------------------------------------
// EVM Signer
// ---------------------------------------------------------------------------

export class EvmSigner implements ChainSigner {
  async sign(
    request: SignRequest,
    privateKey: Uint8Array,
  ): Promise<SignedTransaction> {
    const { chain, to, data, value, gasLimit, maxFeePerGas, maxPriorityFeePerGas } = request;
    const chainIdNum = parseInt(chain.chainId, 10);
    const from = privateKeyToAddress(privateKey);

    // Resolve nonce
    const nonce =
      request.nonce ??
      (await this.getNonce(from, chain.rpcUrl));

    // Resolve gas parameters if not provided
    const resolvedMaxPriorityFeePerGas = maxPriorityFeePerGas ?? 1_500_000_000n; // 1.5 gwei
    const resolvedMaxFeePerGas = maxFeePerGas ?? 30_000_000_000n; // 30 gwei
    const resolvedGasLimit = gasLimit ?? (await this.estimateGas(request));

    // Build unsigned EIP-1559 transaction fields
    // [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]
    const txFields: RLPInput[] = [
      BigInt(chainIdNum),
      BigInt(nonce),
      resolvedMaxPriorityFeePerGas,
      resolvedMaxFeePerGas,
      resolvedGasLimit,
      hexToBytes(to),
      value ?? 0n,
      data ? hexToBytes(data) : new Uint8Array(0),
      [], // accessList — empty for now
    ];

    // Serialize for signing: 0x02 || RLP(fields)
    const encodedUnsigned = rlpEncode(txFields);
    const toSign = new Uint8Array(1 + encodedUnsigned.length);
    toSign[0] = 0x02; // EIP-1559 type
    toSign.set(encodedUnsigned, 1);

    // Hash
    const msgHash = keccak_256(toSign);

    // Sign with secp256k1
    const sig = secp256k1.sign(msgHash, privateKey);
    const r = sig.r;
    const s = sig.s;
    const v = BigInt(sig.recovery);

    // Build signed transaction fields
    // [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s]
    const signedFields: RLPInput[] = [
      ...txFields,
      v,
      bigintToBytes(r),
      bigintToBytes(s),
    ];

    const encodedSigned = rlpEncode(signedFields);
    const rawTx = new Uint8Array(1 + encodedSigned.length);
    rawTx[0] = 0x02;
    rawTx.set(encodedSigned, 1);

    const txHash = bytesToHex(keccak_256(rawTx));

    return {
      rawTx: bytesToHex(rawTx),
      txHash,
      from,
      to,
      chain: chain.chainId,
    };
  }

  async broadcast(rawTx: string, rpcUrl: string): Promise<BroadcastResult> {
    try {
      const txHash = (await rpcCallWithRetry(
        rpcUrl,
        "eth_sendRawTransaction",
        [rawTx],
      )) as string;

      return {
        txHash,
        chain: "evm",
        status: "submitted",
      };
    } catch (err) {
      return {
        txHash: "",
        chain: "evm",
        status: "failed",
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  async estimateGas(request: SignRequest): Promise<bigint> {
    const from =
      "0x0000000000000000000000000000000000000000"; // placeholder for estimation

    const params: Record<string, string> = {
      from,
      to: request.to,
    };

    if (request.data) {
      params.data = request.data.startsWith("0x")
        ? request.data
        : `0x${request.data}`;
    }

    if (request.value !== undefined && request.value !== 0n) {
      params.value = "0x" + request.value.toString(16);
    }

    try {
      const result = (await rpcCallWithRetry(
        request.chain.rpcUrl,
        "eth_estimateGas",
        [params],
      )) as string;

      const gas = BigInt(result);
      // Add 20% buffer
      return (gas * 120n) / 100n;
    } catch {
      // Default gas limit if estimation fails
      return 21_000n;
    }
  }

  async getBalance(address: string, rpcUrl: string): Promise<BalanceResult> {
    const result = (await rpcCallWithRetry(
      rpcUrl,
      "eth_getBalance",
      [address, "latest"],
    )) as string;

    const balance = BigInt(result);

    return {
      chain: "evm",
      address,
      native: {
        balance,
        symbol: "ETH",
        decimals: 18,
      },
      tokens: [], // Token balance queries require additional contract calls
    };
  }

  // ------- Internal helpers -------

  private async getNonce(address: string, rpcUrl: string): Promise<number> {
    const result = (await rpcCallWithRetry(
      rpcUrl,
      "eth_getTransactionCount",
      [address, "pending"],
    )) as string;

    return Number(BigInt(result));
  }
}
