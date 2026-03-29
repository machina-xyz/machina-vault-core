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
import { ed25519 } from "@noble/curves/ed25519";
import { rpcCallWithRetry } from "../rpc.js";
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
/** SystemProgram program ID (all zeros) */
const SYSTEM_PROGRAM_ID = new Uint8Array(32);
/** SystemProgram.transfer instruction index (u32 LE) */
const TRANSFER_INSTRUCTION_INDEX = new Uint8Array([2, 0, 0, 0]);
/** SOL has 9 decimal places — 1 SOL = 1_000_000_000 lamports */
const LAMPORTS_PER_SOL = 1000000000n;
// ---------------------------------------------------------------------------
// Encoding utilities
// ---------------------------------------------------------------------------
function bytesToHex(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
}
function hexToBytes(hex) {
    const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
    if (clean.length === 0)
        return new Uint8Array(0);
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
        bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
    }
    return bytes;
}
/** Base58 alphabet (Bitcoin variant, used by Solana) */
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function bytesToBase58(bytes) {
    const digits = [0];
    for (const byte of bytes) {
        let carry = byte;
        for (let j = 0; j < digits.length; j++) {
            carry += digits[j] * 256;
            digits[j] = carry % 58;
            carry = Math.floor(carry / 58);
        }
        while (carry > 0) {
            digits.push(carry % 58);
            carry = Math.floor(carry / 58);
        }
    }
    let result = "";
    for (const byte of bytes) {
        if (byte === 0)
            result += B58_ALPHABET[0];
        else
            break;
    }
    for (let i = digits.length - 1; i >= 0; i--) {
        result += B58_ALPHABET[digits[i]];
    }
    return result;
}
function base58ToBytes(str) {
    const bytes = [0];
    for (const char of str) {
        const value = B58_ALPHABET.indexOf(char);
        if (value === -1)
            throw new Error(`Invalid base58 character: ${char}`);
        let carry = value;
        for (let j = 0; j < bytes.length; j++) {
            carry += bytes[j] * 58;
            bytes[j] = carry % 256;
            carry = Math.floor(carry / 256);
        }
        while (carry > 0) {
            bytes.push(carry % 256);
            carry = Math.floor(carry / 256);
        }
    }
    // Leading '1's in base58 = leading 0x00 bytes
    for (const char of str) {
        if (char === B58_ALPHABET[0])
            bytes.push(0);
        else
            break;
    }
    return new Uint8Array(bytes.reverse());
}
/**
 * Solana compact-u16 encoding.
 * Values 0-127 → 1 byte, 128-16383 → 2 bytes, 16384-65535 → 3 bytes.
 */
function encodeCompactU16(value) {
    if (value < 0 || value > 65535)
        throw new Error(`compact-u16 out of range: ${value}`);
    if (value < 0x80) {
        return new Uint8Array([value]);
    }
    if (value < 0x4000) {
        return new Uint8Array([(value & 0x7f) | 0x80, value >> 7]);
    }
    return new Uint8Array([(value & 0x7f) | 0x80, ((value >> 7) & 0x7f) | 0x80, value >> 14]);
}
/** Write a u64 as little-endian 8 bytes */
function u64ToLeBytes(value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number(value & 0xffn);
        value >>= 8n;
    }
    return buf;
}
/** Concatenate Uint8Arrays */
function concat(...arrays) {
    let totalLen = 0;
    for (const a of arrays)
        totalLen += a.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
        result.set(a, offset);
        offset += a.length;
    }
    return result;
}
// ---------------------------------------------------------------------------
// Solana Signer
// ---------------------------------------------------------------------------
export class SolanaSigner {
    /**
     * Build and sign a Solana transaction.
     * Supports SOL transfers via SystemProgram.transfer.
     * For program calls, pass `data` as hex-encoded instruction data.
     */
    async sign(request, privateKey) {
        const publicKey = ed25519.getPublicKey(privateKey);
        const fromAddress = bytesToBase58(publicKey);
        const toPublicKey = base58ToBytes(request.to);
        if (toPublicKey.length !== 32) {
            throw new Error(`Invalid Solana address: ${request.to}`);
        }
        // Fetch recent blockhash
        const blockhashResult = (await rpcCallWithRetry(request.chain.rpcUrl, "getLatestBlockhash", [{ commitment: "finalized" }]));
        const recentBlockhash = base58ToBytes(blockhashResult.value.blockhash);
        // Build the transaction message
        let messageBytes;
        if (request.data) {
            // Arbitrary instruction — the caller provides program ID in `to` and instruction data in `data`
            const programId = toPublicKey;
            const instructionData = hexToBytes(request.data);
            // Message format:
            // header: [numRequiredSignatures, numReadonlySignedAccounts, numReadonlyUnsignedAccounts]
            // accounts: [signer, programId]
            // recentBlockhash
            // instructions count + instruction
            const header = new Uint8Array([1, 0, 1]); // 1 signer, 0 readonly signed, 1 readonly unsigned (program)
            const accountKeys = concat(publicKey, programId);
            const numAccounts = encodeCompactU16(2);
            // Instruction: programIdIndex=1, accountIndexes=[0], data
            const numInstructions = encodeCompactU16(1);
            const programIdIndex = new Uint8Array([1]);
            const accountIndexes = encodeCompactU16(1);
            const accountIndex = new Uint8Array([0]);
            const dataLen = encodeCompactU16(instructionData.length);
            messageBytes = concat(header, numAccounts, accountKeys, recentBlockhash, numInstructions, programIdIndex, accountIndexes, accountIndex, dataLen, instructionData);
        }
        else {
            // SOL transfer via SystemProgram.transfer
            const lamports = request.value ?? 0n;
            // Instruction data: u32 instruction index (2 = transfer) + u64 lamports (LE)
            const instructionData = concat(TRANSFER_INSTRUCTION_INDEX, u64ToLeBytes(lamports));
            // Message header
            // numRequiredSignatures: 1 (the sender)
            // numReadonlySignedAccounts: 0
            // numReadonlyUnsignedAccounts: 1 (SystemProgram)
            const header = new Uint8Array([1, 0, 1]);
            // Account keys in order: [signer (writable), recipient (writable), SystemProgram (readonly)]
            const accountKeys = concat(publicKey, toPublicKey, SYSTEM_PROGRAM_ID);
            const numAccounts = encodeCompactU16(3);
            // Instruction:
            // programIdIndex: 2 (SystemProgram is at index 2)
            // accountIndexes: [0, 1] (from, to)
            // data: transfer instruction
            const numInstructions = encodeCompactU16(1);
            const programIdIndex = new Uint8Array([2]);
            const accountIndexes = encodeCompactU16(2);
            const accountIndexData = new Uint8Array([0, 1]);
            const dataLen = encodeCompactU16(instructionData.length);
            messageBytes = concat(header, numAccounts, accountKeys, recentBlockhash, numInstructions, programIdIndex, accountIndexes, accountIndexData, dataLen, instructionData);
        }
        // Sign the message
        const signature = ed25519.sign(messageBytes, privateKey);
        // Assemble the full transaction:
        // compact-u16(numSignatures) + signatures + message
        const numSignatures = encodeCompactU16(1);
        const rawTxBytes = concat(numSignatures, signature, messageBytes);
        const rawTxBase58 = bytesToBase58(rawTxBytes);
        // Transaction ID is the first signature (base58-encoded)
        const txHash = bytesToBase58(signature);
        return {
            rawTx: rawTxBase58,
            txHash,
            from: fromAddress,
            to: request.to,
            chain: request.chain.chainId,
        };
    }
    async broadcast(rawTx, rpcUrl) {
        try {
            // Solana accepts base58 or base64 encoded transactions
            const txHash = (await rpcCallWithRetry(rpcUrl, "sendTransaction", [rawTx, { encoding: "base58", skipPreflight: false }]));
            return {
                txHash,
                chain: "solana",
                status: "submitted",
            };
        }
        catch (err) {
            return {
                txHash: "",
                chain: "solana",
                status: "failed",
                error: err instanceof Error ? err.message : String(err),
            };
        }
    }
    async estimateGas(request) {
        // Solana uses a fixed base fee of 5000 lamports per signature.
        // Priority fees can be added via ComputeBudgetProgram but are optional.
        try {
            const feeResult = (await rpcCallWithRetry(request.chain.rpcUrl, "getRecentPrioritizationFees", []));
            if (feeResult.length > 0) {
                // Use median priority fee + base fee
                const fees = feeResult.map((f) => f.prioritizationFee).sort((a, b) => a - b);
                const median = fees[Math.floor(fees.length / 2)];
                return 5000n + BigInt(median);
            }
        }
        catch {
            // Fall through to default
        }
        return 5000n;
    }
    async getBalance(address, rpcUrl) {
        try {
            const result = (await rpcCallWithRetry(rpcUrl, "getBalance", [address, { commitment: "confirmed" }]));
            return {
                chain: "solana",
                address,
                native: {
                    balance: BigInt(result.value),
                    symbol: "SOL",
                    decimals: 9,
                },
                tokens: [],
            };
        }
        catch {
            return {
                chain: "solana",
                address,
                native: { balance: 0n, symbol: "SOL", decimals: 9 },
                tokens: [],
            };
        }
    }
}
//# sourceMappingURL=solana.js.map