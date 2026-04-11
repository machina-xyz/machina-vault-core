/**
 * MACHINA Vault — Encoding utilities
 * Browser + Cloudflare Workers compatible (no Node.js Buffer)
 */
/**
 * Encode a Uint8Array to a base64url string (no padding).
 */
export declare function base64urlEncode(bytes: Uint8Array): string;
/**
 * Decode a base64url string (with or without padding) to a Uint8Array.
 */
export declare function base64urlDecode(str: string): Uint8Array;
/**
 * Convert a Uint8Array to a lowercase hex string.
 */
export declare function bufferToHex(buf: Uint8Array): string;
/**
 * Convert a hex string (with or without 0x prefix) to a Uint8Array.
 */
export declare function hexToBuffer(hex: string): Uint8Array;
/**
 * Concatenate multiple Uint8Arrays into a single Uint8Array.
 */
export declare function concatBuffers(...buffers: Uint8Array[]): Uint8Array;
