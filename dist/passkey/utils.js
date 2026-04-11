/**
 * MACHINA Vault — Encoding utilities
 * Browser + Cloudflare Workers compatible (no Node.js Buffer)
 */
const BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/**
 * Encode a Uint8Array to a base64url string (no padding).
 */
export function base64urlEncode(bytes) {
    let result = "";
    const len = bytes.length;
    for (let i = 0; i < len; i += 3) {
        const b0 = bytes[i];
        const b1 = i + 1 < len ? bytes[i + 1] : 0;
        const b2 = i + 2 < len ? bytes[i + 2] : 0;
        result += BASE64URL_CHARS[(b0 >> 2)];
        result += BASE64URL_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)];
        if (i + 1 < len) {
            result += BASE64URL_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)];
        }
        if (i + 2 < len) {
            result += BASE64URL_CHARS[b2 & 0x3f];
        }
    }
    return result;
}
/**
 * Decode a base64url string (with or without padding) to a Uint8Array.
 */
export function base64urlDecode(str) {
    // Normalize: replace standard base64 chars and strip padding
    const input = str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const lookup = new Map();
    for (let i = 0; i < BASE64URL_CHARS.length; i++) {
        lookup.set(BASE64URL_CHARS[i], i);
    }
    const byteLength = Math.floor((input.length * 3) / 4);
    const result = new Uint8Array(byteLength);
    let offset = 0;
    for (let i = 0; i < input.length; i += 4) {
        const a = lookup.get(input[i]) ?? 0;
        const b = lookup.get(input[i + 1]) ?? 0;
        const c = i + 2 < input.length ? (lookup.get(input[i + 2]) ?? 0) : 0;
        const d = i + 3 < input.length ? (lookup.get(input[i + 3]) ?? 0) : 0;
        result[offset++] = (a << 2) | (b >> 4);
        if (i + 2 < input.length) {
            result[offset++] = ((b & 0x0f) << 4) | (c >> 2);
        }
        if (i + 3 < input.length) {
            result[offset++] = ((c & 0x03) << 6) | d;
        }
    }
    return result;
}
/**
 * Convert a Uint8Array to a lowercase hex string.
 */
export function bufferToHex(buf) {
    let hex = "";
    for (let i = 0; i < buf.length; i++) {
        hex += buf[i].toString(16).padStart(2, "0");
    }
    return hex;
}
/**
 * Convert a hex string (with or without 0x prefix) to a Uint8Array.
 */
export function hexToBuffer(hex) {
    const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
    if (cleaned.length % 2 !== 0) {
        throw new Error("Hex string must have an even number of characters");
    }
    const bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2) {
        bytes[i / 2] = parseInt(cleaned.slice(i, i + 2), 16);
    }
    return bytes;
}
/**
 * Concatenate multiple Uint8Arrays into a single Uint8Array.
 */
export function concatBuffers(...buffers) {
    const totalLength = buffers.reduce((sum, buf) => sum + buf.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const buf of buffers) {
        result.set(buf, offset);
        offset += buf.length;
    }
    return result;
}
