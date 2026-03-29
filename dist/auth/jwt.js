/**
 * MACHINA Vault — JWT Creation & Verification
 * HMAC-SHA256 (HS256) JWTs using Web Crypto API only.
 * No Node.js APIs — runs on Cloudflare Workers V8.
 */
// ---------------------------------------------------------------------------
// Base64url helpers (no Buffer, no atob/btoa for binary)
// ---------------------------------------------------------------------------
const BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function base64urlEncode(data) {
    let result = "";
    const len = data.length;
    for (let i = 0; i < len; i += 3) {
        const a = data[i];
        const b = i + 1 < len ? data[i + 1] : 0;
        const c = i + 2 < len ? data[i + 2] : 0;
        result += BASE64URL_CHARS[(a >> 2) & 0x3f];
        result += BASE64URL_CHARS[((a << 4) | (b >> 4)) & 0x3f];
        if (i + 1 < len) {
            result += BASE64URL_CHARS[((b << 2) | (c >> 6)) & 0x3f];
        }
        if (i + 2 < len) {
            result += BASE64URL_CHARS[c & 0x3f];
        }
    }
    return result;
}
function base64urlDecode(str) {
    // Build reverse lookup
    const lookup = new Uint8Array(128);
    for (let i = 0; i < BASE64URL_CHARS.length; i++) {
        lookup[BASE64URL_CHARS.charCodeAt(i)] = i;
    }
    const len = str.length;
    const padded = len % 4;
    const totalBytes = Math.floor((len * 3) / 4) - (padded === 2 ? 1 : padded === 3 ? 0 : 0);
    // Calculate output length precisely
    const fullGroups = Math.floor(len / 4);
    const remainder = len % 4;
    let outputLen = fullGroups * 3;
    if (remainder === 2)
        outputLen += 1;
    else if (remainder === 3)
        outputLen += 2;
    const out = new Uint8Array(outputLen);
    let pos = 0;
    for (let i = 0; i < len; i += 4) {
        const a = lookup[str.charCodeAt(i)];
        const b = i + 1 < len ? lookup[str.charCodeAt(i + 1)] : 0;
        const c = i + 2 < len ? lookup[str.charCodeAt(i + 2)] : 0;
        const d = i + 3 < len ? lookup[str.charCodeAt(i + 3)] : 0;
        if (pos < outputLen)
            out[pos++] = (a << 2) | (b >> 4);
        if (pos < outputLen)
            out[pos++] = ((b << 4) | (c >> 2)) & 0xff;
        if (pos < outputLen)
            out[pos++] = ((c << 6) | d) & 0xff;
    }
    return out;
}
function textToBytes(text) {
    const encoder = new TextEncoder();
    return encoder.encode(text);
}
function bytesToText(bytes) {
    const decoder = new TextDecoder();
    return decoder.decode(bytes);
}
function jsonToBase64url(obj) {
    return base64urlEncode(textToBytes(JSON.stringify(obj)));
}
function base64urlToJson(str) {
    return JSON.parse(bytesToText(base64urlDecode(str)));
}
// ---------------------------------------------------------------------------
// HMAC-SHA256 helpers
// ---------------------------------------------------------------------------
async function importHmacKey(secret) {
    return crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function hmacSign(key, data) {
    const sig = await crypto.subtle.sign("HMAC", key, data);
    return new Uint8Array(sig);
}
async function hmacVerify(key, signature, data) {
    return crypto.subtle.verify("HMAC", key, signature, data);
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
/**
 * Create an HS256 JWT.
 *
 * @param payload - Claims to include in the token
 * @param secret  - HMAC signing key (raw bytes)
 * @param expiresInMs - Token lifetime in milliseconds (default 1 hour)
 * @returns Signed JWT string
 */
export async function createJWT(payload, secret, expiresInMs = 3_600_000) {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
        ...payload,
        iat: payload.iat ?? now,
        exp: payload.exp ?? now + Math.floor(expiresInMs / 1000),
    };
    const header = { alg: "HS256", typ: "JWT" };
    const headerB64 = jsonToBase64url(header);
    const payloadB64 = jsonToBase64url(claims);
    const signingInput = `${headerB64}.${payloadB64}`;
    const key = await importHmacKey(secret);
    const signature = await hmacSign(key, textToBytes(signingInput));
    return `${signingInput}.${base64urlEncode(signature)}`;
}
/**
 * Verify an HS256 JWT and return its payload.
 *
 * @param token  - The JWT string
 * @param secret - HMAC verification key (raw bytes)
 * @returns Verification result with decoded payload on success
 */
export async function verifyJWT(token, secret) {
    const parts = token.split(".");
    if (parts.length !== 3) {
        return { valid: false, error: "Invalid JWT format: expected 3 parts" };
    }
    const [headerB64, payloadB64, signatureB64] = parts;
    // Decode and validate header
    let header;
    try {
        header = base64urlToJson(headerB64);
    }
    catch {
        return { valid: false, error: "Invalid JWT header encoding" };
    }
    if (header.alg !== "HS256") {
        return { valid: false, error: `Unsupported algorithm: ${header.alg}` };
    }
    // Verify signature
    const signingInput = textToBytes(`${headerB64}.${payloadB64}`);
    const signature = base64urlDecode(signatureB64);
    const key = await importHmacKey(secret);
    const isValid = await hmacVerify(key, signature, signingInput);
    if (!isValid) {
        return { valid: false, error: "Invalid signature" };
    }
    // Decode payload
    let payload;
    try {
        payload = base64urlToJson(payloadB64);
    }
    catch {
        return { valid: false, error: "Invalid JWT payload encoding" };
    }
    // Check expiration
    if (typeof payload.exp === "number" && payload.exp < Math.floor(Date.now() / 1000)) {
        return { valid: false, error: "Token expired" };
    }
    return { valid: true, payload };
}
/**
 * Decode a JWT without verifying its signature.
 * Useful for inspecting tokens before full verification.
 *
 * @param token - The JWT string
 * @returns Decoded header and payload
 */
export function decodeJWT(token) {
    const parts = token.split(".");
    if (parts.length !== 3) {
        throw new Error("Invalid JWT format: expected 3 parts");
    }
    return {
        header: base64urlToJson(parts[0]),
        payload: base64urlToJson(parts[1]),
    };
}
// Re-export helpers used by other auth modules
export { base64urlEncode, base64urlDecode, textToBytes, bytesToText };
//# sourceMappingURL=jwt.js.map