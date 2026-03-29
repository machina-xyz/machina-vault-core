/**
 * MACHINA Vault — JWT Creation & Verification
 * HMAC-SHA256 (HS256) JWTs using Web Crypto API only.
 * No Node.js APIs — runs on Cloudflare Workers V8.
 */
declare function base64urlEncode(data: Uint8Array): string;
declare function base64urlDecode(str: string): Uint8Array;
declare function textToBytes(text: string): Uint8Array;
declare function bytesToText(bytes: Uint8Array): string;
/**
 * Create an HS256 JWT.
 *
 * @param payload - Claims to include in the token
 * @param secret  - HMAC signing key (raw bytes)
 * @param expiresInMs - Token lifetime in milliseconds (default 1 hour)
 * @returns Signed JWT string
 */
export declare function createJWT(payload: Record<string, unknown>, secret: Uint8Array, expiresInMs?: number): Promise<string>;
/**
 * Verify an HS256 JWT and return its payload.
 *
 * @param token  - The JWT string
 * @param secret - HMAC verification key (raw bytes)
 * @returns Verification result with decoded payload on success
 */
export declare function verifyJWT(token: string, secret: Uint8Array): Promise<{
    valid: boolean;
    payload?: Record<string, unknown>;
    error?: string;
}>;
/**
 * Decode a JWT without verifying its signature.
 * Useful for inspecting tokens before full verification.
 *
 * @param token - The JWT string
 * @returns Decoded header and payload
 */
export declare function decodeJWT(token: string): {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
};
export { base64urlEncode, base64urlDecode, textToBytes, bytesToText };
//# sourceMappingURL=jwt.d.ts.map