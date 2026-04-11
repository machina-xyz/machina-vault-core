/**
 * MACHINA Vault — Server-side verification (Cloudflare Workers compatible)
 *
 * Verifies WebAuthn registration and authentication responses using
 * @noble/curves for P-256 signature verification. No Node.js dependencies.
 */
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { validateChallenge, markChallengeUsed } from "./challenge.js";
import { concatBuffers } from "./utils.js";
/**
 * Verify a WebAuthn registration response.
 *
 * Checks that the credential was created with the expected challenge and
 * origin. Should be called server-side after receiving the credential
 * from the browser.
 *
 * @param credential - The credential returned from createVaultCredential
 * @param challenge - The challenge that was issued for this registration
 * @param expectedOrigin - The expected origin (e.g. "https://machina.money")
 * @returns true if the registration is valid
 */
export function verifyRegistration(credential, challenge, expectedOrigin) {
    // Validate the challenge is still fresh and unused
    if (!validateChallenge(challenge)) {
        return false;
    }
    // Verify the credential has valid public key coordinates
    if (credential.publicKeyX.length !== 32 || credential.publicKeyY.length !== 32) {
        return false;
    }
    // Verify the public key is a valid P-256 point
    try {
        const uncompressedKey = concatBuffers(new Uint8Array([0x04]), credential.publicKeyX, credential.publicKeyY);
        // This will throw if the point is not on the P-256 curve
        p256.ProjectivePoint.fromHex(uncompressedKey);
    }
    catch {
        return false;
    }
    // Verify the origin matches
    const rpIdFromOrigin = extractRpIdFromOrigin(expectedOrigin);
    if (rpIdFromOrigin !== credential.rpId) {
        return false;
    }
    // Mark the challenge as consumed
    markChallengeUsed(challenge);
    return true;
}
/**
 * Verify a WebAuthn authentication response.
 *
 * Verifies the P-256 ECDSA signature over (authenticatorData || sha256(clientDataJSON))
 * using the stored public key. Also checks sign count for replay protection.
 *
 * @param auth - The authentication result from authenticateVault
 * @param storedCredential - The previously registered credential
 * @param challenge - The challenge that was issued for this authentication
 * @param expectedOrigin - The expected origin (e.g. "https://machina.money")
 * @returns true if the authentication is valid
 */
export function verifyAuthentication(auth, storedCredential, challenge, expectedOrigin) {
    // Validate the challenge
    if (!validateChallenge(challenge)) {
        return false;
    }
    // Verify the credential ID matches
    if (auth.credentialId !== storedCredential.credentialId) {
        return false;
    }
    // Parse and validate the client data JSON
    const decoder = new TextDecoder();
    let clientData;
    try {
        clientData = JSON.parse(decoder.decode(auth.clientDataJSON));
    }
    catch {
        return false;
    }
    // Verify the client data fields
    if (clientData.type !== "webauthn.get") {
        return false;
    }
    if (clientData.origin !== expectedOrigin) {
        return false;
    }
    // Verify the challenge in client data matches the issued challenge
    const expectedChallengeB64 = uint8ArrayToBase64url(challenge.challenge);
    if (clientData.challenge !== expectedChallengeB64) {
        return false;
    }
    // Verify the authenticator data
    if (auth.authenticatorData.length < 37) {
        return false;
    }
    // Extract and verify sign count (bytes 33-36, big-endian)
    const signCount = (auth.authenticatorData[33] << 24) |
        (auth.authenticatorData[34] << 16) |
        (auth.authenticatorData[35] << 8) |
        auth.authenticatorData[36];
    // Sign count must be increasing for replay protection
    // (sign count of 0 means the authenticator doesn't support counters, skip check)
    if (signCount !== 0 && storedCredential.signCount !== 0) {
        if (signCount <= storedCredential.signCount) {
            return false;
        }
    }
    // Compute the signed data: authenticatorData || sha256(clientDataJSON)
    const clientDataHash = sha256(auth.clientDataJSON);
    const signedData = concatBuffers(auth.authenticatorData, clientDataHash);
    // Construct the uncompressed public key (0x04 || x || y)
    const uncompressedKey = concatBuffers(new Uint8Array([0x04]), storedCredential.publicKeyX, storedCredential.publicKeyY);
    // Parse the DER-encoded signature to raw r,s format for @noble/curves
    const rawSignature = derToRawSignature(auth.signature);
    if (!rawSignature) {
        return false;
    }
    // Verify the P-256 ECDSA signature
    // The WebAuthn spec signs over sha256(signedData) for ES256
    const messageHash = sha256(signedData);
    let signatureValid;
    try {
        signatureValid = p256.verify(rawSignature, messageHash, uncompressedKey);
    }
    catch {
        return false;
    }
    if (!signatureValid) {
        return false;
    }
    // Update the stored sign count
    storedCredential.signCount = signCount;
    // Mark the challenge as consumed
    markChallengeUsed(challenge);
    return true;
}
/**
 * Convert a DER-encoded ECDSA signature to raw (r || s) format.
 *
 * DER structure: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
 *
 * @returns 64-byte Uint8Array (32 bytes r + 32 bytes s), or null if invalid
 */
function derToRawSignature(der) {
    try {
        if (der[0] !== 0x30) {
            return null;
        }
        let offset = 2; // Skip 0x30 and total length
        // Read R
        if (der[offset] !== 0x02)
            return null;
        offset++;
        const rLen = der[offset];
        offset++;
        let r = der.slice(offset, offset + rLen);
        offset += rLen;
        // Read S
        if (der[offset] !== 0x02)
            return null;
        offset++;
        const sLen = der[offset];
        offset++;
        let s = der.slice(offset, offset + sLen);
        // Remove leading zeros (DER uses signed integers, may prepend 0x00)
        if (r.length > 32 && r[0] === 0x00) {
            r = r.slice(r.length - 32);
        }
        if (s.length > 32 && s[0] === 0x00) {
            s = s.slice(s.length - 32);
        }
        // Pad to 32 bytes if shorter
        const result = new Uint8Array(64);
        result.set(r, 32 - r.length);
        result.set(s, 64 - s.length);
        return result;
    }
    catch {
        return null;
    }
}
/**
 * Convert a Uint8Array to a base64url string (no padding).
 * Local helper to avoid circular dependency with utils.
 */
function uint8ArrayToBase64url(bytes) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let result = "";
    for (let i = 0; i < bytes.length; i += 3) {
        const b0 = bytes[i];
        const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
        const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
        result += chars[(b0 >> 2)];
        result += chars[((b0 & 0x03) << 4) | (b1 >> 4)];
        if (i + 1 < bytes.length)
            result += chars[((b1 & 0x0f) << 2) | (b2 >> 6)];
        if (i + 2 < bytes.length)
            result += chars[b2 & 0x3f];
    }
    return result;
}
/**
 * Extract the RP ID (domain) from an origin URL.
 * e.g. "https://machina.money" -> "machina.money"
 */
function extractRpIdFromOrigin(origin) {
    try {
        const url = new URL(origin);
        return url.hostname;
    }
    catch {
        return origin;
    }
}
