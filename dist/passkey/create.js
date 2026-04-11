/**
 * MACHINA Vault — WebAuthn credential creation (browser-side)
 *
 * Creates a P-256 passkey credential via the WebAuthn API and derives
 * a deterministic EVM vault address from the public key.
 */
import { deriveVaultAddress } from "./derive-address.js";
import { base64urlEncode } from "./utils.js";
/** Default timeout: 5 minutes */
const DEFAULT_TIMEOUT_MS = 300_000;
/**
 * Create a new WebAuthn credential and derive the corresponding vault address.
 *
 * Must be called in a browser context with access to `navigator.credentials`.
 *
 * @throws If the WebAuthn API is unavailable, the user cancels, or the
 *         authenticator response cannot be parsed.
 */
export async function createVaultCredential(options) {
    if (typeof navigator === "undefined" ||
        typeof navigator.credentials === "undefined") {
        throw new Error("WebAuthn API is not available in this environment. " +
            "createVaultCredential must be called in a browser context.");
    }
    // Encode the user ID as UTF-8 bytes
    const encoder = new TextEncoder();
    const userIdBytes = encoder.encode(options.userId);
    // Generate a random challenge for the creation ceremony
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    const publicKeyOptions = {
        rp: {
            id: options.rpId,
            name: options.rpName,
        },
        user: {
            id: userIdBytes,
            name: options.userName,
            displayName: options.userName,
        },
        challenge,
        pubKeyCredParams: [
            { alg: -7, type: "public-key" }, // ES256 (P-256 + SHA-256)
        ],
        authenticatorSelection: {
            authenticatorAttachment: options.authenticatorAttachment,
            residentKey: options.requireResidentKey !== false ? "required" : "preferred",
            userVerification: "required",
        },
        attestation: options.attestation ?? "direct",
        timeout: options.timeout ?? DEFAULT_TIMEOUT_MS,
    };
    const credential = (await navigator.credentials.create({
        publicKey: publicKeyOptions,
    }));
    if (!credential) {
        throw new Error("Credential creation returned null — user may have cancelled.");
    }
    const response = credential.response;
    const credentialIdBytes = new Uint8Array(credential.rawId);
    const credentialId = base64urlEncode(credentialIdBytes);
    // Parse the authenticator data to extract the public key
    const authData = new Uint8Array(response.getAuthenticatorData());
    const { publicKey, publicKeyX, publicKeyY, hardwareBacked } = parseAuthenticatorData(authData);
    // Derive the vault address from the public key coordinates
    const vaultAddress = deriveVaultAddress(publicKeyX, publicKeyY);
    // Determine attestation type from transport hints
    const transports = response.getTransports?.() ?? [];
    const attestationType = transports.includes("internal") ? "platform" : "cross-platform";
    return {
        credentialId,
        publicKey,
        publicKeyX,
        publicKeyY,
        vaultAddress,
        attestationType,
        hardwareBacked,
        rpId: options.rpId,
        createdAt: new Date().toISOString(),
        signCount: 0,
    };
}
/**
 * Parse the CBOR-encoded COSE public key from authenticator data.
 *
 * Authenticator data layout (per WebAuthn spec):
 *   [0..31]   rpIdHash (32 bytes)
 *   [32]      flags (1 byte)
 *   [33..36]  signCount (4 bytes, big-endian)
 *   [37..]    attestedCredentialData (if AT flag set)
 *
 * Attested credential data layout:
 *   [0..15]   AAGUID (16 bytes)
 *   [16..17]  credentialIdLength (2 bytes, big-endian)
 *   [18..18+L-1] credentialId (L bytes)
 *   [18+L..]  COSE public key (CBOR-encoded)
 */
function parseAuthenticatorData(authData) {
    if (authData.length < 37) {
        throw new Error("Authenticator data too short");
    }
    const flags = authData[32];
    const attestedCredentialDataPresent = (flags & 0x40) !== 0;
    if (!attestedCredentialDataPresent) {
        throw new Error("Authenticator data does not contain attested credential data (AT flag not set)");
    }
    // Skip rpIdHash (32) + flags (1) + signCount (4) = 37
    // Then skip AAGUID (16)
    const credIdLenOffset = 37 + 16;
    const credIdLen = (authData[credIdLenOffset] << 8) | authData[credIdLenOffset + 1];
    const coseKeyOffset = credIdLenOffset + 2 + credIdLen;
    const coseKeyBytes = authData.slice(coseKeyOffset);
    // Parse the COSE key to extract X and Y coordinates
    const { x, y, coseKey } = parseCoseP256Key(coseKeyBytes);
    // Determine if hardware-backed from AAGUID (non-zero = specific authenticator)
    const aaguid = authData.slice(37, 37 + 16);
    const hardwareBacked = aaguid.some((b) => b !== 0);
    return {
        publicKey: coseKey,
        publicKeyX: x,
        publicKeyY: y,
        hardwareBacked,
    };
}
/**
 * Parse a COSE-encoded P-256 public key (CBOR map) to extract raw coordinates.
 *
 * We implement a minimal CBOR parser that handles the specific structure
 * of a COSE EC2 key (kty=2, crv=1 for P-256):
 *   { 1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes }
 *
 * CBOR major types relevant here:
 *   0 = unsigned int, 1 = negative int, 2 = byte string, 5 = map
 */
function parseCoseP256Key(data) {
    let offset = 0;
    let x = null;
    let y = null;
    // Read the CBOR map header
    const mapHeader = data[offset];
    const majorType = mapHeader >> 5;
    if (majorType !== 5) {
        throw new Error(`Expected CBOR map (major type 5), got ${majorType}`);
    }
    const mapLength = mapHeader & 0x1f;
    offset++;
    // Handle maps with additional length bytes
    let numEntries;
    if (mapLength < 24) {
        numEntries = mapLength;
    }
    else if (mapLength === 24) {
        numEntries = data[offset];
        offset++;
    }
    else {
        throw new Error(`Unsupported CBOR map length encoding: ${mapLength}`);
    }
    const startOffset = 0;
    for (let i = 0; i < numEntries; i++) {
        // Read key (integer — positive or negative)
        const keyResult = readCborInt(data, offset);
        offset = keyResult.offset;
        const key = keyResult.value;
        // Read value
        const valueMajor = data[offset] >> 5;
        if (valueMajor === 2) {
            // Byte string
            const bstrResult = readCborByteString(data, offset);
            offset = bstrResult.offset;
            if (key === -2) {
                x = bstrResult.value;
            }
            else if (key === -3) {
                y = bstrResult.value;
            }
        }
        else {
            // Other types (integers for kty, alg, crv) — skip value
            const skipResult = skipCborValue(data, offset);
            offset = skipResult;
        }
    }
    if (!x || !y) {
        throw new Error("COSE key missing X or Y coordinate");
    }
    if (x.length !== 32 || y.length !== 32) {
        throw new Error(`Invalid P-256 key coordinates: x=${x.length} bytes, y=${y.length} bytes (expected 32 each)`);
    }
    // Return the full COSE key blob
    const coseKey = data.slice(startOffset, offset);
    return { x, y, coseKey };
}
/** Read a CBOR integer (major type 0 or 1). */
function readCborInt(data, offset) {
    const initial = data[offset];
    const major = initial >> 5;
    const additional = initial & 0x1f;
    offset++;
    let rawValue;
    if (additional < 24) {
        rawValue = additional;
    }
    else if (additional === 24) {
        rawValue = data[offset];
        offset++;
    }
    else if (additional === 25) {
        rawValue = (data[offset] << 8) | data[offset + 1];
        offset += 2;
    }
    else {
        throw new Error(`Unsupported CBOR int additional info: ${additional}`);
    }
    // Major type 1 = negative integer: value = -1 - rawValue
    const value = major === 1 ? -1 - rawValue : rawValue;
    return { value, offset };
}
/** Read a CBOR byte string (major type 2). */
function readCborByteString(data, offset) {
    const initial = data[offset];
    const additional = initial & 0x1f;
    offset++;
    let length;
    if (additional < 24) {
        length = additional;
    }
    else if (additional === 24) {
        length = data[offset];
        offset++;
    }
    else if (additional === 25) {
        length = (data[offset] << 8) | data[offset + 1];
        offset += 2;
    }
    else {
        throw new Error(`Unsupported CBOR byte string length: ${additional}`);
    }
    const value = data.slice(offset, offset + length);
    return { value, offset: offset + length };
}
/** Skip a single CBOR value (for types we don't need to decode). */
function skipCborValue(data, offset) {
    const initial = data[offset];
    const major = initial >> 5;
    const additional = initial & 0x1f;
    offset++;
    let length;
    if (additional < 24) {
        length = additional;
    }
    else if (additional === 24) {
        length = data[offset];
        offset++;
    }
    else if (additional === 25) {
        length = (data[offset] << 8) | data[offset + 1];
        offset += 2;
    }
    else if (additional === 26) {
        length =
            (data[offset] << 24) |
                (data[offset + 1] << 16) |
                (data[offset + 2] << 8) |
                data[offset + 3];
        offset += 4;
    }
    else {
        throw new Error(`Unsupported CBOR additional info: ${additional}`);
    }
    switch (major) {
        case 0: // unsigned int — already consumed
        case 1: // negative int — already consumed
            return offset;
        case 2: // byte string
        case 3: // text string
            return offset + length;
        case 4: // array
            for (let i = 0; i < length; i++) {
                offset = skipCborValue(data, offset);
            }
            return offset;
        case 5: // map
            for (let i = 0; i < length; i++) {
                offset = skipCborValue(data, offset); // key
                offset = skipCborValue(data, offset); // value
            }
            return offset;
        default:
            throw new Error(`Unsupported CBOR major type: ${major}`);
    }
}
