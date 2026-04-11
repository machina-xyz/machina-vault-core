/**
 * MACHINA Vault — Platform Detection
 *
 * Detects the current runtime environment and available secure enclave
 * capabilities. Safe across browser, Cloudflare Workers, mobile, and server.
 */
/**
 * Detect the current runtime platform and its enclave capabilities.
 *
 * Checks in order:
 *   1. WebAuthn (browser with PublicKeyCredential)
 *   2. Cloudflare Workers (V8 isolate markers)
 *   3. TEE (TPM/SGX attestation APIs)
 *   4. Mobile biometric (native bridge)
 *   5. Software fallback
 */
export function detectPlatform() {
    // 1. WebAuthn — browser with credential management API
    if (hasWebAuthn()) {
        return {
            type: "webauthn",
            name: "WebAuthn Authenticator",
            securityLevel: "hardware",
            capabilities: [
                "key_generation",
                "signing",
                "attestation",
                "secure_storage",
                "biometric",
            ],
        };
    }
    // 2. Cloudflare Workers — V8 isolate environment
    if (isCloudflareWorker()) {
        return {
            type: "cloudflare",
            name: "Cloudflare Workers V8 Isolate",
            securityLevel: "firmware",
            capabilities: [
                "key_generation",
                "signing",
                "encryption",
                "attestation",
            ],
        };
    }
    // 3. TEE — Trusted Execution Environment (SGX, TDX, SEV)
    if (hasTeeSupport()) {
        return {
            type: "tee",
            name: "Trusted Execution Environment",
            securityLevel: "hardware",
            capabilities: [
                "key_generation",
                "signing",
                "encryption",
                "attestation",
                "secure_storage",
            ],
        };
    }
    // 4. Mobile biometric — native bridge present
    if (hasMobileBiometric()) {
        return {
            type: "mobile_biometric",
            name: "Mobile Biometric Enclave",
            securityLevel: "hardware",
            capabilities: [
                "key_generation",
                "signing",
                "secure_storage",
                "biometric",
            ],
        };
    }
    // 5. Software fallback — Web Crypto available but no hardware enclave
    return {
        type: "software",
        name: "Software Key Store",
        securityLevel: "software",
        capabilities: [
            "key_generation",
            "signing",
            "encryption",
        ],
    };
}
/**
 * Get the security level for a platform.
 */
export function getSecurityLevel(platform) {
    switch (platform.type) {
        case "webauthn":
            // Hardware if the authenticator is platform-bound; firmware otherwise
            return platform.securityLevel === "hardware" ? "hardware" : "firmware";
        case "cloudflare":
            return "firmware";
        case "tee":
        case "hsm":
            return "hardware";
        case "mobile_biometric":
            return "hardware";
        case "software":
            return "software";
        default:
            return "unknown";
    }
}
/**
 * Check whether the platform is backed by dedicated hardware security.
 * Only true for 'hardware' security level — firmware/software return false.
 */
export function isHardwareBacked(platform) {
    return getSecurityLevel(platform) === "hardware";
}
/**
 * Check whether a platform supports a specific capability.
 */
export function platformSupportsCapability(platform, capability) {
    return platform.capabilities.includes(capability);
}
// ---------------------------------------------------------------------------
// Internal detection helpers — all use typeof guards to avoid throwing
// ---------------------------------------------------------------------------
function hasWebAuthn() {
    try {
        return (typeof globalThis !== "undefined" &&
            typeof globalThis.navigator === "object" &&
            globalThis.navigator !== null &&
            typeof globalThis.navigator
                .credentials === "object" &&
            typeof globalThis.PublicKeyCredential === "function");
    }
    catch {
        return false;
    }
}
function isCloudflareWorker() {
    try {
        // Cloudflare Workers expose `caches` on the global but lack `window`.
        // They also expose `navigator.userAgent === "Cloudflare-Workers"` since 2023.
        const g = globalThis;
        if (typeof g.window !== "undefined")
            return false;
        // Check for Cloudflare-specific navigator.userAgent
        if (typeof g.navigator === "object" &&
            g.navigator !== null &&
            g.navigator.userAgent === "Cloudflare-Workers") {
            return true;
        }
        // Fallback: caches.default is Cloudflare-specific (not present in browsers)
        if (typeof g.caches === "object" &&
            g.caches !== null &&
            typeof g.caches.default === "object") {
            return true;
        }
        return false;
    }
    catch {
        return false;
    }
}
function hasTeeSupport() {
    try {
        // Check for Intel SGX or AMD SEV marker globals
        const g = globalThis;
        return (typeof g.__sgx_attestation === "function" ||
            typeof g.__tee_attestation === "function" ||
            typeof g.__sev_attestation === "function");
    }
    catch {
        return false;
    }
}
function hasMobileBiometric() {
    try {
        // React Native / Capacitor / native bridge marker
        const g = globalThis;
        return (typeof g.__MACHINA_BIOMETRIC === "object" &&
            g.__MACHINA_BIOMETRIC !== null);
    }
    catch {
        return false;
    }
}
