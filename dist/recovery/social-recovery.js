/**
 * Social Recovery via Shamir Secret Sharing
 *
 * Splits a master seed into n shares with threshold t.
 * Any t shares can reconstruct the seed; fewer than t reveals nothing.
 *
 * Uses GF(256) arithmetic for Shamir's Secret Sharing scheme.
 */
// GF(256) arithmetic using AES irreducible polynomial x^8 + x^4 + x^3 + x + 1
const GF256_EXP = new Uint8Array(256);
const GF256_LOG = new Uint8Array(256);
// Initialize GF(256) lookup tables
(function initGF256() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
        GF256_EXP[i] = x;
        GF256_LOG[x] = i;
        x = x ^ (x << 1); // multiply by 2
        if (x >= 256)
            x ^= 0x11b; // reduce by AES polynomial
    }
    GF256_EXP[255] = GF256_EXP[0];
})();
function gf256Mul(a, b) {
    if (a === 0 || b === 0)
        return 0;
    return GF256_EXP[(GF256_LOG[a] + GF256_LOG[b]) % 255];
}
function gf256Div(a, b) {
    if (b === 0)
        throw new Error("Division by zero in GF(256)");
    if (a === 0)
        return 0;
    return GF256_EXP[(GF256_LOG[a] - GF256_LOG[b] + 255) % 255];
}
/**
 * Split a secret into n shares with threshold t using Shamir's Secret Sharing.
 *
 * @param secret - The secret bytes to split
 * @param threshold - Minimum shares needed to reconstruct (t)
 * @param totalShares - Total number of shares to generate (n)
 * @returns Array of shares, each with an index (1-based) and data
 */
export function splitSecret(secret, threshold, totalShares) {
    if (threshold < 2)
        throw new Error("Threshold must be at least 2");
    if (totalShares < threshold)
        throw new Error("Total shares must be >= threshold");
    if (totalShares > 255)
        throw new Error("Maximum 255 shares supported");
    const shares = [];
    for (let i = 1; i <= totalShares; i++) {
        shares.push({ index: i, data: new Uint8Array(secret.length) });
    }
    // For each byte of the secret, create a random polynomial of degree (threshold-1)
    // where the constant term is the secret byte
    for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
        // Random coefficients for polynomial terms 1..(threshold-1)
        const coefficients = new Uint8Array(threshold);
        coefficients[0] = secret[byteIdx]; // constant term = secret byte
        const randomCoeffs = new Uint8Array(threshold - 1);
        crypto.getRandomValues(randomCoeffs);
        for (let c = 1; c < threshold; c++) {
            coefficients[c] = randomCoeffs[c - 1];
        }
        // Evaluate polynomial at each share index
        for (let shareIdx = 0; shareIdx < totalShares; shareIdx++) {
            const x = shares[shareIdx].index;
            let y = 0;
            for (let c = threshold - 1; c >= 0; c--) {
                y = gf256Mul(y, x) ^ coefficients[c];
            }
            shares[shareIdx].data[byteIdx] = y;
        }
    }
    return shares;
}
/**
 * Reconstruct a secret from t shares using Lagrange interpolation in GF(256).
 *
 * @param shares - Array of shares (must have at least threshold shares)
 * @returns Reconstructed secret bytes
 */
export function reconstructSecret(shares) {
    if (shares.length < 2)
        throw new Error("Need at least 2 shares to reconstruct");
    const secretLength = shares[0].data.length;
    const result = new Uint8Array(secretLength);
    for (let byteIdx = 0; byteIdx < secretLength; byteIdx++) {
        // Lagrange interpolation at x=0
        let value = 0;
        for (let i = 0; i < shares.length; i++) {
            let lagrangeCoeff = 1;
            for (let j = 0; j < shares.length; j++) {
                if (i === j)
                    continue;
                // lagrangeCoeff *= (0 - x_j) / (x_i - x_j) in GF(256)
                // Since 0 - x_j = x_j in GF(256) (addition = XOR)
                const numerator = shares[j].index;
                const denominator = shares[i].index ^ shares[j].index;
                lagrangeCoeff = gf256Mul(lagrangeCoeff, gf256Div(numerator, denominator));
            }
            value ^= gf256Mul(shares[i].data[byteIdx], lagrangeCoeff);
        }
        result[byteIdx] = value;
    }
    return result;
}
/**
 * Create a recovery configuration for a vault.
 */
export function createRecoveryConfig(vaultId, threshold, guardians, options) {
    if (guardians.length < threshold) {
        throw new Error(`Need at least ${threshold} guardians for ${threshold}-of-n recovery`);
    }
    const now = new Date().toISOString();
    return {
        vaultId,
        threshold,
        totalGuardians: guardians.length,
        guardians: guardians.map((g, i) => ({
            id: `grd_${randomId()}`,
            identifier: g.identifier,
            type: g.type,
            name: g.name,
            confirmed: false,
            shareIndex: i + 1,
            encryptedShare: null,
            addedAt: now,
        })),
        cloudBackupEnabled: options?.cloudBackup ?? false,
        hardwareBackupEnabled: options?.hardwareBackup ?? false,
        cooldownSeconds: options?.cooldownSeconds ?? 86400, // 24 hours default
        createdAt: now,
        updatedAt: now,
    };
}
/**
 * Initiate a recovery request.
 */
export function initiateRecovery(vaultId, config, method) {
    const now = new Date();
    const cooldownMs = config.cooldownSeconds * 1000;
    const expiryMs = 7 * 24 * 60 * 60 * 1000; // 7 days to complete
    return {
        id: `rec_${randomId()}`,
        vaultId,
        method,
        status: "pending",
        sharesCollected: 0,
        sharesRequired: config.threshold,
        respondedGuardians: [],
        cooldownExpiresAt: new Date(now.getTime() + cooldownMs).toISOString(),
        requestExpiresAt: new Date(now.getTime() + expiryMs).toISOString(),
        createdAt: now.toISOString(),
        completedAt: null,
    };
}
/**
 * Submit a guardian share for recovery.
 */
export function submitRecoveryShare(request, guardianId) {
    if (request.respondedGuardians.includes(guardianId)) {
        throw new Error("Guardian has already submitted a share");
    }
    if (new Date(request.requestExpiresAt) < new Date()) {
        throw new Error("Recovery request has expired");
    }
    const updated = {
        ...request,
        sharesCollected: request.sharesCollected + 1,
        respondedGuardians: [...request.respondedGuardians, guardianId],
        status: request.sharesCollected + 1 >= request.sharesRequired ? "in_progress" : "pending",
    };
    return updated;
}
function randomId() {
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
//# sourceMappingURL=social-recovery.js.map