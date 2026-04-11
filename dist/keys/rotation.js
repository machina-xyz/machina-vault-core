/**
 * MACHINA Vault — Key Rotation
 * MAC-897: 4-Tier Key Hierarchy
 *
 * Supports automatic key rotation based on configured intervals.
 * During rotation, a 5-minute overlap window allows both old and new keys
 * to be valid simultaneously for graceful handoff.
 */
import { deriveOperatorKey, deriveAgentKey } from "./derivation.js";
/** Overlap window during rotation: 5 minutes */
const ROTATION_OVERLAP_MS = 5 * 60 * 1000;
/**
 * Check whether a key should be rotated based on its autoRotateInterval.
 *
 * Returns true if:
 * 1. The key has an autoRotateInterval configured
 * 2. The key is currently "active"
 * 3. The interval has elapsed since key creation
 */
export function shouldRotate(key) {
    if (key.status !== "active")
        return false;
    if (key.scope.autoRotateInterval === null)
        return false;
    const intervalMs = parseIso8601Duration(key.scope.autoRotateInterval);
    if (intervalMs === null || intervalMs <= 0)
        return false;
    const createdAt = new Date(key.createdAt).getTime();
    const now = Date.now();
    return now - createdAt >= intervalMs;
}
/**
 * Rotate a key: generate a new key at the given index and mark the old key
 * as "rotating" with a 5-minute overlap window.
 *
 * During the overlap window, both old and new keys are valid.
 * After the window expires, the old key should be revoked.
 *
 * Only operator and agent keys can be rotated (they are derived).
 * Root keys are rotated via recovery. Session keys just expire.
 */
export function rotateKey(params) {
    const { oldKey, masterSeed, newIndex } = params;
    if (oldKey.tier !== "operator" && oldKey.tier !== "agent") {
        throw new Error(`Cannot rotate "${oldKey.tier}" key. Only operator and agent keys support rotation.`);
    }
    if (oldKey.status !== "active") {
        throw new Error(`Cannot rotate key with status "${oldKey.status}". Key must be "active".`);
    }
    // Derive the new key
    const deriveFn = oldKey.tier === "operator" ? deriveOperatorKey : deriveAgentKey;
    const derived = deriveFn(masterSeed, newIndex);
    const now = new Date();
    const overlapExpiresAt = new Date(now.getTime() + ROTATION_OVERLAP_MS).toISOString();
    const today = now.toISOString().slice(0, 10);
    const month = now.toISOString().slice(0, 7);
    // Create the new key, inheriting scope and permissions from the old key
    const newKey = {
        id: `key_${oldKey.tier === "operator" ? "op" : "agent"}_${oldKey.vaultId}_${newIndex}`,
        vaultId: oldKey.vaultId,
        tier: oldKey.tier,
        name: `${oldKey.name} (rotated)`,
        publicKey: derived.publicKey,
        address: derived.address,
        parentKeyId: oldKey.parentKeyId,
        permissions: { ...oldKey.permissions },
        scope: {
            ...oldKey.scope,
            spendingLimits: oldKey.scope.spendingLimits.map((l) => ({ ...l })),
        },
        status: "active",
        signCount: 0,
        createdAt: now.toISOString(),
        expiresAt: oldKey.scope.expiry,
        revokedAt: null,
        lastUsedAt: null,
        spentToday: {},
        spentThisMonth: {},
        lastResetDay: today,
        lastResetMonth: month,
    };
    // Mark the old key as rotating
    const oldKeyUpdated = {
        ...oldKey,
        status: "rotating",
    };
    return {
        newKey,
        newPrivateKey: derived.privateKey,
        oldKeyUpdated,
        overlapExpiresAt,
    };
}
// ---------------------------------------------------------------------------
// ISO 8601 duration parser (subset: P[nD]T[nH][nM][nS])
// ---------------------------------------------------------------------------
/**
 * Parse a subset of ISO 8601 durations into milliseconds.
 * Supports: P{n}D, PT{n}H, PT{n}M, PT{n}S and combinations.
 * Does not support years or months (ambiguous lengths).
 */
function parseIso8601Duration(duration) {
    const match = duration.match(/^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/);
    if (!match)
        return null;
    const days = parseInt(match[1] || "0", 10);
    const hours = parseInt(match[2] || "0", 10);
    const minutes = parseInt(match[3] || "0", 10);
    const seconds = parseInt(match[4] || "0", 10);
    return (days * 86400000 +
        hours * 3600000 +
        minutes * 60000 +
        seconds * 1000);
}
