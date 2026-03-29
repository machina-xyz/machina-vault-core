/**
 * MACHINA Vault — Key Hierarchy Types
 * MAC-897: 4-Tier Key Hierarchy (Root → Operator → Agent → Session Keys)
 */
/** Permission bit positions */
export const PERM = {
    CREATE_OPERATOR_KEY: 0n,
    REVOKE_OPERATOR_KEY: 1n,
    CREATE_AGENT_KEY: 2n,
    REVOKE_AGENT_KEY: 3n,
    CREATE_SESSION_KEY: 4n,
    REVOKE_SESSION_KEY: 5n,
    SIGN_TRANSACTION: 6n,
    MANAGE_POLICY: 7n,
    VIEW_BALANCES: 8n,
    INITIATE_RECOVERY: 9n,
    MANAGE_IDENTITY: 10n,
    APPROVE_TRANSACTION: 11n,
    MANAGE_ALLOWLIST: 12n,
    ROTATE_KEYS: 13n,
    VIEW_AUDIT_LOG: 14n,
    MANAGE_WEBHOOKS: 15n,
};
//# sourceMappingURL=types.js.map