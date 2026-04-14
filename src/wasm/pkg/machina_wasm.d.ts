/* tslint:disable */
/* eslint-disable */

/**
 * Constant-time hex comparison (no timing leaks).
 */
export function ct_hex_eq(a: string, b: string): boolean;

/**
 * Decrypt a CryptoEnvelope JSON string with passphrase.
 *
 * Returns plaintext as hex string.
 */
export function decrypt(envelope_json: string, passphrase: string): string;

/**
 * Derive an on-chain address from a hex-encoded private key.
 *
 * `chain`: "ethereum", "solana", "bitcoin", "sui", "cosmos", etc.
 */
export function derive_address(private_key_hex: string, chain: string): string;

/**
 * Derive addresses for ALL 9 chains from a mnemonic at the given index.
 *
 * Returns JSON array of `{ "chain": "...", "chain_id": "...", "address": "...", "path": "..." }`
 */
export function derive_all_addresses(mnemonic: string, index?: number | null): string;

/**
 * Derive a child key from mnemonic + path + curve (convenience).
 */
export function derive_key_from_mnemonic(mnemonic: string, path: string, curve: string): string;

/**
 * Encrypt plaintext (hex) with passphrase using scrypt + AES-256-GCM.
 *
 * Returns CryptoEnvelope JSON string.
 */
export function encrypt(plaintext_hex: string, passphrase: string): string;

/**
 * Encrypt with HKDF-SHA256 (for API token-based encryption).
 */
export function encrypt_with_hkdf(plaintext_hex: string, token: string): string;

/**
 * Generate a new BIP-39 mnemonic phrase (12 or 24 words).
 */
export function generate_mnemonic(words?: number | null): string;

/**
 * Derive a child key from seed + path + curve.
 *
 * `curve`: "secp256k1" or "ed25519"
 * Returns hex-encoded private key.
 */
export function hd_derive(seed_hex: string, path: string, curve: string): string;

/**
 * Derive a BIP-39 seed from a mnemonic phrase (hex-encoded).
 */
export function mnemonic_to_seed(phrase: string, passphrase: string): string;

/**
 * Sign a message with a private key on the given chain.
 *
 * Returns JSON: `{ "signature": "<hex>", "recovery_id": <u8|null> }`
 */
export function sign_message(private_key_hex: string, chain: string, message: string): any;

/**
 * Sign a transaction (hex-encoded) with a private key.
 *
 * Returns JSON: `{ "signature": "<hex>", "recovery_id": <u8|null> }`
 */
export function sign_transaction(private_key_hex: string, chain: string, tx_hex: string): any;

/**
 * Sign EIP-712 typed structured data (EVM only).
 */
export function sign_typed_data(private_key_hex: string, typed_data_json: string): any;

/**
 * Validate a BIP-39 mnemonic phrase.
 */
export function validate_mnemonic(phrase: string): boolean;

/**
 * Generate WebAuthn authentication options for `navigator.credentials.get()`.
 */
export function webauthn_authentication_options(rp_id: string, credential_ids_json: string): string;

/**
 * Generate WebAuthn registration options for `navigator.credentials.create()`.
 */
export function webauthn_registration_options(rp_id: string, origin: string, user_name: string, user_id_hex: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly ct_hex_eq: (a: number, b: number, c: number, d: number) => number;
    readonly decrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly derive_address: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly derive_all_addresses: (a: number, b: number, c: number) => [number, number, number, number];
    readonly derive_key_from_mnemonic: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly encrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encrypt_with_hkdf: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly generate_mnemonic: (a: number) => [number, number, number, number];
    readonly hd_derive: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly mnemonic_to_seed: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly sign_message: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly sign_transaction: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly sign_typed_data: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly validate_mnemonic: (a: number, b: number) => number;
    readonly webauthn_authentication_options: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly webauthn_registration_options: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
