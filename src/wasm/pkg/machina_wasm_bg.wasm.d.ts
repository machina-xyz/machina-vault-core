/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const ct_hex_eq: (a: number, b: number, c: number, d: number) => number;
export const decrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const derive_address: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const derive_all_addresses: (a: number, b: number, c: number) => [number, number, number, number];
export const derive_key_from_mnemonic: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const encrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const encrypt_with_hkdf: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const generate_mnemonic: (a: number) => [number, number, number, number];
export const hd_derive: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const mnemonic_to_seed: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const sign_message: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
export const sign_transaction: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
export const sign_typed_data: (a: number, b: number, c: number, d: number) => [number, number, number];
export const validate_mnemonic: (a: number, b: number) => number;
export const webauthn_authentication_options: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const webauthn_registration_options: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
