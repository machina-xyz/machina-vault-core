/**
 * WASM Vault Bridge — loads Rust crypto core, exposes typed functions.
 * All crypto runs in WASM. TypeScript never handles raw key material.
 */

export interface SignResult {
  signature: string;
  recovery_id: number | null;
}

export interface ChainAccount {
  chain: string;
  chain_id: string;
  address: string;
  derivation_path: string;
}

// WASM module interface
interface WasmModule {
  generate_mnemonic(words?: number | null): string;
  validate_mnemonic(phrase: string): boolean;
  mnemonic_to_seed(phrase: string, passphrase: string): string;
  hd_derive(seed_hex: string, path: string, curve: string): string;
  derive_key_from_mnemonic(mnemonic: string, path: string, curve: string): string;
  derive_address(private_key_hex: string, chain: string): string;
  derive_all_addresses(mnemonic: string, index?: number | null): string;
  sign_message(private_key_hex: string, chain: string, message: string): SignResult;
  sign_transaction(private_key_hex: string, chain: string, tx_hex: string): SignResult;
  sign_typed_data(private_key_hex: string, typed_data_json: string): SignResult;
  encrypt(plaintext_hex: string, passphrase: string): string;
  decrypt(envelope_json: string, passphrase: string): string;
  encrypt_with_hkdf(plaintext_hex: string, token: string): string;
  webauthn_registration_options(rp_id: string, origin: string, user_name: string, user_id_hex: string): string;
  webauthn_authentication_options(rp_id: string, credential_ids_json: string): string;
  ct_hex_eq(a: string, b: string): boolean;
}

let wasmModule: WasmModule | null = null;

/**
 * Initialize the WASM vault. Must be called before any crypto operations.
 *
 * Loading modes:
 * 1. No args: auto-loads bundled WASM binary
 * 2. Function: custom init function (e.g., from external WASM package)
 * 3. String/URL: load WASM from a URL
 */
export async function initVault(wasmSource?: string | ArrayBuffer | (() => Promise<any>) | undefined): Promise<void> {
  if (wasmModule) return;

  // Mode 1: Custom init function
  if (typeof wasmSource === "function") {
    await wasmSource();
    return;
  }

  // Mode 2: Auto-load bundled WASM
  try {
    const wasm = await import("./pkg/machina_wasm.js");
    await wasm.default();
    // The WASM module exports functions directly — set them as our module
    wasmModule = wasm as unknown as WasmModule;
    return;
  } catch (_e) {
    // Bundled WASM not available — fall through to error
  }

  throw new Error(
    "WASM not loaded. The bundled WASM binary was not found. " +
    "Ensure @machina-xyz/vault-core was installed correctly, " +
    "or pass a custom init function to initVault()."
  );
}

/** Set the WASM module directly (for testing or custom loading). */
export function setWasmModule(mod: WasmModule): void {
  wasmModule = mod;
}

function requireInit(): WasmModule {
  if (!wasmModule) throw new Error("Vault not initialized. Call initVault() first.");
  return wasmModule;
}

// Typed wrappers
export const vault = {
  init: initVault,
  isInitialized: () => wasmModule !== null,

  generateMnemonic: (words: 12 | 24 = 12): string => requireInit().generate_mnemonic(words),
  validateMnemonic: (phrase: string): boolean => requireInit().validate_mnemonic(phrase),
  mnemonicToSeed: (phrase: string, passphrase = ""): string => requireInit().mnemonic_to_seed(phrase, passphrase),

  deriveKey: (seedHex: string, path: string, curve: "secp256k1" | "ed25519"): string =>
    requireInit().hd_derive(seedHex, path, curve),
  deriveKeyFromMnemonic: (mnemonic: string, path: string, curve: "secp256k1" | "ed25519"): string =>
    requireInit().derive_key_from_mnemonic(mnemonic, path, curve),

  deriveAddress: (privateKeyHex: string, chain: string): string =>
    requireInit().derive_address(privateKeyHex, chain),
  deriveAllAddresses: (mnemonic: string, index = 0): ChainAccount[] =>
    JSON.parse(requireInit().derive_all_addresses(mnemonic, index)),

  signMessage: (privateKeyHex: string, chain: string, message: string): SignResult =>
    requireInit().sign_message(privateKeyHex, chain, message),
  signTransaction: (privateKeyHex: string, chain: string, txHex: string): SignResult =>
    requireInit().sign_transaction(privateKeyHex, chain, txHex),
  signTypedData: (privateKeyHex: string, typedDataJson: string): SignResult =>
    requireInit().sign_typed_data(privateKeyHex, typedDataJson),

  encrypt: (plaintextHex: string, passphrase: string): string =>
    requireInit().encrypt(plaintextHex, passphrase),
  decrypt: (envelopeJson: string, passphrase: string): string =>
    requireInit().decrypt(envelopeJson, passphrase),
  encryptWithHkdf: (plaintextHex: string, token: string): string =>
    requireInit().encrypt_with_hkdf(plaintextHex, token),

  webauthnRegistrationOptions: (rpId: string, origin: string, userName: string, userIdHex: string): object =>
    JSON.parse(requireInit().webauthn_registration_options(rpId, origin, userName, userIdHex)),
  webauthnAuthenticationOptions: (rpId: string, credentialIds: Uint8Array[]): object =>
    JSON.parse(requireInit().webauthn_authentication_options(
      rpId, JSON.stringify(credentialIds.map((id) => Array.from(id))))),

  ctHexEq: (a: string, b: string): boolean => requireInit().ct_hex_eq(a, b),
};

export type Vault = typeof vault;
