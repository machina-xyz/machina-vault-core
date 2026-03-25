/**
 * MACHINA Vault — WebAuthn credential assertion (browser-side)
 *
 * Initiates a WebAuthn authentication ceremony to sign a challenge
 * using a previously registered passkey credential.
 */

import type { AuthenticateOptions, AuthenticationResult } from "./types.js";
import { base64urlEncode, base64urlDecode } from "./utils.js";

/** Default timeout: 5 minutes */
const DEFAULT_TIMEOUT_MS = 300_000;

/**
 * Authenticate using an existing WebAuthn credential.
 *
 * Must be called in a browser context with access to `navigator.credentials`.
 *
 * @param options - Authentication parameters including rpId, credentialId, and challenge
 * @returns The authentication result with signature and authenticator data
 * @throws If the WebAuthn API is unavailable or the user cancels
 */
export async function authenticateVault(
  options: AuthenticateOptions,
): Promise<AuthenticationResult> {
  if (
    typeof navigator === "undefined" ||
    typeof navigator.credentials === "undefined"
  ) {
    throw new Error(
      "WebAuthn API is not available in this environment. " +
        "authenticateVault must be called in a browser context.",
    );
  }

  const credentialIdBytes = base64urlDecode(options.credentialId);

  const publicKeyOptions: PublicKeyCredentialRequestOptions = {
    rpId: options.rpId,
    challenge: options.challenge as BufferSource,
    allowCredentials: [
      {
        id: credentialIdBytes as BufferSource,
        type: "public-key",
      },
    ],
    userVerification: "required",
    timeout: options.timeout ?? DEFAULT_TIMEOUT_MS,
  };

  const assertion = (await navigator.credentials.get({
    publicKey: publicKeyOptions,
  })) as PublicKeyCredential | null;

  if (!assertion) {
    throw new Error("Authentication returned null — user may have cancelled.");
  }

  const response = assertion.response as AuthenticatorAssertionResponse;

  const authenticatorData = new Uint8Array(response.authenticatorData);
  const clientDataJSON = new Uint8Array(response.clientDataJSON);
  const signature = new Uint8Array(response.signature);
  const credentialId = base64urlEncode(new Uint8Array(assertion.rawId));

  return {
    credentialId,
    signature,
    authenticatorData,
    clientDataJSON,
    verified: false, // Must be verified server-side via verify.ts
  };
}
