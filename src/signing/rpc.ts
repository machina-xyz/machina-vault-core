/**
 * MAC-898: JSON-RPC 2.0 provider abstraction.
 * Uses fetch() only — compatible with Cloudflare Workers.
 */

const RPC_TIMEOUT_MS = 15_000;

export class RpcError extends Error {
  constructor(
    public readonly code: number,
    message: string,
    public readonly data?: unknown,
  ) {
    super(`RPC error ${code}: ${message}`);
    this.name = "RpcError";
  }
}

let rpcIdCounter = 1;

/**
 * Make a single JSON-RPC 2.0 call via fetch().
 */
export async function rpcCall(
  url: string,
  method: string,
  params: unknown[],
): Promise<unknown> {
  const id = rpcIdCounter++;

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params,
    }),
    signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new RpcError(
      -1,
      `HTTP ${response.status}: ${response.statusText}`,
    );
  }

  const json = (await response.json()) as {
    result?: unknown;
    error?: { code: number; message: string; data?: unknown };
  };

  if (json.error) {
    throw new RpcError(json.error.code, json.error.message, json.error.data);
  }

  return json.result;
}

/**
 * JSON-RPC call with exponential backoff retry.
 */
export async function rpcCallWithRetry(
  url: string,
  method: string,
  params: unknown[],
  retries: number = 3,
): Promise<unknown> {
  let lastError: unknown;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await rpcCall(url, method, params);
    } catch (err) {
      lastError = err;

      // Don't retry on explicit RPC errors (invalid params, etc.)
      if (err instanceof RpcError && err.code >= -32600 && err.code <= -32600) {
        throw err;
      }

      if (attempt < retries) {
        // Exponential backoff: 500ms, 1s, 2s
        const delay = 500 * Math.pow(2, attempt);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }

  throw lastError;
}
