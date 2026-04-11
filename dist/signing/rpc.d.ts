/**
 * MAC-898: JSON-RPC 2.0 provider abstraction.
 * Uses fetch() only — compatible with Cloudflare Workers.
 */
export declare class RpcError extends Error {
    readonly code: number;
    readonly data?: unknown | undefined;
    constructor(code: number, message: string, data?: unknown | undefined);
}
/**
 * Make a single JSON-RPC 2.0 call via fetch().
 */
export declare function rpcCall(url: string, method: string, params: unknown[]): Promise<unknown>;
/**
 * JSON-RPC call with exponential backoff retry.
 */
export declare function rpcCallWithRetry(url: string, method: string, params: unknown[], retries?: number): Promise<unknown>;
