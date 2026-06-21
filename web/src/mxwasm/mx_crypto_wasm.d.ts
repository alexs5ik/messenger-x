/* tslint:disable */
/* eslint-disable */

/**
 * Inverse of [`seal`]: takes `nonce(12) || ct` and returns the plaintext, or an error if the
 * secret is wrong or the ciphertext was tampered with (AEAD authentication).
 */
export function open(secret: Uint8Array, data: Uint8Array): Uint8Array;

/**
 * Run a complete PQXDH handshake + ratchet exchange and return a JSON status string.
 * `ok` is true only if both parties derived the identical secret AND a message round-trips
 * through the ratchet.
 */
export function pqxdh_selftest(): string;

/**
 * Encrypt `plaintext` under a 32-byte (or any-length) `secret`. Output is `nonce(12) || ct`.
 * Uses the same AEAD as mx-crypto's ratchet, so the wire bytes are produced by real Rust
 * crypto compiled to wasm — the server only ever sees this opaque blob.
 */
export function seal(secret: Uint8Array, plaintext: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly open: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pqxdh_selftest: () => [number, number];
    readonly seal: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
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
