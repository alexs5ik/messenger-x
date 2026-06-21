/* tslint:disable */
/* eslint-disable */

/**
 * A freshly created device account: the public bundle to publish, plus the secret blob the
 * device must persist (to answer responder handshakes later). See [`PreKeySecrets::to_bytes`].
 */
export class Account {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * JSON of the public `PreKeyBundle` to POST to `/v1/prekeys`.
     */
    readonly bundle_json: string;
    /**
     * Opaque secret blob to store locally (e.g. sessionStorage).
     */
    readonly secrets: Uint8Array;
}

/**
 * The initiator's result: the seeded Double Ratchet state (to persist) and the init message
 * (JSON) to send on the first frame so the responder can seed the matching ratchet.
 */
export class InitSession {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * PQXDH init message (JSON) to send on the first message.
     */
    readonly init_json: string;
    /**
     * Serialized [`RatchetState`] to persist for this outbound session.
     */
    readonly ratchet: Uint8Array;
}

/**
 * Result of a ratchet step: the advanced state to persist plus the produced bytes (ciphertext
 * frame for encrypt, plaintext for decrypt).
 */
export class RatchetStep {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly data: Uint8Array;
    readonly state: Uint8Array;
}

/**
 * Create a device account for `device_id` (a UUID string): generate identity + pre-keys,
 * returning the publishable bundle and the secret blob to keep.
 */
export function account_create(device_id: string): Account;

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
 * Decrypt one frame, advancing the ratchet. Returns the new state and the plaintext.
 */
export function ratchet_decrypt(state: Uint8Array, frame: Uint8Array): RatchetStep;

/**
 * Encrypt one message, advancing the ratchet. Returns the new state and the ciphertext frame.
 */
export function ratchet_encrypt(state: Uint8Array, plaintext: Uint8Array): RatchetStep;

/**
 * Encrypt `plaintext` under a 32-byte (or any-length) `secret`. Output is `nonce(12) || ct`.
 * Uses the same AEAD as mx-crypto's ratchet, so the wire bytes are produced by real Rust
 * crypto compiled to wasm — the server only ever sees this opaque blob.
 */
export function seal(secret: Uint8Array, plaintext: Uint8Array): Uint8Array;

/**
 * Initiator side of a real PQXDH session: handshake against `their_bundle_json`, seed a
 * Double Ratchet, and return the ratchet state + the init message to transmit.
 */
export function session_initiator(my_secrets: Uint8Array, their_bundle_json: string): InitSession;

/**
 * Responder side: handshake from the initiator's init message and seed the matching ratchet.
 * Returns the serialized ratchet state.
 */
export function session_responder(my_secrets: Uint8Array, init_json: string): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_account_free: (a: number, b: number) => void;
    readonly __wbg_initsession_free: (a: number, b: number) => void;
    readonly __wbg_ratchetstep_free: (a: number, b: number) => void;
    readonly account_bundle_json: (a: number) => [number, number];
    readonly account_create: (a: number, b: number) => [number, number, number];
    readonly account_secrets: (a: number) => [number, number];
    readonly initsession_init_json: (a: number) => [number, number];
    readonly initsession_ratchet: (a: number) => [number, number];
    readonly open: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pqxdh_selftest: () => [number, number];
    readonly ratchet_decrypt: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly ratchet_encrypt: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly ratchetstep_data: (a: number) => [number, number];
    readonly ratchetstep_state: (a: number) => [number, number];
    readonly seal: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly session_initiator: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly session_responder: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
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
