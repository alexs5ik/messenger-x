# Messenger X

AI-First Secure Super Messenger. A privacy-first messaging platform with post-quantum
end-to-end encryption, a tiered AI layer, communities, and a creator economy.

> Architecture & product rationale: see [Messenger_X_Design_Document.md](Messenger_X_Design_Document.md).

## Status

**Horizon 1 scaffold.** Implemented as a **modular monolith**: domain logic lives in library
crates; a single binary (`mx`) wires them together. Services can be split out by load later
(design doc §5/§12).

## Workspace layout

| Crate | Role |
|-------|------|
| `mx-types` | Shared domain contract (ids, envelopes, prekey bundles, crypto material). Ciphertext-only by design. |
| `mx-crypto` | PQXDH (hybrid X25519 + ML-KEM) handshake, Double Ratchet, MLS glue. |
| `mx-storage` | Postgres + Redis persistence. |
| `mx-transport` | WebSocket (primary) + QUIC (experimental) framing. |
| `mx-auth` | Registration, device keys, prekey publish/fetch, session tokens. |
| `mx-messaging` | Envelope ingest, per-device fan-out, offline queues. |
| `mx-groups` | MLS group state, membership, roles. |
| `mx-presence` | Online status, typing. |
| `mx-ai` | Tiered AI orchestrator (on-device / enclave / external) enforcing the envelope rule. |
| `mx-server` | Runnable backend binary (HTTP API + WS gateway). |

## Build & run

This machine uses the **GNU Rust toolchain** (pinned in `rust-toolchain.toml`) and redirects
the build dir to an ASCII path (`.cargo/config.toml`) because the project path is non-ASCII.
Build from **PowerShell** (the Git-Bash `link` shadows the toolchain linker).

```powershell
cargo build --workspace        # compile everything
cargo test  --workspace        # run tests
docker compose up -d           # bring up Postgres/Redis/Kafka/NATS/ClickHouse/MinIO
cargo run -p mx-server         # start the backend (binary name: `mx`)
```

## Security note

The backend stores and routes **ciphertext only** — message payloads are end-to-end
encrypted and opaque to the server. Server-side AI never reads plaintext outside an attested
enclave or with explicit user delegation (design doc §8, the "envelope rule").
