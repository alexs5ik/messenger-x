# syntax=docker/dockerfile:1

# ---- Stage A: build the wasm crypto bundle ---------------------------------
FROM rust:1-bookworm AS wasm
WORKDIR /src
# Prefer the prebuilt wasm-pack binary (fast, light on the free-tier builder); fall back to
# compiling it if the installer is unavailable.
RUN rustup target add wasm32-unknown-unknown \
    && (curl -sSfL https://rustwasm.github.io/wasm-pack/installer/init.sh | sh \
        || cargo install wasm-pack --locked)
# Copy the whole workspace (wasm-pack needs the crate + its path deps).
COPY . .
# Drop the Windows-only toolchain pin (rust-toolchain.toml) so cargo uses the Linux image
# default, then build the wasm bundle into web/src/mxwasm (matches package.json build:wasm).
RUN rm -f rust-toolchain.toml \
    && wasm-pack build crates/mx-crypto-wasm --target web --out-dir /src/web/src/mxwasm

# ---- Stage B: build the static frontend ------------------------------------
FROM node:20-bookworm AS web
WORKDIR /web
# package manifests first for layer caching.
COPY web/package.json web/package-lock.json* ./
RUN npm ci || npm install
# Web sources + the wasm produced in stage A.
COPY web/ ./
COPY --from=wasm /src/web/src/mxwasm ./src/mxwasm
RUN npm run build   # -> /web/dist

# ---- Stage C: build the server binary --------------------------------------
FROM rust:1-bookworm AS server
WORKDIR /src
COPY . .
# Drop the Windows-only toolchain pin so the Linux image default stable is used.
RUN rm -f rust-toolchain.toml \
    && cargo build --release -p mx-server   # -> /src/target/release/mx

# ---- Final: minimal runtime ------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=server /src/target/release/mx /app/mx
COPY --from=web    /web/dist             /app/web/dist
ENV MX_WEB_DIR=/app/web/dist
# Do NOT set MX_BIND_ADDR — main() derives 0.0.0.0:$PORT from Render's PORT.
EXPOSE 9990
CMD ["/app/mx"]
