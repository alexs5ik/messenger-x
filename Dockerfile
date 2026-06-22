# syntax=docker/dockerfile:1

# ---- Stage A: build the wasm crypto bundle ---------------------------------
FROM rust:1-bookworm AS wasm
WORKDIR /src
RUN rustup target add wasm32-unknown-unknown \
    && cargo install wasm-pack --locked
# Copy the whole workspace (wasm-pack needs the crate + its path deps).
COPY . .
# Produces web/src/mxwasm (matches package.json build:wasm output dir).
RUN wasm-pack build crates/mx-crypto-wasm --target web --out-dir /src/web/src/mxwasm

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
RUN cargo build --release -p mx-server   # -> /src/target/release/mx

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
