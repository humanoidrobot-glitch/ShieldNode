# ── Stage 1: build ────────────────────────────────────────────────────
# Build from repo root: docker build -f node/Dockerfile -t shieldnode .
FROM rust:1.91.0-bookworm AS builder

WORKDIR /build

# Cache dependency compilation separately from source changes.
COPY Cargo.toml ./
COPY node/Cargo.toml node/Cargo.lock node/
COPY packages/shieldnode-types/Cargo.toml packages/shieldnode-types/
RUN mkdir -p node/src && echo "fn main() {}" > node/src/main.rs \
    && mkdir -p packages/shieldnode-types/src && echo "" > packages/shieldnode-types/src/lib.rs \
    && cd node && cargo build --release
COPY node/src/ node/src/
COPY packages/shieldnode-types/src/ packages/shieldnode-types/src/
RUN touch node/src/main.rs && cd node && cargo build --release --bin shieldnode

# ── Stage 2: runtime ──────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --shell /bin/bash shieldnode

COPY --from=builder /build/node/target/release/shieldnode /usr/local/bin/shieldnode

RUN mkdir -p /data && chown shieldnode:shieldnode /data

USER shieldnode
WORKDIR /data

EXPOSE 51820/udp 51821/udp 4001/tcp 9090/tcp

ENTRYPOINT ["shieldnode"]
CMD ["--config", "/data/config.toml"]
