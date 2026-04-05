# ── Stage 1: build ────────────────────────────────────────────────────
FROM rust:1.91.0-bookworm AS builder

WORKDIR /build

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && cargo build --release
COPY src/ src/
RUN touch src/main.rs && cargo build --release --bin shieldnode

# ── Stage 2: runtime ──────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --shell /bin/bash shieldnode

COPY --from=builder /build/target/release/shieldnode /usr/local/bin/shieldnode

RUN mkdir -p /data && chown shieldnode:shieldnode /data

USER shieldnode
WORKDIR /data

EXPOSE 51820/udp 51821/udp 4001/tcp 9090/tcp

ENTRYPOINT ["shieldnode"]
CMD ["--config", "/data/config.toml"]
