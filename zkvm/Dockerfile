# RISC Zero development environment for building and proving.
#
# Usage:
#   docker build -t shieldnode-zkvm zkvm/
#   docker run --rm -v $(pwd)/zkvm:/workspace shieldnode-zkvm cargo build
#   docker run --rm -v $(pwd)/zkvm:/workspace shieldnode-zkvm cargo run --bin shieldnode-zkvm-host

FROM rust:1.85-bookworm

# Install RISC Zero toolchain.
RUN cargo install cargo-risczero --locked && \
    cargo risczero install

# Install dependencies for guest compilation (riscv target).
RUN rustup target add riscv32im-unknown-none-elf 2>/dev/null || true

WORKDIR /workspace

# Pre-fetch common crates to speed up builds.
COPY Cargo.toml ./
COPY guest/Cargo.toml guest/
COPY host/Cargo.toml host/
RUN mkdir -p guest/src host/src && \
    echo '#![no_main]\n#![no_std]\nrisc0_zkvm::guest::entry!(main);\nfn main() {}' > guest/src/main.rs && \
    echo 'fn main() {}' > host/src/main.rs && \
    cargo build 2>/dev/null || true && \
    rm -rf guest/src host/src

ENTRYPOINT ["cargo"]
