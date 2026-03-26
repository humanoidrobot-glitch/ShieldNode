# RISC Zero development environment for building and proving.
#
# Uses rzup (official installer) to get pre-built binaries instead of
# compiling cargo-risczero from source (which requires nightly features).

FROM rust:1.85-bookworm

# Install system deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install RISC Zero via rzup (downloads pre-built binaries).
RUN curl -L https://risczero.com/install | bash && \
    /root/.risc0/bin/rzup install

ENV PATH="/root/.risc0/bin:${PATH}"

WORKDIR /workspace

ENTRYPOINT ["cargo"]
