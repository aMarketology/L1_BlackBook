# ============================================================================
# BlackBook L1 — Production Docker Image (Multi-Stage) — v1.0.2
# ============================================================================
# Stage 1: Build  (ubuntu:22.04 + rustup → cached toolchain layer)
# Stage 2: Runtime (ubuntu:22.04 → ~100MB final image)
#
# Run with --mode validator for multi-validator rotating leader consensus:
#   docker run ... /app/layer1 --mode validator --identity cherry-writer
# ============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    curl build-essential pkg-config libssl-dev protobuf-compiler \
    perl make \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Rust toolchain via rustup
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain 1.88.0

WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ src/
COPY runtime/ runtime/
COPY protocol/ protocol/
COPY proto/ proto/
COPY tests/ tests/
COPY examples/ examples/

# Build release binary with all optimizations.
# --locked: fail if Cargo.lock is out of sync (reproducible builds).
RUN cargo build --release --locked --bin layer1

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
# Refresh Debian archive keyring first (handles GPG key rotation in older images)
RUN apt-get update && apt-get install -y \
    ca-certificates curl libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash blackbook

WORKDIR /app

# Copy only the binary from builder
COPY --from=builder /build/target/release/layer1 /app/layer1

# Data directory for ReDB persistence
RUN mkdir -p /data/blockchain_data && chown -R blackbook:blackbook /data /app
ENV REDB_PATH=/data/blockchain_data/blockchain.redb

USER blackbook

# Expose HTTP (8080) + JSON-RPC (8899) + UDP TPU (8003) + gRPC relay (50051)
EXPOSE 8080 8899 8003/udp 50051

# Health check — block production staleness < 10s
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["/app/layer1"]