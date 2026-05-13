# ============================================================================
# BlackBook L1 — Production Docker Image (Multi-Stage)
# ============================================================================
# Stage 1: Build  (rust:1.82-slim → ~1.2GB build layer, discarded)
# Stage 2: Runtime (debian:bookworm-slim → ~80MB final image)
# ============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────
FROM rust:1.85-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev protobuf-compiler \
    perl make \
    && rm -rf /var/lib/apt/lists/*

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
FROM debian:bookworm-slim AS runtime

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