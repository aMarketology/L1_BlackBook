# ============================================================================
# BlackBook L2 Sequencer — Multi-stage Dockerfile
# ============================================================================
# Stage 1 (builder): installs ALL deps (including devDeps) and compiles TS
# Stage 2 (runner):  copies only compiled JS + prod deps — no source, no tsc
# ============================================================================

# ── Stage 1: Build ──────────────────────────────────────────────────────────
# node:sqlite (used by shared/src/db.ts) requires Node.js 22.5+.
FROM node:22-alpine AS builder

WORKDIR /build

# Copy workspace manifests first so Docker cache layers only rebuild
# when deps change, not on every source edit.
COPY package.json package-lock.json ./
COPY shared/package.json     ./shared/
COPY l2/package.json         ./l2/
COPY l3/package.json         ./l3/
COPY l5/package.json         ./l5/
COPY tsconfig.base.json      ./

# Install all deps (dev included) for the full workspace
RUN npm ci

# Copy source and compile
COPY shared/  ./shared/
COPY l2/      ./l2/
COPY l3/      ./l3/
COPY l5/      ./l5/

# Build all workspaces (shared first, then l2/l3/l5 depend on it)
RUN npm run build

# ── Stage 2: Production runner ──────────────────────────────────────────────
FROM node:22-alpine AS runner

# Non-root user for security
RUN addgroup -S sequencer && adduser -S sequencer -G sequencer

WORKDIR /app

# Copy workspace manifests for prod-only install
COPY package.json package-lock.json ./
COPY shared/package.json  ./shared/
COPY l2/package.json      ./l2/
COPY l3/package.json      ./l3/
COPY l5/package.json      ./l5/

# Install production deps only
RUN npm ci --omit=dev

# Copy compiled output from builder
COPY --from=builder /build/shared/dist  ./shared/dist/
COPY --from=builder /build/l2/dist      ./l2/dist/
COPY --from=builder /build/l3/dist      ./l3/dist/
COPY --from=builder /build/l5/dist      ./l5/dist/

# SQLite data directory — mounted as a volume in production
RUN mkdir -p /app/data && chown sequencer:sequencer /app/data

USER sequencer

# L2 sequencer HTTP port
EXPOSE 7072

# Health check — L2 exposes /health
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:7072/health || exit 1

# Default: run L2. Override CMD in compose for L3/L5.
CMD ["node", "l2/dist/index.js"]
