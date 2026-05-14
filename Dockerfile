# syntax=docker/dockerfile:1.6
#
# Hearth — multi-stage build.
#
# Stage 1 ("builder"): compile the release binary on top of the official Rust
# image. Debian (not Alpine) because Hearth links against glibc via `ring` /
# `rustls` and the stdlib — Alpine/musl compiles, but the extra yak-shaving
# (musl-dev, cc-variants, `cargo build --target`) isn't worth the ~10 MB image
# savings for local dev.
#
# Stage 2 ("runtime"): copy the static-ish binary onto a minimal
# `debian:bookworm-slim` base, drop privileges to UID 10001, and run
# `hearth serve -c /etc/hearth/hearth.yaml`.
#
# Build context is trimmed by `.dockerignore` (sibling file) to keep the
# streaming phase under a couple of megabytes.

# -----------------------------------------------------------------------------
# Stage 1: builder
# -----------------------------------------------------------------------------
# Pinned to 1.89 — the repo's declared `rust-version = "1.75"` is aspirational;
# transitive deps (e.g. ureq-proto 0.6) require edition 2024, which stabilized
# in Rust 1.85. Bump in lockstep with the host toolchain when deps move.
#
# Supply-chain hardening: pinned by both tag and digest.
# To re-pin after a base-image upgrade:
#   docker pull rust:1.89-slim-bookworm && \
#   docker inspect rust:1.89-slim-bookworm --format '{{index .RepoDigests 0}}'
FROM rust:1.89-slim-bookworm@sha256:d7fc7de78bb8c1469933aeecbf801314d30d7d6e9f0578bba4cfa285bfa37fe6 AS builder

# Build-time deps:
#   - protobuf-compiler: `build.rs` calls `prost_build::compile_protos`, which
#     shells out to `protoc`. Without it the build fails at the "compile
#     protos" step before a single .rs file is touched.
#   - pkg-config: cargo convention for native-dep crates even though we avoid
#     the big ones (no libssl-dev: Hearth uses ring + rustls, pure-Rust TLS).
#   - ca-certificates: so cargo can fetch from crates.io over HTTPS.
#   - git: a handful of crates pull git metadata during `build.rs`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        pkg-config \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ----- Dependency caching pass ------------------------------------------------
#
# Copy only the manifest files and a stub `src/` so Docker can cache the
# expensive dependency compile step. Any change to Hearth's own source code
# invalidates the second stage but NOT this one.
#
# `simulation/` is a workspace member (see root Cargo.toml) — we must stub its
# manifest + src too or `cargo build` refuses to resolve the workspace.
#
# `Cargo.lock` is gitignored in this repo, so we generate one if the host
# didn't copy a cached one in (acceptable: `.dockerignore` doesn't exclude
# Cargo.lock, so when a developer has one locally it's honoured). The missing
# case produces a non-reproducible image, which is a pre-existing repo-wide
# tradeoff, not something this Dockerfile fixes.
COPY Cargo.toml ./
COPY simulation/Cargo.toml simulation/Cargo.toml
COPY build.rs ./
COPY proto ./proto

# Stub binaries + libs + benches so `cargo build` has something to compile.
# Cargo validates every target path declared in `Cargo.toml` (including each
# `[[bench]]`) at manifest-parse time, even with `--bin hearth` — a missing
# file is a hard error, not a skip. The content doesn't matter; the second
# pass overwrites it and uses `touch` to force rebuild of just the crate
# root, not the 300+ dependency crates.
RUN mkdir -p src simulation/src benches \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && echo '' > simulation/src/lib.rs \
    && for b in user_lookup token_validation oidc_exchange \
                session_lookup tiered_storage oauth admin audit rbac_check; do \
         echo 'fn main() {}' > "benches/${b}.rs"; \
       done \
    && (test -f Cargo.lock || cargo generate-lockfile)

# Dependency-only build. BuildKit cache mounts persist the cargo registry and
# target directory across builds, so subsequent `docker compose up --build`
# invocations skip already-compiled dependencies entirely.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin hearth \
    && rm -rf src simulation/src benches src/protocol/generated

# ----- Real source pass -------------------------------------------------------
#
# Now copy the real sources. `cargo build` will:
#   1. See the new mtimes on `src/` and recompile the `hearth` crate only.
#   2. Skip every dependency crate, which is already in `target/release/deps`.
#   3. Re-run `build.rs` because `rerun-if-changed=proto/` is set and proto/
#      is identical — so it's effectively a no-op beyond `protoc` being called
#      once more.
COPY src ./src
COPY templates ./templates
COPY simulation ./simulation
# benches/ is not compiled by `--bin hearth`, but Cargo still validates every
# `[[bench]]` target path at manifest-parse time — so the files must exist.
COPY benches ./benches

# `touch` forces cargo to detect the crate roots as changed even if the stub
# had the same mtime (rare but possible with very fast builds). `build.rs`
# is touched too so cargo re-runs it and regenerates `src/protocol/generated/`
# (which was produced in the cache pass, then wiped with the stub src/).
# Templates are touched for the same reason: Askama compiles them at build time
# via proc macros, and the BuildKit cache mount can leave stale fingerprints
# that cause Cargo to skip recompilation even when template files changed.
# Final build: only the hearth crate recompiles (deps are cached). The binary
# must be copied out of the cache mount within this RUN step — the mount
# vanishes from the layer once the command finishes.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    touch src/main.rs src/lib.rs simulation/src/lib.rs build.rs \
    && find templates -type f -exec touch {} + \
    && cargo build --release --bin hearth \
    && strip target/release/hearth \
    && cp target/release/hearth /tmp/hearth

# -----------------------------------------------------------------------------
# Stage 2: runtime
# -----------------------------------------------------------------------------
# Pinning by digest is the strongest supply-chain control available for base
# images. The tag below is kept for human readability; the digest is the
# authoritative lock. Re-pin after every intentional base-image upgrade:
#   docker pull debian:bookworm-slim
#   docker inspect debian:bookworm-slim --format '{{index .RepoDigests 0}}'
FROM debian:bookworm-slim@sha256:67b30a61dc87758f0caf819646104f29ecbda97d920aaf5edc834128ac8493d3 AS runtime

# Runtime deps:
#   - ca-certificates: for outbound TLS (SMTP relay, remote IdPs, webhook
#     targets). Required even though Hearth itself terminates TLS via rustls —
#     the server side uses loaded certs, but any outbound call uses the system
#     trust store.
#   - wget: used by the Docker HEALTHCHECK. bookworm-slim ships it by default
#     in some builds but not all; install explicitly to avoid surprises.
#   - tini: tiny PID 1 that reaps zombies and forwards signals. `hearth serve`
#     already handles SIGTERM cleanly, but tini costs ~200 KB and gives us
#     correct behaviour under `docker stop` (10s grace → SIGKILL) with zero
#     application code changes.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. UID 10001 is outside the system UID range (<1000) and unlikely
# to collide with host users bind-mounted into the container.
RUN groupadd --system --gid 10001 hearth \
    && useradd --system --uid 10001 --gid hearth --no-create-home --shell /usr/sbin/nologin hearth \
    && mkdir -p /var/lib/hearth /etc/hearth \
    && chown -R hearth:hearth /var/lib/hearth /etc/hearth

COPY --from=builder --chmod=0555 /tmp/hearth /usr/local/bin/hearth

USER 10001:10001
WORKDIR /var/lib/hearth

# OCI standard labels: bind the image to a source revision for auditability.
# BUILD_VERSION and BUILD_REVISION are optional build-args; CI should pass them.
ARG BUILD_VERSION=dev
ARG BUILD_REVISION=unknown
LABEL org.opencontainers.image.title="Hearth" \
      org.opencontainers.image.description="Purpose-built identity database: authentication, authorization, and session management" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.revision="${BUILD_REVISION}"

EXPOSE 8420

# /health is unauthenticated and returns `{"status":"ok"}` (see
# src/protocol/http.rs). Fails the healthcheck on any non-2xx, which is the
# signal Compose uses to stop routing to the container.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD wget -qO- http://127.0.0.1:8420/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/hearth"]
CMD ["serve", "-c", "/etc/hearth/hearth.yaml"]
