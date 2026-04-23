# Hearth — Build Targets
# Requires: cargo, cargo-nextest, buf, protoc

PROTOC ?= protoc
CARGO_FLAGS ?=
BUF := buf

.PHONY: setup build test clippy fmt check css css-watch tailwind-install proto-gen proto-lint proto-breaking proto-check sdk-test docker-up docker-reload

# ── Contributor Setup ─────────────────────────────────

## One-time contributor setup: enable repo-managed git hooks.
setup:
	git config core.hooksPath .githooks
	@echo "✓ Git hooks enabled (.githooks/pre-commit)"

# ── Tailwind CSS ──────────────────────────────────────

## Build Tailwind CSS (minified output → embedded asset).
## Must cd into ui/ so Tailwind resolves content paths relative to the config file.
css:
	cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --minify

## Watch mode for local development (auto-rebuilds on template change).
css-watch:
	cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --watch

## Download Tailwind standalone CLI (platform-specific).
tailwind-install:
	@mkdir -p ui
	@OS=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	ARCH=$$(uname -m); \
	case "$$OS-$$ARCH" in \
		linux-x86_64)  BIN=tailwindcss-linux-x64 ;; \
		linux-aarch64) BIN=tailwindcss-linux-arm64 ;; \
		darwin-x86_64) BIN=tailwindcss-macos-x64 ;; \
		darwin-arm64)  BIN=tailwindcss-macos-arm64 ;; \
		*) echo "Unsupported platform: $$OS-$$ARCH" && exit 1 ;; \
	esac; \
	curl -sLo ui/tailwindcss "https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/$$BIN" && \
	chmod +x ui/tailwindcss && \
	echo "✓ Tailwind CLI installed at ui/tailwindcss ($$BIN)"

# ── Rust ──────────────────────────────────────────────

build: css
	PROTOC=$(PROTOC) cargo build $(CARGO_FLAGS)

## Run every Rust test across both workspace crates (main + simulation)
## via nextest. Doctests are intentionally excluded — Hearth favors
## regular `#[cfg(test)] mod tests` blocks over doctest round-trips:
## same coverage, faster compile, shared helpers, single runner.
## Runnable documentation examples live under `examples/`.
test:
	PROTOC=$(PROTOC) cargo nextest run --workspace $(CARGO_FLAGS)

clippy:
	PROTOC=$(PROTOC) cargo clippy --all-targets $(CARGO_FLAGS) -- -D warnings

fmt:
	cargo fmt --check

## Run all Rust checks (build + clippy + fmt + tests).
check: clippy fmt test

# ── Proto ─────────────────────────────────────────────

## Generate SDK types from .proto files (TypeScript + Go).
proto-gen:
	cd proto && $(BUF) generate

## Lint .proto files against STANDARD rules.
proto-lint:
	cd proto && $(BUF) lint

## Check for backwards-incompatible proto changes vs main.
proto-breaking:
	cd proto && $(BUF) breaking --against '../.git#branch=main,subdir=proto'

## Verify generated SDK code is up-to-date with .proto files.
proto-check:
	@echo "Checking generated code is up-to-date..."
	cd proto && $(BUF) generate
	@if git diff --quiet sdks/typescript/src/generated sdks/go/generated; then \
		echo "Generated code is up-to-date."; \
	else \
		echo "ERROR: Generated code is out of date. Run 'make proto-gen' and commit."; \
		git diff --stat sdks/typescript/src/generated sdks/go/generated; \
		exit 1; \
	fi

# ── SDK Tests ─────────────────────────────────────────

## Run TypeScript and Go SDK integration tests.
sdk-test:
	cd sdks/typescript && PROTOC=$(PROTOC) npm test
	cd sdks/go && PROTOC=$(PROTOC) go test ./...

# ── CI Tiers ──────────────────────────────────────────

## CI fast tier: lint + fmt + proto lint (every commit).
ci-fast: fmt clippy proto-lint

## CI standard tier: fast + tests + SDK tests + proto breaking (merge).
ci-standard: ci-fast test proto-breaking sdk-test proto-check

# ── Docker ──────────────────────────────────────────

## First-time image build + start (bakes binary into image).
docker-up:
	docker compose up --build -d

## Fast iterate: incremental Docker build via BuildKit cache + restart (~15–25 s).
## BuildKit cache mounts persist cargo registry + target dir across builds, so
## only the hearth crate recompiles. Works on Linux, macOS, and Windows.
docker-reload:
	docker compose down
	DOCKER_BUILDKIT=1 docker compose up --build -d hearth
