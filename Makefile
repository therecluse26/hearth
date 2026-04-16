# Hearth — Build Targets
# Requires: cargo, cargo-nextest, buf, protoc

PROTOC ?= protoc
CARGO_FLAGS ?=
BUF := buf

.PHONY: setup build test clippy fmt check proto-gen proto-lint proto-breaking proto-check sdk-test

# ── Contributor Setup ─────────────────────────────────

## One-time contributor setup: enable repo-managed git hooks.
setup:
	git config core.hooksPath .githooks
	@echo "✓ Git hooks enabled (.githooks/pre-commit)"

# ── Rust ──────────────────────────────────────────────

build:
	PROTOC=$(PROTOC) cargo build $(CARGO_FLAGS)

test:
	PROTOC=$(PROTOC) cargo nextest run $(CARGO_FLAGS)

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
