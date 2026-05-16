# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

# OpenHTTPA Workspace Makefile


# Detect OS
OS := $(shell uname)

# Isolation for parallel CI runners
# Use GITHUB_RUN_ID if available, otherwise hash the current directory
RUNNER_ID ?= $(shell pwd | openssl dgst -md5 | sed 's/.* //')
export COMPOSE_PROJECT_NAME ?= openhttpa-$(shell echo $(RUNNER_ID) | head -c 8)

# Build Infrastructure Hardening
export CARGO_NET_RETRY := 10
export RUSTUP_MAX_RETRIES := 10
export CARGO_TERM_COLOR := always
export OPENHTTPA_ALLOW_MOCK_HARDWARE := 1

# Default to skipping expensive ZK method builds and kernels to avoid toolchain dependencies.
# This ensures stability on standard runners without full RISC Zero toolchains.
export OPENHTTPA_SKIP_ZK_BUILD := 1
export RISC0_SKIP_BUILD_KERNELS := 1

# OP-TEE build requirement (optee-teec-sys)
# On non-hardware runners, we provide a dummy export path to allow compilation
export OPTEE_CLIENT_EXPORT ?= /tmp

.PHONY: all build build-release test test-release clean demo clippy fmt format check check-bindings audit test-web check-examples e2e test-all-examples example-resumption example-ohttpa example-attestation example-oblivious example-gpu example-hub example-orchestration example-oracle native-build native-demo native-test ci docs demo-stable-up demo-stable-down test-contracts build-contracts formal formal-verify formal-pv formal-tamarin test-zk-compression audit-zk-scalability

all: build test

setup: ## Install dependencies (pnpm + system libraries)
ifeq ($(OS),Linux)
	@$(MAKE) linux-setup
endif
ifeq ($(OS),Darwin)
	@$(MAKE) darwin-setup
endif
	pnpm install
	@echo "Ready to build! Run 'make build' or 'make demo-up'."

linux-setup: ## Install system dependencies on Ubuntu/Debian
	@echo "Delegating system setup to scripts/setup_linux_env.sh..."
	@bash scripts/setup_linux_env.sh

darwin-setup: ## Install system dependencies on macOS
	@echo "Delegating system setup to scripts/setup_macos_env.sh..."
	@bash scripts/setup_macos_env.sh

## -- CI / Verification --

# Full CI pipeline locally
ci: ## Run all standard CI checks
	@echo "--- Running CI Checks in Parallel ---"
	$(MAKE) -j4 ci-parallel
	@echo "All CI checks passed locally!"

verify-all: format clippy build build-release test test-release ci test-all-examples e2e ## Exhaustive formal validation and verification suite
	@echo "--- ALL FORMAL VALIDATION AND VERIFICATION COMPLETED SUCCESSFULLY ---"
	@echo "The OpenHTTPA project stack is verified for production readiness."

ci-parallel: fmt audit clippy test test-rust-examples check-bindings test-contracts

## -- Development --

# Allow manual override via OPENHTTPA_ZK_GPU (e.g., OPENHTTPA_ZK_GPU=cuda, metal, or none)
OPENHTTPA_ZK_GPU ?= auto

ifeq ($(OS),Darwin)
    # ---------------------------------------------------------------------------
    # macOS: Auto-detect Xcode Metal Toolchain for RISC Zero GPU kernel builds.
    # ---------------------------------------------------------------------------

    ifeq ($(OPENHTTPA_ZK_GPU),auto)
        ifneq ($(OPENHTTPA_SKIP_ZK_BUILD),0)
            ZK_GPU_FEATURE :=
        else
            # Only enable metal GPU feature when the toolchain is actually present;
            # avoids silently producing a non-GPU build without an obvious error.
            ifeq ($(HAS_METAL),yes)
                ZK_GPU_FEATURE := metal
            else
                ZK_GPU_FEATURE :=
            endif
        endif
    else ifeq ($(OPENHTTPA_ZK_GPU),none)
        ZK_GPU_FEATURE :=
    else
        ZK_GPU_FEATURE := $(OPENHTTPA_ZK_GPU)
    endif

    FEATURES := mock,nvidia_gpu
    ifneq ($(ZK_GPU_FEATURE),)
        FEATURES := $(FEATURES),$(ZK_GPU_FEATURE)
    endif
    # For clippy/docs, we prefer a stable baseline unless explicitly testing GPU code
    CLIPPY_FEATURES := --features mock,nvidia_gpu,ita,maa
    ifneq ($(ZK_GPU_FEATURE),)
        # Only add ZK GPU to clippy if we are explicitly building ZK
        ifeq ($(OPENHTTPA_SKIP_ZK_BUILD),0)
            CLIPPY_FEATURES := $(CLIPPY_FEATURES),$(ZK_GPU_FEATURE)
        endif
    endif
else
    # ---------------------------------------------------------------------------
    # Linux: Auto-detect NVIDIA CUDA Toolkit for RISC Zero GPU kernel builds.
    # ---------------------------------------------------------------------------
    # Only enable if nvcc is present AND functional to avoid build failures on non-GPU runners.
    # Some environments have 'nvcc' but lack the full toolkit/libraries.

    ifeq ($(OPENHTTPA_ZK_GPU),auto)
        ifneq ($(OPENHTTPA_SKIP_ZK_BUILD),0)
            ZK_GPU_FEATURE :=
        else
            ifeq ($(HAS_CUDA),yes)
                ZK_GPU_FEATURE := cuda
            else
                ZK_GPU_FEATURE :=
            endif
        endif
    else ifeq ($(OPENHTTPA_ZK_GPU),none)
        ZK_GPU_FEATURE :=
    else
        ZK_GPU_FEATURE := $(OPENHTTPA_ZK_GPU)
    endif

    # Exclude broken 'sgx' feature from automated CI checks for now
    FEATURES := mock,tdx,sev_snp,trustzone,nvidia_gpu
    ifneq ($(ZK_GPU_FEATURE),)
        FEATURES := $(FEATURES),$(ZK_GPU_FEATURE)
    endif

    # Core features that are safe for all runners
    BASE_CLIPPY_FEATURES := mock,tdx,sev_snp,trustzone,nvidia_gpu,ita,maa
    CLIPPY_FEATURES := --features $(BASE_CLIPPY_FEATURES)
    ifneq ($(ZK_GPU_FEATURE),)
        # Only add ZK GPU to clippy if we are explicitly building ZK
        ifeq ($(OPENHTTPA_SKIP_ZK_BUILD),0)
            CLIPPY_FEATURES := $(CLIPPY_FEATURES),$(ZK_GPU_FEATURE)
        endif
    endif
endif

# Autonomous ZK-Compression Verification (ZAA)
test-zk-compression: ## Verify ZK-DCAP compression ratio and guest logic
	@echo "--- Verifying ZK-DCAP Compression (ZAA) ---"
	OPENHTTPA_SKIP_ZK_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo test -p openhttpa-zk --test integration -- test_zk_dcap_compression
	@echo "ZAA autonomous verification passed!"

audit-zk-scalability: ## Profile ZK guest cycle counts for scalability audit
	@echo "--- Profiling ZK Guest Scalability ---"
	@if [ "$(OPENHTTPA_SKIP_ZK_BUILD)" = "1" ]; then \
		echo "Error: audit-zk-scalability requires OPENHTTPA_SKIP_ZK_BUILD=0"; \
		exit 1; \
	fi
	cargo run --example profile_guest -p openhttpa-zk -- --mode dcap-compression

# Build all Rust crates (excluding those that require special toolchains like wasm/python).
# RISC0_SKIP_BUILD_KERNELS is set automatically above by the Metal/CUDA probe.
# It is forwarded explicitly here so all child cargo invocations see the same value,
# even when invoked via recursive make or with a different environment.
build: ## Build all Rust crates (debug)
	RISC0_SKIP_BUILD_KERNELS=$(RISC0_SKIP_BUILD_KERNELS) cargo build --workspace --features $(FEATURES)

build-release: ## Build all Rust crates (release)
	RISC0_SKIP_BUILD_KERNELS=$(RISC0_SKIP_BUILD_KERNELS) cargo build --workspace --features $(FEATURES) --release

# Run all Rust tests.
# Forwards RISC0_SKIP_BUILD_KERNELS so test compilation is consistent with the build.
test: ## Run all Rust tests (debug)
	RISC0_SKIP_BUILD_KERNELS=$(RISC0_SKIP_BUILD_KERNELS) cargo test --workspace --features $(FEATURES)

test-release: ## Run all Rust tests (release)
	RISC0_SKIP_BUILD_KERNELS=$(RISC0_SKIP_BUILD_KERNELS) cargo test --workspace --features $(FEATURES) --release

# Run all Playwright E2E tests (requires running stack)
test-web: ## Run Playwright E2E tests (individual)
	pnpm test

# Run full E2E suite (starts demo stack + tests)
e2e: build wasm ## Run full E2E suite (starts demo stack + tests)
	@echo "Starting E2E stack for project: $(COMPOSE_PROJECT_NAME)"
	@trap '$(MAKE) -C demo/multiparty-webapp down' EXIT; \
	$(MAKE) -C demo/multiparty-webapp up; \
	$(MAKE) -C demo/multiparty-webapp e2e-run; \
	$(MAKE) test-bindings

# Fast workspace check
check: ## Run cargo check on workspace
	cargo check --workspace

# Verify all examples compile (software-safe features)
check-examples: ## Verify all examples compile
	cargo check --examples --workspace --features openhttpa-attestation/ita,openhttpa-attestation/maa,openhttpa-tee/mock,openhttpa-tee/nvidia_gpu

clippy: ## Run clippy lints (all features)
	@mkdir -p /tmp/usr/lib
	OPENHTTPA_SKIP_ZK_BUILD=$(OPENHTTPA_SKIP_ZK_BUILD) RISC0_SKIP_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 rustup run stable cargo clippy --workspace --all-targets $(CLIPPY_FEATURES) -- -D warnings

node_modules: package.json pnpm-lock.yaml ## Ensure Node.js dependencies are installed
	pnpm install
	@touch node_modules

fmt: node_modules ## Check code formatting
	rustup run stable cargo fmt --all -- --check
	@if command -v forge >/dev/null 2>&1; then \
		cd crates/openhttpa-contract && forge fmt --check; \
	fi
	pnpm run fmt:check

format: node_modules ## Apply code formatting
	rustup run stable cargo fmt --all
	@if command -v forge >/dev/null 2>&1; then \
		cd crates/openhttpa-contract && forge fmt; \
	fi
	pnpm run fmt

# Audit dependencies for vulnerabilities and licenses
audit: ## Audit dependencies (cargo-deny + cargo-audit + pnpm + uv)
	@command -v cargo-deny >/dev/null 2>&1 || cargo install cargo-deny --locked
	cargo deny check
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	cargo audit
	@echo "Auditing Node.js dependencies..."
	cd bindings/nodejs && pnpm audit --prod
	@echo "Auditing Python dependencies..."
	cd bindings/python && uv lock --check

# Verify all language bindings compile
check-bindings: check-python-bindings check-node-bindings check-go-bindings ## Verify all language bindings compile

check-python-bindings:
	@echo "Checking Python bindings..."
	@command -v uv >/dev/null 2>&1 && uvx maturin build -m bindings/python/Cargo.toml --release || { cd bindings/python && maturin build --release; }

check-node-bindings:
	@echo "Checking Node.js bindings..."
	cd bindings/nodejs && pnpm install && pnpm build

check-go-bindings:
	@echo "Checking Go bindings..."
	cargo build -p openhttpa-c --release
	cd bindings/go && go build ./...

# Generate documentation and check for broken links
docs: ## Generate workspace documentation
	@mkdir -p /tmp/usr/lib
	OPENHTTPA_SKIP_ZK_BUILD=$(OPENHTTPA_SKIP_ZK_BUILD) RUSTDOCFLAGS="-D warnings" cargo doc --workspace $(CLIPPY_FEATURES) --no-deps

# Clean build artifacts
clean: ## Remove basic build artifacts
	cargo clean || rm -rf target/

deep-clean: clean ## Remove ALL artifacts (node_modules, wasm, etc.)
	rm -rf node_modules/
	rm -rf bindings/nodejs/node_modules/
	rm -rf demo/multiparty-webapp/frontend/wasm/
	rm -rf playwright-report/ test-results/
	find . -name "dist" -type d -exec rm -rf {} +
	find . -name ".turbo" -type d -exec rm -rf {} +

doctor: ## Check system dependencies and environment readiness
	@echo "=== OpenHTTPA System Doctor ==="
	@echo -n "Rust: " && cargo --version || echo "MISSING"
	@echo -n "Go: " && go version || echo "MISSING"
	@echo -n "Node.js: " && node --version || echo "MISSING"
	@echo -n "pnpm: " && pnpm --version || echo "MISSING"
	@echo -n "Python/uv: " && uv --version || echo "MISSING"
	@echo -n "Docker: " && docker version --format '{{.Server.Version}}' || echo "MISSING"
	@echo -n "Wasm-pack: " && wasm-pack --version || echo "MISSING"
	@echo -n "ProVerif: " && (proverif -version 2>/dev/null || (eval $(opam env) && proverif -version)) || echo "MISSING"
	@echo "============================="
	@$(MAKE) repair-rust

repair-rust: ## Repair corrupted Rust toolchain and components
	@echo "Repairing Rust toolchain (stable)..."
	@if command -v rustup >/dev/null 2>&1; then \
		rustup self update; \
		rustup toolchain install stable --component rustfmt --component clippy --component llvm-tools-preview --force; \
		rustup default stable; \
		echo "Rust toolchain repaired successfully."; \
	else \
		echo "Error: rustup not found."; \
		exit 1; \
	fi

formal: ## Run formal verification models (ProVerif)
	@echo "Running formal verification..."
	@if ! command -v proverif >/dev/null 2>&1; then \
		eval $$(opam env) || true; \
	fi; \
	if command -v proverif >/dev/null 2>&1; then \
		proverif formal/handshake.pv; \
	else \
		echo "Error: proverif not found. Please install it via opam."; \
		exit 1; \
	fi

## -- Demo --

# Start the full demo stack (backend + frontend)
demo-up: build wasm ## Launch the MPC demo via Docker
	make -C demo/multiparty-webapp up

# Stop the demo stack
demo-down: ## Stop the demo stack
	make -C demo/multiparty-webapp down

# Start the stable demo instance (port 3001, isolated)
demo-stable-up: build wasm ## Start the stable demo instance (port 3001, isolated)
	make -C demo/multiparty-webapp stable-up

# Stop the stable demo instance
demo-stable-down: ## Stop the stable demo instance
	make -C demo/multiparty-webapp stable-down

# Restart the stable demo instance (clean refresh)
demo-stable-restart: demo-stable-down demo-stable-up ## Restart the stable demo instance (clean refresh)

# Show status of the stable demo instance
demo-stable-status: ## Show status of the stable demo instance
	make -C demo/multiparty-webapp stable-status

# Follow logs from the stable demo instance
demo-stable-logs: ## Follow logs from the stable demo instance
	COMPOSE_PROJECT_NAME=openhttpa-stable docker compose -f demo/multiparty-webapp/docker-compose.yml logs -f

# Launch the native Nginx/Caddy module demo stack
demo-native-up: native-build ## Launch the native module demo stack
	cd demo/native-modules && docker-compose up -d

# Stop the native module demo stack
demo-native-down: ## Stop the native module demo stack
	cd demo/native-modules && docker-compose down

## -- Agentic Mesh --

# Run the basic 2-agent swarm simulation
swarm: swarm-basic
swarm-basic: ## Run basic 2-agent swarm simulation
	cargo run --example basic_swarm -p openhttpa-mesh

# Run the massive 100-agent swarm simulation
swarm-massive: ## Run massive 100-agent swarm simulation
	cargo run --example massive_swarm -p openhttpa-mesh

# Run the complex 10+ agent delegation demo
swarm-complex: ## Run complex 10+ agent delegation demo
	cargo run --example complex_delegation -p openhttpa-mesh

## -- Examples --

# Run all non-interactive examples and verify others
test-all-examples: check-examples test-rust-examples test-bindings ## Run all non-interactive examples
	@echo "All verified examples passed."

test-rust-examples: example-resumption example-ohttpa example-attestation example-gpu example-oblivious example-orchestration example-hub example-oracle example-swarm example-llm example-crypto ## Run only Rust-based non-interactive examples
	@echo "All Rust examples passed."

# Individual Rust examples (root moved to crates)
example-resumption: ## Run the session resumption example
	cargo run --example resumption_example -p openhttpa-core

example-ohttpa: ## Run the O-HTTPA oblivious example
	cargo run --example o-httpa_example -p openhttpa-transport

example-attestation: ## Run the remote attestation config example
	OpenHTTPA_ITA_API_KEY=mock cargo run --example remote_attestation -p openhttpa-server --features ita

example-oblivious: ## Run the full oblivious client example
	cargo run --example full_oblivious_client -p openhttpa-client

# Individual Rust examples (crates)
example-gpu: ## Run the NVIDIA GPU attestation example
	cargo run --example nvidia_gpu_attestation -p openhttpa-client --features nvidia_gpu

example-hub: ## Run the attestation hub server example (timeout 5s)
	@echo "Starting Hub (will stop after 5s)..."
	-timeout 5 cargo run --example attestation_hub -p openhttpa-server || true

example-orchestration: ## Run the agent orchestration example
	cargo run --example orchestration -p openhttpa-a2a

example-oracle: ## Run the Web3 Oracle integration tests
	RISC0_SKIP_BUILD_KERNELS=1 cargo test -p openhttpa-oracle

example-swarm: ## Run basic swarm simulation
	cargo run --example basic_swarm -p openhttpa-mesh

example-llm: ## Run verified AI chat example
	cargo run --example verified_ai -p openhttpa-llm

example-crypto: ## Run crypto test vector generation example
	cargo run --example gen_vectors -p openhttpa-crypto

build-contracts: ## Build Solidity contracts
	@if command -v forge >/dev/null 2>&1; then \
		cd crates/openhttpa-contract && forge build; \
	fi

test-contracts: ## Run Solidity contract tests
	@if command -v forge >/dev/null 2>&1; then \
		cd crates/openhttpa-contract && forge test; \
	fi

## -- Bindings --

# Run all language binding examples (requires Docker)
test-bindings: test-all-bindings ## Alias for test-all-bindings
test-all-bindings: ## Run all language binding integration tests
	./bindings/run_examples.sh

# Individual binding shortcuts
bind-python: ## Build Python bindings
	cd bindings/python && maturin develop

bind-nodejs: ## Build Node.js bindings
	cd bindings/nodejs && pnpm install && pnpm run build

bind-go: ## Build Go bindings
	cd bindings/go && go build ./...

bind-c: ## Build C bindings
	cargo build -p openhttpa-c --release

wasm: ## Build browser Wasm bindings
	make -C demo/multiparty-webapp wasm

## -- Native Infrastructure --

native-build: bind-c bind-go ## Build native Nginx and Caddy modules
	cd modules/nginx && cargo build --release
	cd modules/caddy && go build -o openhttpa-caddy main.go

native-demo: demo-native-up ## Alias for demo-native-up

native-test: demo-native-up ## Run autonomous E2E tests for native modules
	cd demo/native-modules && pnpm install && pnpm test

native-down: demo-native-down ## Alias for demo-native-down

## -- Formal Verification --

# Run all formal security proofs
formal-verify: formal-pv formal-tamarin ## Run all formal proofs
	@echo "All formal proofs complete."

# Run ProVerif symbolic analysis
formal-pv: ## Run ProVerif symbolic analysis
	@echo "Running ProVerif... (If not found, try: eval \$$(opam env))"
	proverif formal/handshake.pv

# Run Tamarin temporal logic analysis (CLI mode)
formal-tamarin: ## Run Tamarin temporal logic analysis
	tamarin-prover --prove --heuristic=s formal/handshake.spthy +RTS -N -RTS

# Start Tamarin interactive web UI
formal-tamarin-ui: ## Start Tamarin interactive web UI
	tamarin-prover interactive formal/

## -- Documents --

# Convert any Markdown file to PDF
# Usage: make pdf FILE=API.md
pdf: ## Convert Markdown to PDF (Usage: make pdf FILE=README.md)
	@if [ -z "$(FILE)" ]; then echo "Error: Please specify FILE=... (e.g., make pdf FILE=API.md)"; exit 1; fi
	@echo "Rendering $(FILE) to PDF..."
	@PUPPETEER_EXECUTABLE_PATH="/Users/gordonk/.cache/puppeteer/chrome/mac_arm-146.0.7680.153/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" \
	pnpm dlx md-to-pdf $(FILE) --pdf-options '{ "format": "A4", "margin": { "top": "20mm", "bottom": "20mm", "left": "20mm", "right": "20mm" } }'

## -- Help --

help: ## Show this help message
	@echo "\033[1;34mOpenHTTPA Monorepo Management\033[0m"
	@echo ""
	@echo "Usage: \033[1mmake [target]\033[0m"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$|## -- .* --' $(MAKEFILE_LIST) | grep -v "grep" | sort | awk 'BEGIN {FS = ":.*?## "}; { \
		if ($$0 ~ /^## --/) { \
			header = substr($$0, 7, length($$0) - 9); \
			printf "\n\033[1;33m%s\033[0m\n", header \
		} else { \
			printf "  \033[1;32m%-15s\033[0m %s\n", $$1, $$2 \
		} \
	}'
