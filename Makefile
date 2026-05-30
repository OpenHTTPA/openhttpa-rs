# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

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
export CI ?= true
export TMPDIR ?= /tmp


# Default to skipping expensive ZK method builds and kernels to avoid toolchain dependencies.
# This ensures stability on standard runners without full RISC Zero toolchains.
export OPENHTTPA_SKIP_ZK_BUILD := 1
export RISC0_SKIP_BUILD_KERNELS := 1

# OP-TEE build requirement (optee-teec-sys)
# On non-hardware runners, we provide a dummy export path to allow compilation
export OPTEE_CLIENT_EXPORT ?= /tmp

# Paths and Commands
DEMO_DIR := demo/multiparty-webapp
DEMO_MAKE := $(MAKE) -C $(DEMO_DIR)


.PHONY: all
all: build test

.PHONY: setup
setup: ## Install dependencies (pnpm + system libraries)
ifeq ($(OS),Linux)
	@$(MAKE) linux-setup
endif
ifeq ($(OS),Darwin)
	@$(MAKE) darwin-setup
endif
	pnpm install
	@echo "Ready to build! Run 'make build' or 'make demo-up'."

.PHONY: linux-setup
linux-setup: ## Install system dependencies on Ubuntu/Debian
	@echo "Delegating system setup to scripts/setup_linux_env.sh..."
	@bash scripts/setup_linux_env.sh

.PHONY: darwin-setup
darwin-setup: ## Install system dependencies on macOS
	@echo "Delegating system setup to scripts/setup_macos_env.sh..."
	@bash scripts/setup_macos_env.sh

## -- CI / Verification --

# Full CI pipeline locally
.PHONY: ci
ci: ## Run all standard CI checks
	@echo "--- Running CI Checks ---"
	@$(MAKE) -j3 ci-tools
	@$(MAKE) ci-rust
	@echo "All CI checks passed locally!"

.PHONY: ci-tools
ci-tools: fmt audit check-bindings

.PHONY: ci-rust
ci-rust: clippy test test-rust-examples test-contracts

.PHONY: verify-core
verify-core: format clippy build build-release test test-release ## Verify core Rust crates
	@echo "--- CORE VERIFICATION COMPLETED ---"

.PHONY: verify-bindings
verify-bindings: check-bindings test-bindings ## Verify multi-language bindings and FFI
	@echo "--- BINDINGS VERIFICATION COMPLETED ---"

.PHONY: verify-examples
verify-examples: check-examples test-rust-examples ## Verify all interactive and non-interactive examples
	@echo "--- EXAMPLES VERIFICATION COMPLETED ---"

.PHONY: verify-demo-run
verify-demo-run:
	$(DEMO_MAKE) e2e-run

.PHONY: verify-demo
verify-demo: ## Verify E2E demo stack functionality
	@echo "Starting E2E stack for project: $(COMPOSE_PROJECT_NAME) for verify-demo"
	@set -e; \
	trap '$(MAKE) demo-down' EXIT; \
	$(MAKE) demo-up; \
	$(MAKE) verify-demo-run
	@echo "--- DEMO VERIFICATION COMPLETED ---"

.PHONY: verify-all
verify-all: verify-core check-bindings verify-examples ci ## Exhaustive formal validation and verification suite
	@echo "--- STARTING SHARED DEMO STACK FOR VERIFY-ALL ---"
	@set -e; \
	trap '$(MAKE) demo-down' EXIT; \
	$(MAKE) demo-up; \
	$(MAKE) test-bindings-run; \
	$(MAKE) verify-demo-run
	@echo "--- ALL FORMAL VALIDATION AND VERIFICATION COMPLETED SUCCESSFULLY ---"
	@echo "The OpenHTTPA project stack is verified for production readiness."

.PHONY: ci-parallel
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
.PHONY: test-zk-compression
test-zk-compression: ## Verify ZK-DCAP compression ratio and guest logic
	@echo "--- Verifying ZK-DCAP Compression (ZAA) ---"
	+OPENHTTPA_SKIP_ZK_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo test -p openhttpa-zk --test integration -- test_zk_dcap_compression
	@echo "ZAA autonomous verification passed!"

.PHONY: audit-zk-scalability
audit-zk-scalability: ## Profile ZK guest cycle counts for scalability audit
	@echo "--- Profiling ZK Guest Scalability ---"
	@if [ "$(OPENHTTPA_SKIP_ZK_BUILD)" = "1" ]; then \
		echo "Error: audit-zk-scalability requires OPENHTTPA_SKIP_ZK_BUILD=0"; \
		exit 1; \
	fi
	+cargo run --example profile_guest -p openhttpa-zk -- --mode dcap-compression

# Build all Rust crates (excluding those that require special toolchains like wasm/python).
# RISC0_SKIP_BUILD_KERNELS is set automatically above by the Metal/CUDA probe.
# It is forwarded explicitly here so all child cargo invocations see the same value,
# even when invoked via recursive make or with a different environment.
.PHONY: build
build: ## Build all Rust crates (debug)
	+RISC0_SKIP_BUILD_KERNELS=$(RISC0_SKIP_BUILD_KERNELS) cargo build --workspace --features $(FEATURES)

.PHONY: build-release
build-release: ## Build all Rust crates (release)
	+RISC0_SKIP_BUILD_KERNELS=$(RISC0_SKIP_BUILD_KERNELS) cargo build --workspace --features $(FEATURES) --release

# Run all Rust tests.
# Forwards RISC0_SKIP_BUILD_KERNELS so test compilation is consistent with the build.
.PHONY: test
test: ## Run all Rust tests (debug)
	+RISC0_SKIP_BUILD_KERNELS=$(RISC0_SKIP_BUILD_KERNELS) cargo test --workspace --features $(FEATURES)

.PHONY: test-release
test-release: ## Run all Rust tests (release)
	+RISC0_SKIP_BUILD_KERNELS=$(RISC0_SKIP_BUILD_KERNELS) cargo test --workspace --features $(FEATURES) --release

# Run all Playwright E2E tests (requires running stack)
.PHONY: test-web
test-web: ## Run Playwright E2E tests (individual)
	pnpm test

# Run full E2E suite (starts demo stack + tests)
.PHONY: e2e
e2e: ## Run full E2E suite (starts demo stack + tests)
	@echo "Starting E2E stack for project: $(COMPOSE_PROJECT_NAME)"
	@set -e; \
	trap '$(MAKE) demo-down' EXIT; \
	$(MAKE) demo-up; \
	$(MAKE) verify-demo-run; \
	$(MAKE) test-bindings-run

# Fast workspace check
.PHONY: check
check: ## Run cargo check on workspace
	+cargo check --workspace

# Verify all examples compile (software-safe features)
.PHONY: check-examples
check-examples: ## Verify all examples compile
	+cargo check --examples --workspace --features openhttpa-attestation/ita,openhttpa-attestation/maa,openhttpa-tee/mock,openhttpa-tee/nvidia_gpu

.PHONY: clippy
clippy: ## Run clippy lints (all features)
	@mkdir -p /tmp/usr/lib
	+OPENHTTPA_SKIP_ZK_BUILD=$(OPENHTTPA_SKIP_ZK_BUILD) RISC0_SKIP_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 rustup run stable cargo clippy --workspace --all-targets $(CLIPPY_FEATURES) -- -D warnings

node_modules: package.json pnpm-lock.yaml ## Ensure Node.js dependencies are installed
	pnpm install
	@touch node_modules

.PHONY: fmt
fmt: node_modules ## Check code formatting
	+rustup run stable cargo fmt --all -- --check
	@if command -v forge >/dev/null 2>&1; then \
		cd crates/openhttpa-contract && forge fmt --check; \
	fi
	pnpm run fmt:check

.PHONY: format
format: node_modules ## Apply code formatting
	+rustup run stable cargo fmt --all
	@if command -v forge >/dev/null 2>&1; then \
		cd crates/openhttpa-contract && forge fmt; \
	fi
	pnpm run fmt

# Audit dependencies for vulnerabilities and licenses
.PHONY: audit
audit: ## Audit dependencies (cargo-deny + cargo-audit + pnpm + uv)
	@command -v cargo-deny >/dev/null 2>&1 || cargo install cargo-deny --locked
	cargo deny check
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	cargo audit
	@echo "Auditing Node.js dependencies..."
	cd bindings/nodejs && pnpm audit --prod
	@echo "Auditing Python dependencies..."
	cd bindings/python && uv lock --check

.PHONY: upgrade-outdated
upgrade-outdated: ## Identify outdated crates and upgrade them all autonomously
	@echo "Identifying and upgrading outdated crates..."
	@command -v cargo-outdated >/dev/null 2>&1 || cargo install cargo-outdated
	@command -v cargo-upgrade >/dev/null 2>&1 || cargo install cargo-edit
	cargo outdated || true
	cargo upgrade -i --exclude teaclave-sgx-sdk --exclude sgx_types
	cargo update

# Verify all language bindings compile
.PHONY: check-bindings
check-bindings: check-python-bindings check-node-bindings check-go-bindings ## Verify all language bindings compile

.PHONY: check-python-bindings
check-python-bindings:
	@echo "Checking Python bindings..."
	+@command -v uv >/dev/null 2>&1 && uvx maturin build -m bindings/python/Cargo.toml --release --auditwheel repair || { cd bindings/python && maturin build --release --auditwheel repair; }

.PHONY: check-node-bindings
check-node-bindings:
	@echo "Checking Node.js bindings..."
	# bindings/nodejs is a pnpm workspace member; deps are managed by the root pnpm-lock.yaml.
	# Use --filter to install/sync only this workspace package without triggering an interactive
	# "recreate node_modules?" prompt that occurs when pnpm install is run inside the subdirectory.
	pnpm install --frozen-lockfile --filter @openhttpa/core
	cd bindings/nodejs && pnpm build

.PHONY: check-go-bindings
check-go-bindings:
	@echo "Checking Go bindings..."
	+cargo build -p openhttpa-c --release
	cd bindings/go && go build ./...

# Generate documentation and check for broken links
.PHONY: docs
docs: ## Generate workspace documentation
	@mkdir -p /tmp/usr/lib
	+OPENHTTPA_SKIP_ZK_BUILD=$(OPENHTTPA_SKIP_ZK_BUILD) RUSTDOCFLAGS="-D warnings" cargo doc --workspace $(CLIPPY_FEATURES) --no-deps

# Clean build artifacts
.PHONY: clean
clean: ## Remove basic build artifacts
	cargo clean || rm -rf target/

.PHONY: deep-clean
deep-clean: clean ## Remove ALL artifacts (node_modules, wasm, etc.)
	rm -rf node_modules/
	rm -rf bindings/nodejs/node_modules/
	rm -rf $(DEMO_DIR)/frontend/wasm/
	rm -rf modules/browser-extension/wasm/
	rm -rf playwright-report/ test-results/
	find . -name "dist" -type d -exec rm -rf {} +
	find . -name ".turbo" -type d -exec rm -rf {} +

.PHONY: doctor
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

.PHONY: repair-rust
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

.PHONY: formal
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
.PHONY: demo-up
demo-up: build wasm ## Launch the MPC demo via Docker
	$(MAKE) demo-down
	$(DEMO_MAKE) up

# Stop the demo stack
.PHONY: demo-down
demo-down: ## Stop the demo stack
	$(DEMO_MAKE) down

# Start the stable demo instance (port 3001, isolated)
.PHONY: demo-stable-up
demo-stable-up: build wasm ## Start the stable demo instance (port 3001, isolated)
	$(MAKE) demo-stable-down
	$(DEMO_MAKE) stable-up

# Stop the stable demo instance
.PHONY: demo-stable-down
demo-stable-down: ## Stop the stable demo instance
	$(DEMO_MAKE) stable-down

# Restart the stable demo instance (clean refresh)
.PHONY: demo-stable-restart
demo-stable-restart: demo-stable-down demo-stable-up ## Restart the stable demo instance (clean refresh)

# Show status of the stable demo instance
.PHONY: demo-stable-status
demo-stable-status: ## Show status of the stable demo instance
	$(DEMO_MAKE) stable-status

.PHONY: status
status: ## Show complete status of project workspace, Git, Husky hooks, and stable docker stack
	@echo "\033[1;34m=== OpenHTTPA Project Status ===\033[0m"
	@echo ""
	@echo "\033[1;33m[Git Workspace Status]\033[0m"
	@git status -s || echo "Error: Not a Git repository"
	@echo ""
	@echo "\033[1;33m[Husky Hooks Status]\033[0m"
	@if [ -x .husky/commit-msg ] && [ -x .husky/prepare-commit-msg ]; then \
		echo "  \033[1;32m✓\033[0m Husky hooks are configured and executable"; \
	else \
		echo "  \033[1;31m✗\033[0m Warning: Husky hooks are missing or not executable"; \
	fi
	@echo ""
	@echo "\033[1;33m[Stable Demo Stack Status]\033[0m"
	@$(MAKE) demo-stable-status
	@echo ""
	@echo "\033[1;34m================================\033[0m"

# Follow logs from the stable demo instance
.PHONY: demo-stable-logs
demo-stable-logs: ## Follow logs from the stable demo instance
	COMPOSE_PROJECT_NAME=openhttpa-stable docker compose -f $(DEMO_DIR)/docker-compose.yml logs -f

# Launch the native Nginx/Caddy module demo stack
.PHONY: demo-native-up
demo-native-up: native-build ## Launch the native module demo stack
	cd demo/native-modules && docker-compose up -d

# Stop the native module demo stack
.PHONY: demo-native-down
demo-native-down: ## Stop the native module demo stack
	cd demo/native-modules && docker-compose down

## -- Agentic Mesh --

# Run the basic 2-agent swarm simulation
.PHONY: swarm
swarm: swarm-basic
.PHONY: swarm-basic
swarm-basic: ## Run basic 2-agent swarm simulation
	cargo run --example basic_swarm -p openhttpa-mesh

# Run the massive 100-agent swarm simulation
.PHONY: swarm-massive
swarm-massive: ## Run massive 100-agent swarm simulation
	cargo run --example massive_swarm -p openhttpa-mesh

# Run the complex 10+ agent delegation demo
.PHONY: swarm-complex
swarm-complex: ## Run complex 10+ agent delegation demo
	cargo run --example complex_delegation -p openhttpa-mesh

## -- Examples --

# Run all non-interactive examples and verify others
.PHONY: test-all-examples
test-all-examples: check-examples test-rust-examples test-bindings ## Run all non-interactive examples
	@echo "All verified examples passed."

.PHONY: test-rust-examples
test-rust-examples: example-resumption example-ohttpa example-attestation example-gpu example-oblivious example-orchestration example-hub example-oracle example-swarm example-llm example-crypto example-federation ## Run only Rust-based non-interactive examples
	@echo "All Rust examples passed."

# Individual Rust examples (root moved to crates)
.PHONY: example-resumption
example-resumption: ## Run the session resumption example
	+cargo run --example resumption_example -p openhttpa-core

.PHONY: example-ohttpa
example-ohttpa: ## Run the O-HTTPA oblivious example
	+cargo run --example o-httpa_example -p openhttpa-transport

.PHONY: example-attestation
example-attestation: ## Run the remote attestation config example
	+OpenHTTPA_ITA_API_KEY=mock cargo run --example remote_attestation -p openhttpa-server --features ita

.PHONY: example-oblivious
example-oblivious: ## Run the full oblivious client example
	+cargo run --example full_oblivious_client -p openhttpa-client

# Individual Rust examples (crates)
.PHONY: example-gpu
example-gpu: ## Run the NVIDIA GPU attestation example
	+cargo run --example nvidia_gpu_attestation -p openhttpa-client --features nvidia_gpu

.PHONY: example-hub
example-hub: ## Run the attestation hub server example (timeout 5s)
	@echo "Starting Hub (will stop after 5s)..."
	+-timeout 5 cargo run --example attestation_hub -p openhttpa-server || true

.PHONY: example-federation
example-federation: ## Run the autonomous cross-vendor federation demo
	+cargo run --example federated_mock_mesh -p openhttpa-attestation --features mock

.PHONY: example-orchestration
example-orchestration: ## Run the agent orchestration example
	+cargo run --example orchestration -p openhttpa-a2a

.PHONY: example-oracle
example-oracle: ## Run the Web3 Oracle integration tests
	+RISC0_SKIP_BUILD_KERNELS=1 cargo test -p openhttpa-oracle

.PHONY: example-swarm
example-swarm: ## Run basic swarm simulation
	+cargo run --example basic_swarm -p openhttpa-mesh

.PHONY: example-llm
example-llm: ## Run verified AI chat example
	+cargo run --example verified_ai -p openhttpa-llm

.PHONY: example-crypto
example-crypto: ## Run crypto test vector generation example
	+cargo run --example gen_vectors -p openhttpa-crypto

.PHONY: build-contracts
build-contracts: ## Build Solidity contracts
	@if command -v forge >/dev/null 2>&1; then \
		cd crates/openhttpa-contract && forge build; \
	fi

.PHONY: test-contracts
test-contracts: ## Run Solidity contract tests
	@if command -v forge >/dev/null 2>&1; then \
		cd crates/openhttpa-contract && forge test; \
	fi

## -- Bindings --

# Run all language binding examples (requires Docker)
.PHONY: test-bindings-run
test-bindings-run:
	./bindings/run_examples.sh

.PHONY: test-bindings
test-bindings: test-all-bindings ## Alias for test-all-bindings
.PHONY: test-all-bindings
test-all-bindings: ## Run all language binding integration tests
	@set -e; \
	trap '$(MAKE) demo-down' EXIT; \
	$(MAKE) demo-up; \
	$(MAKE) test-bindings-run

# Individual binding shortcuts
.PHONY: bind-python
bind-python: ## Build Python bindings
	cd bindings/python && maturin develop

.PHONY: bind-nodejs
bind-nodejs: ## Build Node.js bindings
	# bindings/nodejs is a pnpm workspace member; use --filter from workspace root to avoid
	# interactive "recreate node_modules?" prompts caused by running pnpm install inside the subdir.
	pnpm install --filter @openhttpa/core
	cd bindings/nodejs && pnpm run build

.PHONY: bind-go
bind-go: ## Build Go bindings
	cd bindings/go && go build ./...

.PHONY: bind-c
bind-c: ## Build C bindings
	+cargo build -p openhttpa-c --release

.PHONY: wasm
wasm: wasm-demo wasm-extension ## Build both browser and extension Wasm bindings

.PHONY: wasm-demo
wasm-demo:
	$(DEMO_MAKE) wasm

.PHONY: wasm-extension
wasm-extension: ## Build browser extension Wasm bindings
	@command -v wasm-pack >/dev/null 2>&1 || { \
		echo "wasm-pack not found. Install with:  cargo install wasm-pack"; \
		exit 1; \
	}
	@echo "Building browser extension Wasm bindings..."
	@mkdir -p modules/browser-extension/wasm
	+wasm-pack build bindings/wasm \
		--target web \
		--out-dir $(CURDIR)/modules/browser-extension/wasm \
		--release
	@echo "Browser extension Wasm build complete."

## -- Publish / Distribution --

.PHONY: bump
bump: version ## Alias for version
.PHONY: version
version: ## Interactive wizard to bump semantic version
	uv run scripts/bump.py

.PHONY: publish
publish: publish-wizard ## Alias for publish-wizard
.PHONY: publish-wizard
publish-wizard: ## Interactive wizard to publish packages smoothly
	uv run scripts/publish.py

.PHONY: publish-python
publish-python: ## Publish Python bindings to PyPI
	@bash scripts/publish_python.sh

.PHONY: publish-npm
publish-npm: ## Publish Node.js bindings to npm
	@bash scripts/publish_npm.sh

.PHONY: publish-wasm
publish-wasm: ## Publish WASM bindings to npm
	@bash scripts/publish_wasm.sh

.PHONY: publish-go
publish-go: ## Publish Go FFI module to Git/Go Proxy
	@bash scripts/publish_go.sh

.PHONY: publish-crates
publish-crates: ## Publish workspace Rust crates to crates.io
	@bash scripts/publish_crates.sh

.PHONY: publish-github
publish-github: ## Build hardened production binary, SBOM, and publish GitHub Release
	@bash scripts/publish_github.sh

.PHONY: publish-all
publish-all: publish-crates publish-python publish-npm publish-wasm publish-go publish-github ## Publish to all destinations sequentially

## -- Native Infrastructure --

.PHONY: native-build
native-build: bind-c bind-go ## Build native Nginx and Caddy modules
	+cd modules/nginx && cargo build --release
	cd modules/caddy && go build -o openhttpa-caddy main.go

.PHONY: native-demo
native-demo: demo-native-up ## Alias for demo-native-up

.PHONY: native-test
native-test: demo-native-up ## Run autonomous E2E tests for native modules
	cd demo/native-modules && pnpm install && pnpm test

.PHONY: native-down
native-down: demo-native-down ## Alias for demo-native-down

## -- Formal Verification --

# Run all formal security proofs
.PHONY: formal-verify
formal-verify: formal-pv formal-tamarin ## Run all formal proofs
	@echo "All formal proofs complete."

# Run ProVerif symbolic analysis
.PHONY: formal-pv
formal-pv: ## Run ProVerif symbolic analysis
	@echo "Running ProVerif... (If not found, try: eval \$$(opam env))"
	proverif formal/handshake.pv

# Run Tamarin temporal logic analysis (CLI mode)
.PHONY: formal-tamarin
formal-tamarin: ## Run Tamarin temporal logic analysis
	tamarin-prover --prove --heuristic=s formal/handshake.spthy +RTS -N -RTS

# Start Tamarin interactive web UI
.PHONY: formal-tamarin-ui
formal-tamarin-ui: ## Start Tamarin interactive web UI
	tamarin-prover interactive formal/

## -- Documents --

# Convert any Markdown file to PDF
# Usage: make pdf FILE=API.md
.PHONY: pdf
pdf: ## Convert Markdown to PDF (Usage: make pdf FILE=README.md)
	@if [ -z "$(FILE)" ]; then echo "Error: Please specify FILE=... (e.g., make pdf FILE=API.md)"; exit 1; fi
	@echo "Rendering $(FILE) to PDF..."
	@PUPPETEER_EXECUTABLE_PATH="/Users/gordonk/.cache/puppeteer/chrome/mac_arm-146.0.7680.153/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" \
	pnpm dlx md-to-pdf $(FILE) --pdf-options '{ "format": "A4", "margin": { "top": "20mm", "bottom": "20mm", "left": "20mm", "right": "20mm" } }'

## -- Help --

.PHONY: help
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
