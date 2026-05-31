# OpenHTTPA Bindings Examples Makefile

export CI ?= true

# Maximum wall-clock seconds allowed per individual language example before the
# run is aborted.  Override on the command line for local debugging:
#   EXAMPLE_TIMEOUT_SECS=300 make python
EXAMPLE_TIMEOUT_SECS ?= 120

.PHONY: all python node go c wasm clean help

help:
	@echo "OpenHTTPA Bindings Examples"
	@echo "-------------------------"
	@echo "Ensure the backend is running: 'make up' in demo/multiparty-webapp"
	@echo ""
	@echo "Usage:"
	@echo "  make python  - Run Python example (venv + maturin)"
	@echo "  make node    - Run Node.js example (pnpm install + build)"
	@echo "  make go      - Run Go example (cargo build + go run)"
	@echo "  make c       - Run C example (cargo build + gcc)"
	@echo "  make wasm    - Build and serve Wasm example (wasm-pack + http.server)"
	@echo "  make all     - Attempt to run all (except wasm which is long-running)"
	@echo "  make clean   - Remove build artifacts and venvs"

python:
	timeout $(EXAMPLE_TIMEOUT_SECS) ./python/examples/run.sh || { \
		[ $$? -eq 124 ] && echo "[ERROR] python example timed out after $(EXAMPLE_TIMEOUT_SECS)s"; \
		exit 1; \
	}

node:
	timeout $(EXAMPLE_TIMEOUT_SECS) ./nodejs/examples/run.sh || { \
		[ $$? -eq 124 ] && echo "[ERROR] node example timed out after $(EXAMPLE_TIMEOUT_SECS)s"; \
		exit 1; \
	}

go:
	timeout $(EXAMPLE_TIMEOUT_SECS) ./go/examples/run.sh || { \
		[ $$? -eq 124 ] && echo "[ERROR] go example timed out after $(EXAMPLE_TIMEOUT_SECS)s"; \
		exit 1; \
	}

c:
	timeout $(EXAMPLE_TIMEOUT_SECS) ./c/examples/run.sh || { \
		[ $$? -eq 124 ] && echo "[ERROR] c example timed out after $(EXAMPLE_TIMEOUT_SECS)s"; \
		exit 1; \
	}

wasm:
	@./wasm/examples/run.sh

prebuild:
	@echo "--- Pre-building Workspace (Release) ---"
	+cargo build --release --workspace

# run-prebuilt: Execute all binding examples WITHOUT rebuilding.
# This is the target used inside the openhttpa-examples Docker container,
# where cargo build has already been completed at image-build time (Dockerfile
# line: RUN cargo build --release --workspace --features mock,nvidia_gpu).
# Running 'prebuild' again inside the container wastes 2+ hours every invocation.
run-prebuilt:
	@echo "--- Running all binding examples in parallel (using pre-built artifacts) ---"
	$(MAKE) -j4 SKIP_BUILD=1 python node go c
	@echo "All examples completed successfully."

# all: Build then run.  Used for standalone (non-Docker) invocations.
all: prebuild run-prebuilt

clean:
	rm -rf python/examples/venv
	rm -rf nodejs/node_modules nodejs/build nodejs/index.js nodejs/index.d.ts nodejs/*.node
	rm -rf c/examples/example
	rm -rf wasm/examples/pkg
	+cargo clean
