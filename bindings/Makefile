# OpenHTTPA Bindings Examples Makefile

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
	./python/examples/run.sh

node:
	./nodejs/examples/run.sh

go:
	./go/examples/run.sh

c:
	./c/examples/run.sh

wasm:
	@./wasm/examples/run.sh

prebuild:
	@echo "--- Pre-building Workspace (Release) ---"
	cargo build --release --workspace

all: prebuild
	@echo "--- Running all binding examples in parallel ---"
	$(MAKE) -j4 python node go c
	@echo "All examples completed successfully."

clean:
	rm -rf python/examples/venv
	rm -rf nodejs/node_modules nodejs/build nodejs/index.js nodejs/index.d.ts nodejs/*.node
	rm -rf c/examples/example
	rm -rf wasm/examples/pkg
	cargo clean
