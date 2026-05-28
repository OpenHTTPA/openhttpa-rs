export CI ?= true

.PHONY: up down logs reset build clean open wasm dev e2e status help stable-up stable-down stable-status

COMPOSE      = docker compose

# Host ports are randomized by default in docker-compose.yml (using :0)
# to allow parallel stacks on the same host (e.g. for E2E tests).
# Use 'make stable-up' for a persistent instance on port 3001.
# We can still inspect them via 'make status'.

WASM_OUTDIR  = frontend/wasm
WASM_PKGDIR  = ../../bindings/wasm
# Playwright config lives at the workspace root (two directories up)
WORKSPACE    = ../..

## up: Build images (if needed) and start all services
up: wasm
	$(COMPOSE) up --build --wait

## stable-up: Start a stable demo instance on port 3001 (isolated from E2E)
stable-up: wasm
	COMPOSE_PROJECT_NAME=openhttpa-stable FRONTEND_PORT=3001 BACKEND_PORT=8082 $(COMPOSE) up -d --build --wait
	@echo "Stable demo is up at http://127.0.0.1:3001"

## stable-down: Stop the stable demo instance
stable-down:
	COMPOSE_PROJECT_NAME=openhttpa-stable $(COMPOSE) down -v --remove-orphans

## stable-restart: Restart the stable demo instance (clean refresh)
stable-restart: stable-down stable-up

## stable-status: Show health of the stable demo instance
stable-status:
	@echo "=== Stable Container Status ==="
	@COMPOSE_PROJECT_NAME=openhttpa-stable $(COMPOSE) ps
	@echo ""

## down: Stop and remove all containers, networks, and volumes
down:
	@echo "Aggressively cleaning up all containers for project: $(COMPOSE_PROJECT_NAME)..."
	@# Forcefully remove any containers (including those from 'run') to clear network endpoints
	@CONTAINERS=$$(docker ps -a --filter name=^$(COMPOSE_PROJECT_NAME)- -q); \
	if [ -n "$$CONTAINERS" ]; then \
		echo "Removing orphaned containers: $$CONTAINERS"; \
		docker rm -f $$CONTAINERS || true; \
	fi
	-$(COMPOSE) down -v --remove-orphans --timeout 10
	@# Handle race condition where network removal fails due to active endpoints
	@NETWORK_ID=$$(docker network ls --filter name=^$(COMPOSE_PROJECT_NAME)_default$$ -q); \
	if [ -n "$$NETWORK_ID" ]; then \
		echo "Network $$NETWORK_ID still active, waiting 2s for endpoints to clear..."; \
		sleep 2; \
		$(COMPOSE) down -v --remove-orphans --timeout 10 || true; \
	fi

## logs: Stream logs from all services
logs:
	$(COMPOSE) logs -f

## reset: Stop containers, remove volumes, rebuild, and start fresh
reset: wasm
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) up --build -d

## build: Build (or rebuild) images without starting
build:
	$(COMPOSE) build

## clean: Stop containers and remove images and volumes
clean:
	$(COMPOSE) down -v --rmi local --remove-orphans

## wasm: Build the browser Wasm bindings with wasm-pack (requires wasm-pack)
##       Output is written to frontend/wasm/ and served by the Nginx container.
##       Run from the workspace root: make -C demo/multiparty-webapp wasm
wasm:
	@command -v wasm-pack >/dev/null 2>&1 || { \
		echo "wasm-pack not found. Install with:  cargo install wasm-pack"; \
		exit 1; \
	}
	@echo "Building Wasm bindings..."
	@mkdir -p $(WASM_OUTDIR)
	cd $(WORKSPACE) && wasm-pack build bindings/wasm \
		--target web \
		--out-dir "$(CURDIR)/$(WASM_OUTDIR)" \
		--release
	@echo "Wasm build complete → $(WASM_OUTDIR)/"
	@echo "Fixing permissions for generated assets (Wasm/JS)..."
	@chmod -R a+rX $(CURDIR)/$(WASM_OUTDIR) || true

## dev: Build Wasm bindings then start all services
dev: wasm up

## status: Show running container health and port bindings
status:
	@echo "=== Container status ==="
	@$(COMPOSE) ps
	@echo ""

## e2e: Build wasm, start services, run tests, and shut down.
e2e: wasm
	@trap '$(MAKE) down' EXIT; \
	$(COMPOSE) up --build --wait; \
	$(MAKE) e2e-run

## e2e-run: Run the containerized Playwright test suite without managing service state.
##          This assumes the stack is already running (e.g. via 'make up').
e2e-run:
	@echo "Running containerized E2E tests for project: $(COMPOSE_PROJECT_NAME)"
	$(COMPOSE) run --rm --build e2e-runner
	@$(MAKE) fix-permissions
	@echo "Tests complete."

## fix-permissions: Fix ownership of artifacts created by Docker (root)
fix-permissions:
	@echo "Fixing artifact permissions for host user..."
	@$(COMPOSE) run --rm --entrypoint "" e2e-runner chown -R $(shell id -u):$(shell id -g) /src/playwright-report /src/test-results 2>/dev/null || true

## help: Show this help
help:
	@echo "OpenHTTPA Multiparty Demo — available targets:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  make /'
