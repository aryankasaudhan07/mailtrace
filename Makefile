# Mailtrace — common tasks. Run `make` or `make help` to list them.
SHELL := /bin/bash
.ONESHELL:
.DEFAULT_GOAL := help

VENV     := ./venv
PY       := $(VENV)/bin/python
UVICORN  := $(VENV)/bin/uvicorn
NODE_BIN := $(HOME)/.local/node/bin

# ---------------------------------------------------------------------------
##@ Run

.PHONY: start
start: ## Launch the stack — Docker if available (UI :8080), else local (UI :5173)
	@if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		echo "▶ Docker detected — building containerized stack (UI :8080, API :8000)"; \
		docker compose up --build; \
	else \
		echo "▶ Docker not available — starting locally instead (API :8000, UI :5173)"; \
		$(MAKE) --no-print-directory dev; \
	fi

.PHONY: stop
stop: ## Stop and remove the Docker stack
	docker compose down

.PHONY: logs
logs: ## Tail logs from the running Docker stack
	docker compose logs -f

.PHONY: dev
dev: ## Run API + UI locally without Docker (API :8000, UI :5173)
	@echo "Starting API on :8000 and UI on :5173  (Ctrl-C to stop both)"
	@$(UVICORN) app.main:app --port 8000 & API_PID=$$!; \
	trap 'kill $$API_PID 2>/dev/null' EXIT INT TERM; \
	cd frontend && PATH="$(NODE_BIN):$$PATH" npm run dev

.PHONY: api
api: ## Run only the backend API (:8000)
	$(UVICORN) app.main:app --reload --port 8000

.PHONY: web
web: ## Run only the frontend dev server (:5173)
	cd frontend && PATH="$(NODE_BIN):$$PATH" npm run dev

# ---------------------------------------------------------------------------
##@ Setup & quality

.PHONY: setup
setup: ## Install backend (venv) and frontend (npm) dependencies
	$(PY) -m pip install -r requirements.txt
	cd frontend && PATH="$(NODE_BIN):$$PATH" npm ci

.PHONY: test
test: ## Run backend tests and lint
	$(PY) -m pytest -q
	$(PY) -m ruff check app tests

.PHONY: build
build: ## Production build of the frontend
	cd frontend && PATH="$(NODE_BIN):$$PATH" npm run build

.PHONY: clean
clean: ## Remove build artefacts and caches
	rm -rf frontend/dist .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

# ---------------------------------------------------------------------------
##@ Help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS=":.*##"; printf "\nMailtrace — make targets\n\n"} \
		/^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2} \
		/^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0,5)}' $(MAKEFILE_LIST)
	@echo ""
