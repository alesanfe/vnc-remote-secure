# ============================================================================
# VNC Remote Secure - Makefile
# ============================================================================
# Central entry point for all project operations.
# Run `make` or `make help` to see all available targets.
# ============================================================================

SHELL := /bin/bash

# Detect OS
ifeq ($(OS),Windows_NT)
    DETECTED_OS := windows
else
    DETECTED_OS := $(shell uname -s | tr A-Z a-z)
endif

# Default target
.DEFAULT_GOAL := help

# Load .env file if it exists (for local development)
ifneq (,$(wildcard .env))
    include .env
    export
endif

# Colors for output
BLUE   := \033[0;34m
GREEN  := \033[0;32m
YELLOW := \033[1;33m
RED    := \033[0;31m
CYAN   := \033[0;36m
NC     := \033[0m

# ============================================================================
# HELP (categorized)
# ============================================================================

help: ## Show this help message
	@echo "$(CYAN)╔══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(CYAN)║          VNC Remote Secure - Available Commands            ║$(NC)"
	@echo "$(CYAN)╚══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(BLUE)Setup:$(NC)"
	@grep -hE '^setup-[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BLUE)Run (Linux/RPi):$(NC)"
	@grep -hE '^run-[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BLUE)Run (Windows):$(NC)"
	@grep -hE '^win-[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BLUE)Testing:$(NC)"
	@grep -hE '^test[a-zA-Z_-]*:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BLUE)Quality:$(NC)"
	@grep -hE '^(lint|format|check)[a-zA-Z_-]*:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BLUE)Services:$(NC)"
	@grep -hE '^(vnc|ttyd|novnc|nginx|services|ssl|user|deps|status|stop|cleanup|duckdns)[a-zA-Z_-]*:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BLUE)Docs:$(NC)"
	@grep -hE '^docs[a-zA-Z_-]*:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BLUE)Maintenance:$(NC)"
	@grep -hE '^(clean|install|uninstall|systemd|git-)[a-zA-Z_-]*:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Tip:$(NC) Most targets accept the same env vars as .env.example"
	@echo "$(YELLOW)     Copy .env.example to .env and edit before running.$(NC)"

# ============================================================================
# SETUP
# ============================================================================

setup-env: ## Copy .env.example to .env (if not exists)
	@if [[ ! -f .env ]]; then \
		cp .env.example .env; \
		echo "$(GREEN)✓ Created .env from .env.example$(NC)"; \
		echo "$(YELLOW)  Edit .env to set your credentials before running.$(NC)"; \
	else \
		echo "$(YELLOW).env already exists, skipping$(NC)"; \
	fi

setup-deps: ## Install Python dependencies
	@echo "$(BLUE)Installing Python dependencies...$(NC)"
	@if command -v pip3 &>/dev/null; then \
		pip3 install -e ".[dev]"; \
	else \
		echo "$(RED)pip3 not found. Install Python 3 first.$(NC)"; exit 1; \
	fi
	@echo "$(GREEN)✓ Python dependencies installed$(NC)"

setup-novnc: ## Clone noVNC (if not present)
	@if [[ ! -d novnc ]]; then \
		echo "$(BLUE)Cloning noVNC...$(NC)"; \
		git clone --depth 1 --branch v1.4.0 https://github.com/novnc/noVNC.git novnc; \
		PINNED=$$(python3 -c "import json;print(json.load(open('src/vnc_remote_secure/third_party/manifests/novnc.json'))['pinned_commit_sha'])" 2>/dev/null || \
			python -c "import json;print(json.load(open('src/vnc_remote_secure/third_party/manifests/novnc.json'))['pinned_commit_sha'])" 2>/dev/null || true); \
		if [[ -n "$$PINNED" ]]; then \
			HEAD=$$(git -C novnc rev-parse HEAD); \
			if [[ "$$HEAD" != "$$PINNED" ]]; then \
				echo "$(RED)✗ noVNC HEAD $$HEAD != pinned $$PINNED - tag may have been re-pointed$(NC)"; \
				rm -rf novnc; exit 1; \
			fi; \
		fi; \
		echo "$(GREEN)✓ noVNC cloned (HEAD verified against pinned_commit_sha)$(NC)"; \
	else \
		echo "$(YELLOW)noVNC already present$(NC)"; \
	fi

setup: setup-env setup-deps setup-novnc ## Full setup (env + deps + noVNC)
	@echo "$(GREEN)✓ Setup complete$(NC)"

# ============================================================================
# RUN (Linux/Raspberry Pi)
# ============================================================================

run: ## Run on Linux/RPi (requires .env with credentials)
	@echo "$(BLUE)Starting VNC Remote Secure (Linux)...$(NC)"
	@if [[ ! -f .env ]]; then echo "$(RED)Error: .env not found. Run 'make setup-env' first.$(NC)"; exit 1; fi
	@if [[ -z "$(TTYD_PASSWD)" ]]; then echo "$(YELLOW)Warning: TTYD_PASSWD not set in .env$(NC)"; fi
	@./vnc-remote start --no-ssl

run-ssl: ## Run on Linux/RPi with SSL (requires DUCK_DOMAIN and EMAIL)
	@echo "$(BLUE)Starting VNC Remote Secure (Linux + SSL)...$(NC)"
	@if [[ -z "$(DUCK_DOMAIN)" ]]; then echo "$(RED)Error: DUCK_DOMAIN not set in .env$(NC)"; exit 1; fi
	@if [[ -z "$(EMAIL)" ]]; then echo "$(RED)Error: EMAIL not set in .env$(NC)"; exit 1; fi
	@./vnc-remote start

stop: ## Stop all services (Linux)
	@./vnc-remote stop

# ============================================================================
# RUN (Windows)
# ============================================================================

win-run: ## Run on Windows with SSL
	@echo "$(BLUE)Starting VNC Remote Secure (Windows + SSL)...$(NC)"
	@./vnc-remote start

win-run-nossl: ## Run on Windows without SSL (HTTP, for testing)
	@echo "$(BLUE)Starting VNC Remote Secure (Windows, no SSL)...$(NC)"
	@./vnc-remote start --no-ssl

win-stop: ## Stop all Windows services
	@./vnc-remote stop

win-verify: ## Verify all Windows services are responding
	@python -m vnc_remote_secure.cli doctor 2>/dev/null || python3 -m vnc_remote_secure.cli doctor

# ============================================================================
# TESTING
# ============================================================================

test: test-all ## Alias for test-all

test-all: ## Run all tests (full pyramid)
	@echo "$(BLUE)Running all tests (pyramid)...$(NC)"
	@cd tests && bash run_tests.sh

test-list: ## List available tests
	@cd tests && bash run_tests.sh -l

test-static: ## Level 0: static analysis (lint, syntax, CRLF)
	@echo "$(BLUE)Running static tests (Level 0)...$(NC)"
	@cd tests && bash run_tests.sh static/

test-unit: ## Level 1: unit tests (isolated functions)
	@echo "$(BLUE)Running unit tests (Level 1)...$(NC)"
	@cd tests && bash run_tests.sh unit/

test-integration: ## Level 3: integration tests (multi-module)
	@echo "$(BLUE)Running integration tests (Level 3)...$(NC)"
	@cd tests && bash run_tests.sh integration/

test-e2e: ## Level 5: end-to-end tests (entry point)
	@echo "$(BLUE)Running E2E tests (Level 5)...$(NC)"
	@cd tests && bash run_tests.sh e2e/

test-security: ## Level 7: security tests (password, sanitization)
	@echo "$(BLUE)Running security tests (Level 7)...$(NC)"
	@cd tests && bash run_tests.sh security/

test-fast: test-static test-unit test-integration test-security ## Run fast tests (skip e2e)
	@echo "$(GREEN)✓ Fast tests complete$(NC)"

# ============================================================================
# QUALITY / LINTING
# ============================================================================

lint: ## Run shellcheck on all shell scripts (non-fatal)
	@echo "$(BLUE)Running shellcheck...$(NC)"
	@shellcheck -x src/rpi-vnc-remote.sh || true
	@shellcheck -x scripts/development/*.sh scripts/maintenance/*.sh scripts/release/*.sh scripts/utilities/*.sh || true
	@shellcheck -x launch.sh vnc-remote || true
	@shellcheck -x tests/run_tests.sh || true
	@find tests/static tests/unit tests/integration tests/e2e tests/security -name 'test_*.sh' -type f -print0 2>/dev/null | xargs -0 -r shellcheck -x || true
	@echo "$(GREEN)✓ Linting complete$(NC)"

lint-strict: ## Run shellcheck and fail on any warning
	@echo "$(BLUE)Running shellcheck (strict)...$(NC)"
	@shellcheck -x src/rpi-vnc-remote.sh
	@shellcheck -x scripts/development/*.sh scripts/maintenance/*.sh scripts/release/*.sh scripts/utilities/*.sh
	@shellcheck -x launch.sh vnc-remote
	@shellcheck -x tests/run_tests.sh
	@find tests/static tests/unit tests/integration tests/e2e tests/security -name 'test_*.sh' -type f -print0 2>/dev/null | xargs -0 -r shellcheck -x
	@echo "$(GREEN)✓ Linting complete (no warnings)$(NC)"

lint-python: ## Run Python linters (ruff, black if available)
	@echo "$(BLUE)Running Python linters...$(NC)"
	@if command -v ruff &>/dev/null; then ruff check src/vnc_remote_secure/ tools/ scripts/utilities/ || true; \
	else echo "$(YELLOW)ruff not installed, skipping$(NC)"; fi
	@if command -v black &>/dev/null; then black --check src/vnc_remote_secure/ tools/ scripts/utilities/ || true; \
	else echo "$(YELLOW)black not installed, skipping$(NC)"; fi
	@echo "$(GREEN)✓ Python linting complete$(NC)"

format: ## Format Python and shell code (delegates to scripts/development/format.sh)
	@echo "$(BLUE)Formatting code...$(NC)"
	@bash scripts/development/format.sh
	@echo "$(GREEN)✓ Formatting complete$(NC)"

check: lint lint-python test-fast ## Run all quality checks (lint + fast tests)
	@echo "$(GREEN)✓ All quality checks passed$(NC)"

# ============================================================================
# DOCKER
# ============================================================================
# Container packaging lives in packaging/docker/ (Dockerfile, compose.yml,
# compose.integration.yml). Build and run with:
#   docker compose -f packaging/docker/compose.yml --env-file .env up -d
# Integration tests run under the `test` Compose profile:
#   docker compose -f packaging/docker/compose.yml \
#       -f packaging/docker/compose.integration.yml --profile test \
#       run --rm test-runner
# The docker-* / demo make targets are intentionally omitted; use
# `docker compose` directly.

# ============================================================================
# SERVICES (Linux/RPi) — canonical via vnc-remote CLI
# ============================================================================

# Per-service legacy targets removed: use `vnc-remote start` / `vnc-remote stop`
# which delegate to the Python service manager. The Bash stack remains
# available via `src/rpi-vnc-remote.sh` for internal use.

cleanup: ## Run cleanup (remove services and temp user)
	@echo "$(BLUE)Running cleanup...$(NC)"
	@./vnc-remote stop

# ============================================================================
# SSL / USER / DEPS (Linux/RPi)
# ============================================================================

ssl-setup: ## Setup SSL certificates (requires DUCK_DOMAIN and EMAIL)
	@if [[ -z "$(DUCK_DOMAIN)" ]]; then echo "$(RED)Error: DUCK_DOMAIN not set$(NC)"; exit 1; fi
	@if [[ -z "$(EMAIL)" ]]; then echo "$(RED)Error: EMAIL not set$(NC)"; exit 1; fi
	@echo "$(BLUE)Setting up SSL certificates...$(NC)"
	@./vnc-remote install

ssl-renew: ## Renew SSL certificates via certbot (requires root)
	@echo "$(BLUE)Renewing SSL certificates...$(NC)"
	@sudo certbot renew --deploy-hook "systemctl reload nginx 2>/dev/null || true" || \
		{ echo "$(RED)certbot renew failed — is certbot configured?$(NC)"; exit 1; }

ssl-check: ## Check SSL certificate expiry
	@echo "$(BLUE)Checking SSL certificate expiry...$(NC)"
	@./vnc-remote doctor

# ============================================================================
# DUCK DNS
# ============================================================================

duckdns-update: ## Update Duck DNS IP (one-shot, Python — canonical)
	@echo "$(BLUE)Updating Duck DNS...$(NC)"
	@python3 scripts/utilities/duckdns_update.py

duckdns-daemon: ## Start Duck DNS update daemon (runs until Ctrl+C)
	@echo "$(BLUE)Starting Duck DNS daemon...$(NC)"
	@python3 scripts/utilities/duckdns_update.py --daemon

duckdns-check: ## Check Duck DNS resolution
	@echo "$(BLUE)Checking Duck DNS...$(NC)"
	@python3 scripts/utilities/duckdns_update.py --check

duckdns-update-sh: ## Update Duck DNS IP via Bash (legacy fallback)
	@bash scripts/utilities/duckdns_update.sh

user-create: ## DEPRECATED alias — temp user is created by install
	@echo "$(YELLOW)DEPRECATED: the runtime user is created by 'install'$(NC)"
	@./vnc-remote install

user-remove: ## DEPRECATED alias — runtime user removal is part of uninstall
	@echo "$(YELLOW)DEPRECATED: the runtime user is removed by 'uninstall'$(NC)"
	@./vnc-remote uninstall

deps-install: ## DEPRECATED alias — system deps are installed by install
	@echo "$(YELLOW)DEPRECATED: system dependencies are installed by 'install'$(NC)"
	@./vnc-remote install

ttyd-install: ## Download optional ttyd binary (canonical terminal is the built-in Python Tornado server)
	@echo "$(BLUE)Downloading optional ttyd binary...$(NC)"
	@python tools/download_dependencies.py || python3 tools/download_dependencies.py

nginx-install: ## Install nginx (delegates to vnc-remote install)
	@echo "$(BLUE)Installing nginx...$(NC)"
	@./vnc-remote install

nginx-configure: ## Configure nginx (delegates to vnc-remote install)
	@echo "$(BLUE)Configuring nginx...$(NC)"
	@./vnc-remote install

nginx-start: ## Start all services incl. nginx (delegates to vnc-remote start)
	@echo "$(BLUE)Starting nginx...$(NC)"
	@./vnc-remote start

nginx-stop: ## Stop all services incl. nginx (delegates to vnc-remote stop)
	@echo "$(BLUE)Stopping nginx...$(NC)"
	@./vnc-remote stop

nginx-restart: ## Restart all services (delegates to vnc-remote restart)
	@echo "$(BLUE)Restarting nginx...$(NC)"
	@./vnc-remote restart

nginx-reload: ## Reload nginx config (systemctl reload nginx)
	@echo "$(BLUE)Reloading nginx...$(NC)"
	@sudo systemctl reload nginx

nginx-status: ## Show service status (delegates to vnc-remote status)
	@echo "$(BLUE)Checking nginx status...$(NC)"
	@./vnc-remote status

# ============================================================================
# STATUS
# ============================================================================

status: ## Show status of services via the canonical CLI
	@./vnc-remote status

# ============================================================================
# DOCS
# ============================================================================

docs: ## Show documentation index
	@echo "$(BLUE)Documentation available in docs/ directory$(NC)"
	@echo ""
	@echo "Architecture:    docs/architecture/"
	@echo "Installation:    docs/installation/"
	@echo "User Guide:      docs/user-guide/"
	@echo "Developer:       docs/developer/"
	@echo "ADRs:            docs/adr/"

# docs-serve / docs-build targets removed: mkdocs.yml is not present in the
# repo and mkdocs is not a project dependency. Restore these targets when
# mkdocs configuration is added.

# ============================================================================
# INSTALL / UNINSTALL (system-wide, Linux)
# ============================================================================

install: ## Install system-wide via the canonical packaging installer (Linux)
	@echo "$(YELLOW)Running installer via vnc-remote...$(NC)"
	@./vnc-remote install
	@echo "$(GREEN)✓ Installation complete$(NC)"
	@echo "$(BLUE)  Use: vnc-remote install / start / stop / status / doctor / uninstall$(NC)"

uninstall: ## Uninstall: stop services, remove systemd units, nginx, certs, temp user
	@echo "$(YELLOW)Uninstalling VNC Remote Secure...$(NC)"
	@./vnc-remote uninstall

install-systemd: ## Install systemd service units (requires sudo, Linux only)
	@echo "$(BLUE)Installing systemd service units...$(NC)"
	@./vnc-remote install

systemd-start: ## Start the unified vnc-remote service
	@sudo systemctl start vnc-remote

systemd-stop: ## Stop the unified vnc-remote service
	@sudo systemctl stop vnc-remote

systemd-status: ## Show status of the vnc-remote service
	@sudo systemctl status vnc-remote --no-pager

systemd-enable: ## Enable the service to start on boot
	@sudo systemctl enable vnc-remote

systemd-disable: ## Disable the service from starting on boot
	@sudo systemctl disable vnc-remote

# ============================================================================
# MAINTENANCE / CLEANUP
# ============================================================================

clean: ## Clean temporary files
	@echo "$(YELLOW)Cleaning temporary files...$(NC)"
	@rm -f data/tmp/.terminal-cred.* data/tmp/.terminal-launch.* 2>/dev/null || true
	@rm -f *.log 2>/dev/null || true
	@rm -f landing_*.log 2>/dev/null || true
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Clean complete$(NC)"

clean-all: clean clean-docs ## Clean everything (temp + docs)
	@echo "$(YELLOW)Full clean complete$(NC)"

clean-docs: ## Clean generated documentation
	@echo "$(YELLOW)Cleaning documentation...$(NC)"
	@rm -rf site/
	@echo "$(GREEN)✓ Documentation clean complete$(NC)"

# ============================================================================
# GIT HELPERS
# ============================================================================

git-status: ## Show git status
	@git status

git-log: ## Show recent git log
	@git log --oneline -10

git-push: ## Push to remote (current branch)
	@git push origin $$(git rev-parse --abbrev-ref HEAD)

git-pull: ## Pull from remote (current branch)
	@git pull origin $$(git rev-parse --abbrev-ref HEAD)

# ============================================================================
# DEMO
# ============================================================================

# Demo target intentionally omitted: a containerized deployment is available
# via packaging/docker/compose.yml (see the DOCKER section above).

# ============================================================================
# PHONY
# ============================================================================

.PHONY: help setup setup-env setup-deps setup-novnc \
        run run-ssl stop \
        win-run win-run-nossl win-stop win-verify \
        test test-all test-list test-static test-unit test-integration test-e2e test-security test-fast \
        lint lint-strict lint-python format check \
        cleanup \
        ssl-setup ssl-renew ssl-check user-create user-remove deps-install ttyd-install \
        duckdns-update duckdns-daemon duckdns-check duckdns-update-sh \
        nginx-install nginx-configure nginx-start nginx-stop nginx-restart nginx-reload nginx-status \
        status docs \
        install uninstall install-systemd systemd-start systemd-stop systemd-status systemd-enable systemd-disable \
        clean clean-all clean-docs \
        git-status git-log git-push git-pull
