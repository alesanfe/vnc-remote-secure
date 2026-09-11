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
	@echo "$(BLUE)Docker:$(NC)"
	@grep -hE '^docker-[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
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
		git clone --depth 1 https://github.com/novnc/noVNC.git novnc; \
		echo "$(GREEN)✓ noVNC cloned$(NC)"; \
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
	@bash src/rpi-vnc-remote.sh

run-ssl: ## Run on Linux/RPi with SSL (requires DUCK_DOMAIN and EMAIL)
	@echo "$(BLUE)Starting VNC Remote Secure (Linux + SSL)...$(NC)"
	@if [[ -z "$(DUCK_DOMAIN)" ]]; then echo "$(RED)Error: DUCK_DOMAIN not set in .env$(NC)"; exit 1; fi
	@if [[ -z "$(EMAIL)" ]]; then echo "$(RED)Error: EMAIL not set in .env$(NC)"; exit 1; fi
	@bash src/rpi-vnc-remote.sh

stop: ## Stop all services (Linux)
	@bash src/rpi-vnc-remote.sh stop

# ============================================================================
# RUN (Windows)
# ============================================================================

win-run: ## Run on Windows with SSL
	@echo "$(BLUE)Starting VNC Remote Secure (Windows + SSL)...$(NC)"
	@./vnc-remote start

win-run-nossl: ## Run on Windows without SSL (HTTP, for testing)
	@echo "$(BLUE)Starting VNC Remote Secure (Windows, no SSL)...$(NC)"
	@./vnc-remote start --profile local

win-stop: ## Stop all Windows services
	@./vnc-remote stop --force

win-verify: ## Verify all Windows services are responding
	@python3 -m vnc_remote_secure.cli doctor

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
	@shellcheck -x src/lib/core/*.sh src/lib/security/*.sh src/lib/web/*.sh || true
	@shellcheck -x src/lib/monitoring/*.sh src/lib/communication/*.sh src/lib/features/*.sh || true
	@shellcheck -x src/lib/platform/*.sh || true
	@shellcheck -x scripts/development/*.sh scripts/maintenance/*.sh scripts/release/*.sh || true
	@shellcheck -x launch.sh vnc-remote || true
	@shellcheck -x tests/run_tests.sh || true
	@find tests/unit tests/integration tests/e2e tests/security -name 'test_*.sh' -type f -print0 2>/dev/null | xargs -0 -r shellcheck -x || true
	@echo "$(GREEN)✓ Linting complete$(NC)"

lint-strict: ## Run shellcheck and fail on any warning
	@echo "$(BLUE)Running shellcheck (strict)...$(NC)"
	@shellcheck -x src/rpi-vnc-remote.sh
	@shellcheck -x src/lib/core/*.sh src/lib/security/*.sh src/lib/web/*.sh
	@shellcheck -x src/lib/monitoring/*.sh src/lib/communication/*.sh src/lib/features/*.sh
	@shellcheck -x src/lib/platform/*.sh
	@shellcheck -x scripts/development/*.sh scripts/maintenance/*.sh scripts/release/*.sh
	@shellcheck -x launch.sh vnc-remote
	@shellcheck -x tests/run_tests.sh
	@find tests/unit tests/integration tests/e2e tests/security -name 'test_*.sh' -type f -print0 2>/dev/null | xargs -0 -r shellcheck -x
	@echo "$(GREEN)✓ Linting complete (no warnings)$(NC)"

lint-python: ## Run Python linters (ruff, black if available)
	@echo "$(BLUE)Running Python linters...$(NC)"
	@if command -v ruff &>/dev/null; then ruff check src/vnc_remote_secure/ tools/ scripts/utilities/ || true; \
	else echo "$(YELLOW)ruff not installed, skipping$(NC)"; fi
	@if command -v black &>/dev/null; then black --check src/vnc_remote_secure/ tools/ scripts/utilities/ || true; \
	else echo "$(YELLOW)black not installed, skipping$(NC)"; fi
	@echo "$(GREEN)✓ Python linting complete$(NC)"

format: ## Format Python code with black (if available)
	@echo "$(BLUE)Formatting Python code...$(NC)"
	@if command -v black &>/dev/null; then black src/vnc_remote_secure/ tools/ scripts/utilities/; \
	else echo "$(YELLOW)black not installed. Install with: pip install black$(NC)"; fi
	@echo "$(GREEN)✓ Formatting complete$(NC)"

check: lint lint-python test-fast ## Run all quality checks (lint + fast tests)
	@echo "$(GREEN)✓ All quality checks passed$(NC)"

# ============================================================================
# DOCKER
# ============================================================================

docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	@cd packaging/docker && docker build -t vnc-remote-secure-test -f Dockerfile ../..

docker-test: docker-build ## Run tests in Docker
	@echo "$(BLUE)Running tests in Docker...$(NC)"
	@cd packaging/docker && docker compose run test

docker-compose-up: ## Start Docker Compose integration services
	@echo "$(BLUE)Starting Docker Compose services...$(NC)"
	@docker compose -f packaging/docker/compose.integration.yml up -d

docker-compose-down: ## Stop Docker Compose integration services
	@echo "$(BLUE)Stopping Docker Compose services...$(NC)"
	@docker compose -f packaging/docker/compose.integration.yml down

docker-clean: ## Remove Docker images and containers
	@echo "$(YELLOW)Cleaning Docker resources...$(NC)"
	@docker rmi vnc-remote-secure-test 2>/dev/null || true
	@cd packaging/docker && docker compose down -v 2>/dev/null || true
	@docker compose -f packaging/docker/compose.integration.yml down -v 2>/dev/null || true
	@echo "$(GREEN)✓ Docker clean complete$(NC)"

# ============================================================================
# SERVICES (Linux/RPi)
# ============================================================================

vnc-start: ## Start VNC server
	@echo "$(BLUE)Starting VNC server...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/logging.sh && source lib/core/utils.sh && source lib/core/services.sh && start_vnc_server

vnc-stop: ## Stop VNC server
	@echo "$(BLUE)Stopping VNC server...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/core/cleanup_utils.sh && kill_vnc_server

ttyd-start: ## Start ttyd
	@echo "$(BLUE)Starting ttyd...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/logging.sh && source lib/core/utils.sh && source lib/core/services.sh && start_ttyd

ttyd-stop: ## Stop ttyd
	@echo "$(BLUE)Stopping ttyd...$(NC)"
	@pkill -f ttyd || echo "$(YELLOW)No ttyd process found$(NC)"

novnc-start: ## Start noVNC
	@echo "$(BLUE)Starting noVNC...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/logging.sh && source lib/core/utils.sh && source lib/core/services.sh && start_novnc

services-start: ## Start all services (VNC, ttyd, noVNC)
	@echo "$(BLUE)Starting all services...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/logging.sh && source lib/core/utils.sh && source lib/core/services.sh && start_vnc_server && start_ttyd && start_novnc

services-stop: ## Stop all services
	@echo "$(BLUE)Stopping all services...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/core/cleanup_utils.sh && cleanup_processes

cleanup: ## Run cleanup (remove services and temp user)
	@echo "$(BLUE)Running cleanup...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/core/cleanup_utils.sh && cleanup_processes

# ============================================================================
# SSL / USER / DEPS (Linux/RPi)
# ============================================================================

ssl-setup: ## Setup SSL certificates (requires DUCK_DOMAIN and EMAIL)
	@if [[ -z "$(DUCK_DOMAIN)" ]]; then echo "$(RED)Error: DUCK_DOMAIN not set$(NC)"; exit 1; fi
	@if [[ -z "$(EMAIL)" ]]; then echo "$(RED)Error: EMAIL not set$(NC)"; exit 1; fi
	@echo "$(BLUE)Setting up SSL certificates...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/security/ssl.sh && setup_ssl

ssl-renew: ## Renew SSL certificates
	@echo "$(BLUE)Renewing SSL certificates...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/security/ssl.sh && setup_ssl

ssl-check: ## Check SSL certificate expiry
	@echo "$(BLUE)Checking SSL certificate expiry...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/security/ssl.sh && check_ssl_expiry

# ============================================================================
# DUCK DNS
# ============================================================================

duckdns-update: ## Update Duck DNS IP (one-shot)
	@echo "$(BLUE)Updating Duck DNS...$(NC)"
	@bash scripts/utilities/duckdns_update.sh

duckdns-daemon: ## Start Duck DNS update daemon (runs until Ctrl+C)
	@echo "$(BLUE)Starting Duck DNS daemon...$(NC)"
	@bash scripts/utilities/duckdns_update.sh --daemon

duckdns-check: ## Check Duck DNS resolution
	@echo "$(BLUE)Checking Duck DNS...$(NC)"
	@bash scripts/utilities/duckdns_update.sh --check

duckdns-update-py: ## Update Duck DNS IP via Python (cross-platform fallback)
	@python3 scripts/utilities/duckdns_update.py

user-create: ## Create temporary user
	@echo "$(BLUE)Creating temporary user...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/security/user.sh && create_temp_user

user-remove: ## Remove temporary user
	@echo "$(BLUE)Removing temporary user...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/core/cleanup_utils.sh && remove_temp_user

deps-install: ## Install system dependencies (Linux)
	@echo "$(BLUE)Installing system dependencies...$(NC)"
	@cd src && source lib/core/utils.sh && install_dependencies

ttyd-install: ## Install ttyd binary
	@echo "$(BLUE)Installing ttyd...$(NC)"
	@cd src && source lib/core/utils.sh && install_ttyd

nginx-install: ## Install nginx
	@echo "$(BLUE)Installing nginx...$(NC)"
	@cd src && source lib/core/utils.sh && source lib/web/nginx.sh && install_nginx

nginx-configure: ## Configure nginx reverse proxy
	@echo "$(BLUE)Configuring nginx...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/web/nginx.sh && configure_nginx

nginx-start: ## Start nginx
	@echo "$(BLUE)Starting nginx...$(NC)"
	@cd src && source lib/core/utils.sh && source lib/web/nginx.sh && start_nginx

nginx-stop: ## Stop nginx
	@echo "$(BLUE)Stopping nginx...$(NC)"
	@cd src && source lib/core/utils.sh && source lib/web/nginx.sh && stop_nginx

nginx-restart: ## Restart nginx
	@echo "$(BLUE)Restarting nginx...$(NC)"
	@cd src && source lib/core/utils.sh && source lib/web/nginx.sh && restart_nginx

nginx-reload: ## Reload nginx configuration
	@echo "$(BLUE)Reloading nginx...$(NC)"
	@cd src && source lib/core/utils.sh && source lib/web/nginx.sh && reload_nginx

nginx-status: ## Show nginx status
	@echo "$(BLUE)Checking nginx status...$(NC)"
	@cd src && source lib/core/utils.sh && source lib/web/nginx.sh && nginx_status

# ============================================================================
# STATUS
# ============================================================================

status: ## Show status of services
	@echo "$(BLUE)Checking service status...$(NC)"
	@echo "VNC Server:"
	@pgrep -f Xtigervnc >/dev/null 2>&1 && echo "  $(GREEN)Running$(NC)" || echo "  $(RED)Stopped$(NC)"
	@echo "ttyd:"
	@pgrep -f ttyd >/dev/null 2>&1 && echo "  $(GREEN)Running$(NC)" || echo "  $(RED)Stopped$(NC)"
	@echo "noVNC:"
	@pgrep -f novnc_proxy >/dev/null 2>&1 && echo "  $(GREEN)Running$(NC)" || echo "  $(RED)Stopped$(NC)"

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

docs-serve: ## Serve documentation locally (requires mkdocs)
	@echo "$(BLUE)Serving documentation locally...$(NC)"
	@if command -v mkdocs &>/dev/null; then mkdocs serve; \
	else echo "$(YELLOW)mkdocs not installed. Install with: pip install mkdocs$(NC)"; fi

docs-build: ## Build documentation (requires mkdocs)
	@echo "$(BLUE)Building documentation...$(NC)"
	@if command -v mkdocs &>/dev/null; then mkdocs build; \
	else echo "$(YELLOW)mkdocs not installed. Install with: pip install mkdocs$(NC)"; fi

# ============================================================================
# INSTALL / UNINSTALL (system-wide, Linux)
# ============================================================================

install: ## Install vnc-remote CLI to /usr/local/bin (Linux, system-wide)
	@echo "$(YELLOW)Installing vnc-remote CLI to /usr/local...$(NC)"
	@sudo mkdir -p /usr/local/share/rpi-vnc-remote
	@sudo cp -r src/ /usr/local/share/rpi-vnc-remote/src/
	@sudo cp -r scripts/ /usr/local/share/rpi-vnc-remote/scripts/ 2>/dev/null || true
	@sudo cp vnc-remote /usr/local/bin/vnc-remote
	@sudo chmod +x /usr/local/bin/vnc-remote
	@sudo sed -i 's|PROJECT_DIR=.*|PROJECT_DIR="/usr/local/share/rpi-vnc-remote"|' /usr/local/bin/vnc-remote
	@echo "$(GREEN)✓ Installation complete$(NC)"
	@echo "$(BLUE)  Use: vnc-remote install / start / stop / status / doctor / uninstall$(NC)"

uninstall: ## Uninstall: stop services, remove systemd units, nginx, certs, temp user
	@echo "$(YELLOW)Uninstalling VNC Remote Secure...$(NC)"
	@sudo bash scripts/maintenance/uninstall.sh

install-systemd: ## Install systemd service units (requires sudo, Linux only)
	@echo "$(BLUE)Installing systemd service units...$(NC)"
	@sudo bash scripts/maintenance/install_systemd.sh

systemd-start: ## Start all systemd services
	@sudo systemctl start vnc-remote-vnc vnc-remote-novnc vnc-remote-ttyd vnc-remote-health

systemd-stop: ## Stop all systemd services
	@sudo systemctl stop vnc-remote-vnc vnc-remote-novnc vnc-remote-ttyd vnc-remote-health

systemd-status: ## Show status of all systemd services
	@sudo systemctl status vnc-remote-vnc vnc-remote-novnc vnc-remote-ttyd vnc-remote-health --no-pager

systemd-enable: ## Enable services to start on boot
	@sudo systemctl enable vnc-remote-vnc vnc-remote-novnc vnc-remote-ttyd vnc-remote-health

systemd-disable: ## Disable services from starting on boot
	@sudo systemctl disable vnc-remote-vnc vnc-remote-novnc vnc-remote-ttyd vnc-remote-health

# ============================================================================
# MAINTENANCE / CLEANUP
# ============================================================================

clean: ## Clean temporary files
	@echo "$(YELLOW)Cleaning temporary files...$(NC)"
	@rm -f /tmp/.ttyd-cred.* /tmp/.ttyd-launch.* 2>/dev/null || true
	@rm -f *.log 2>/dev/null || true
	@rm -f landing_*.log 2>/dev/null || true
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Clean complete$(NC)"

clean-all: clean clean-docs docker-clean ## Clean everything (temp + docs + docker)
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
# PHONY
# ============================================================================

.PHONY: help setup setup-env setup-deps setup-novnc \
        run run-ssl stop \
        win-run win-run-nossl win-stop win-verify \
        test test-all test-list test-static test-unit test-integration test-e2e test-security test-fast \
        lint lint-strict lint-python format check \
        docker-build docker-test docker-compose-up docker-compose-down docker-clean \
        vnc-start vnc-stop ttyd-start ttyd-stop novnc-start services-start services-stop cleanup \
        ssl-setup ssl-renew ssl-check user-create user-remove deps-install ttyd-install \
        duckdns-update duckdns-daemon duckdns-check duckdns-update-py \
        nginx-install nginx-configure nginx-start nginx-stop nginx-restart nginx-reload nginx-status \
        status docs docs-serve docs-build \
        install uninstall install-systemd systemd-start systemd-stop systemd-status systemd-enable systemd-disable \
        clean clean-all clean-docs \
        git-status git-log git-push git-pull
