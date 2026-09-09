# ============================================================================
# MAKEFILE FOR RPI VNC REMOTE SETUP
# ============================================================================

SHELL := /bin/bash

.PHONY: help install test test-all test-list test-static test-unit
.PHONY: test-integration test-e2e test-security
.PHONY: docker-build docker-test docker-clean clean lint format

# Default target
.DEFAULT_GOAL := help

# Load .env file if it exists
ifneq (,$(wildcard .env))
    include .env
    export
endif

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m

# ============================================================================
# HELP
# ============================================================================

help: ## Show this help message
	@echo "$(BLUE)========================================$(NC)"
	@echo "$(BLUE)  Available Commands$(NC)"
	@echo "$(BLUE)========================================$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""

# ============================================================================
# INSTALLATION
# ============================================================================

install: ## Install script to /usr/local/bin
	@echo "$(YELLOW)Installing rpi-vnc-remote to /usr/local...$(NC)"
	@sudo mkdir -p /usr/local/share/rpi-vnc-remote
	@sudo cp -r src/ /usr/local/share/rpi-vnc-remote/src/
	@sudo cp -r src/config/ /usr/local/share/rpi-vnc-remote/config/ 2>/dev/null || true
	@printf '#!/bin/bash\nexec /usr/local/share/rpi-vnc-remote/src/rpi-vnc-remote.sh "$$@"\n' | sudo tee /usr/local/bin/rpi-vnc-remote > /dev/null
	@sudo chmod +x /usr/local/bin/rpi-vnc-remote
	@echo "$(GREEN)✓ Installation complete$(NC)"

uninstall: ## Remove script from /usr/local/bin
	@echo "$(YELLOW)Removing rpi-vnc-remote from /usr/local...$(NC)"
	@sudo rm -f /usr/local/bin/rpi-vnc-remote
	@sudo rm -rf /usr/local/share/rpi-vnc-remote
	@echo "$(GREEN)✓ Uninstallation complete$(NC)"

# ============================================================================
# TESTING
# ============================================================================

test: ## Show test help (use test-all to run all tests)
	@echo "$(BLUE)Test Help:$(NC)"
	@cd tests && bash run_tests.sh -h

test-all: ## Run all tests (all pyramid levels in order)
	@echo "$(BLUE)Running all tests (pyramid)...$(NC)"
	@cd tests && bash run_tests.sh

test-list: ## List available tests
	@echo "$(BLUE)Available tests:$(NC)"
	@cd tests && bash run_tests.sh -l

test-static: ## Level 0: static analysis (lint, syntax, CRLF, shellcheck)
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

test-security: ## Level 7: security tests (password, sanitization, hardening)
	@echo "$(BLUE)Running security tests (Level 7)...$(NC)"
	@cd tests && bash run_tests.sh security/

# ============================================================================
# DOCKER
# ============================================================================

docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	@cd docker && docker build -t rpi-vnc-remote-test -f Dockerfile ..

docker-test: docker-build ## Run tests in Docker
	@echo "$(BLUE)Running tests in Docker...$(NC)"
	@cd docker && docker-compose run test

docker-compose-up: ## Start Docker Compose services
	@echo "$(BLUE)Starting Docker Compose services...$(NC)"
	@docker-compose up -d

docker-compose-down: ## Stop Docker Compose services
	@echo "$(BLUE)Stopping Docker Compose services...$(NC)"
	@docker-compose down

docker-clean: ## Remove Docker images and containers
	@echo "$(YELLOW)Cleaning Docker resources...$(NC)"
	@docker rmi rpi-vnc-remote-test 2>/dev/null || true
	@cd docker && docker-compose down -v 2>/dev/null || true
	@echo "$(GREEN)✓ Docker clean complete$(NC)"

# ============================================================================
# LINTING
# ============================================================================

lint: ## Run shellcheck on all shell scripts (warnings shown, non-fatal)
	@echo "$(BLUE)Running shellcheck...$(NC)"
	@shellcheck -x src/rpi-vnc-remote.sh || true
	@shellcheck -x src/lib/core/*.sh src/lib/security/*.sh src/lib/web/*.sh || true
	@shellcheck -x src/lib/monitoring/*.sh src/lib/communication/*.sh src/lib/features/*.sh || true
	@shellcheck -x tests/run_tests.sh || true
	@find tests/unit tests/integration tests/system tests/e2e tests/maintenance tests/documentation -name 'test_*.sh' -type f -print0 2>/dev/null | xargs -0 -r shellcheck -x || true
	@echo "$(GREEN)✓ Linting complete$(NC)"

lint-strict: ## Run shellcheck and fail on any warning
	@echo "$(BLUE)Running shellcheck (strict)...$(NC)"
	@shellcheck -x src/rpi-vnc-remote.sh
	@shellcheck -x src/lib/core/*.sh src/lib/security/*.sh src/lib/web/*.sh
	@shellcheck -x src/lib/monitoring/*.sh src/lib/communication/*.sh src/lib/features/*.sh
	@shellcheck -x tests/run_tests.sh
	@find tests/unit tests/integration tests/system tests/e2e tests/maintenance tests/documentation -name 'test_*.sh' -type f -print0 2>/dev/null | xargs -0 -r shellcheck -x
	@echo "$(GREEN)✓ Linting complete (no warnings)$(NC)"

# ============================================================================
# DOCUMENTATION
# ============================================================================

docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	@echo "$(GREEN)Documentation available in doc/ directory$(NC)"
	@echo ""
	@echo "Quick Start:     doc/installation/quick-start.md"
	@echo "Installation:    doc/installation/detailed-setup.md"
	@echo "Configuration:   doc/installation/configuration.md"
	@echo "User Guide:      doc/user-guide/"
	@echo "Developer:       doc/developer/"
	@echo "Reference:       doc/reference/"

docs-serve: ## Serve documentation locally (requires mkdocs)
	@echo "$(BLUE)Serving documentation locally...$(NC)"
	@if command -v mkdocs &>/dev/null; then \
		mkdocs serve; \
	else \
		echo "$(YELLOW)mkdocs not installed. Install with: pip install mkdocs$(NC)"; \
	fi

docs-build: ## Build documentation (requires mkdocs)
	@echo "$(BLUE)Building documentation...$(NC)"
	@if command -v mkdocs &>/dev/null; then \
		mkdocs build; \
	else \
		echo "$(YELLOW)mkdocs not installed. Install with: pip install mkdocs$(NC)"; \
	fi

docs-validate: ## Validate documentation links and structure
	@echo "$(BLUE)Validating documentation...$(NC)"
	@find doc/ -name "*.md" -exec echo "Checking: {}" \; -exec markdownlint {} \; 2>/dev/null || echo "$(YELLOW)markdownlint not available$(NC)"
	@echo "$(GREEN)Documentation validation complete$(NC)"

# ============================================================================
# CLEANUP
# ============================================================================

clean: ## Clean temporary files
	@echo "$(YELLOW)Cleaning temporary files...$(NC)"
	@rm -f ttyd*
	@rm -f *.log
	@echo "$(GREEN)✓ Clean complete$(NC)"

clean-docs: ## Clean generated documentation
	@echo "$(YELLOW)Cleaning documentation...$(NC)"
	@rm -rf site/
	@echo "$(GREEN)✓ Documentation clean complete$(NC)"

clean-all: clean clean-docs docker-clean ## Clean everything including Docker
	@echo "$(YELLOW)Full clean complete$(NC)"

# ============================================================================
# SCRIPT EXECUTION
# ============================================================================

run: ## Run the script (requires TTYD_PASSWD)
	@if [ -z "$(TTYD_PASSWD)" ]; then \
		echo "$(YELLOW)Warning: TTYD_PASSWD not set$(NC)"; \
	fi
	@bash src/rpi-vnc-remote.sh

run-ssl: ## Run the script with SSL (requires TTYD_PASSWD and DUCK_DOMAIN)
	@if [ -z "$(TTYD_PASSWD)" ]; then \
		echo "$(YELLOW)Warning: TTYD_PASSWD not set$(NC)"; \
	fi
	@if [ -z "$(DUCK_DOMAIN)" ]; then \
		echo "$(YELLOW)Warning: DUCK_DOMAIN not set$(NC)"; \
	fi
	@bash src/rpi-vnc-remote.sh

stop: ## Stop services
	@bash src/rpi-vnc-remote.sh stop

# ============================================================================
# FUNCTIONALITY TARGETS
# ============================================================================

ssl-setup: ## Setup SSL certificates (requires DUCK_DOMAIN and EMAIL)
	@if [ -z "$(DUCK_DOMAIN)" ]; then \
		echo "$(YELLOW)Error: DUCK_DOMAIN not set$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(EMAIL)" ]; then \
		echo "$(YELLOW)Error: EMAIL not set$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Setting up SSL certificates...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/security/ssl.sh && setup_ssl

ssl-renew: ## Renew SSL certificates
	@echo "$(BLUE)Renewing SSL certificates...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/security/ssl.sh && setup_ssl

ssl-check: ## Check SSL certificate expiry
	@echo "$(BLUE)Checking SSL certificate expiry...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/security/ssl.sh && check_ssl_expiry

user-create: ## Create temporary user
	@echo "$(BLUE)Creating temporary user...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/security/user.sh && create_temp_user

user-remove: ## Remove temporary user
	@echo "$(BLUE)Removing temporary user...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && remove_temp_user

deps-install: ## Install system dependencies
	@echo "$(BLUE)Installing system dependencies...$(NC)"
	@cd src && source lib/core/utils.sh && install_dependencies

ttyd-install: ## Install ttyd
	@echo "$(BLUE)Installing ttyd...$(NC)"
	@cd src && source lib/core/utils.sh && install_ttyd

vnc-start: ## Start VNC server
	@echo "$(BLUE)Starting VNC server...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/services.sh && start_vnc_server

vnc-stop: ## Stop VNC server
	@echo "$(BLUE)Stopping VNC server...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && kill_vnc_server

ttyd-start: ## Start ttyd
	@echo "$(BLUE)Starting ttyd...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/services.sh && start_ttyd

ttyd-stop: ## Stop ttyd
	@echo "$(BLUE)Stopping ttyd...$(NC)"
	@pkill -f ttyd || echo "$(YELLOW)No ttyd process found$(NC)"

novnc-start: ## Start noVNC
	@echo "$(BLUE)Starting noVNC...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/services.sh && start_novnc

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

services-start: ## Start all services (VNC, ttyd, noVNC)
	@echo "$(BLUE)Starting all services...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/services.sh && start_vnc_server && start_ttyd && start_novnc

services-stop: ## Stop all services
	@echo "$(BLUE)Stopping all services...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/core/cleanup_utils.sh && cleanup_processes

cleanup: ## Run cleanup (remove services and temp user)
	@echo "$(BLUE)Running cleanup...$(NC)"
	@cd src && source lib/core/config.sh && source lib/core/utils.sh && source lib/core/cleanup_utils.sh && cleanup_processes

# ============================================================================
# STATUS
# ============================================================================

status: ## Show status of services
	@echo "$(BLUE)Checking service status...$(NC)"
	@echo "VNC Server:"
	@pgrep -f Xtigervnc && echo "  $(GREEN)Running$(NC)" || echo "  $(RED)Stopped$(NC)"
	@echo "ttyd:"
	@pgrep -f ttyd && echo "  $(GREEN)Running$(NC)" || echo "  $(RED)Stopped$(NC)"
	@echo "noVNC:"
	@pgrep -f novnc_proxy && echo "  $(GREEN)Running$(NC)" || echo "  $(RED)Stopped$(NC)"

# ============================================================================
# GIT
# ============================================================================

git-status: ## Show git status
	@git status

git-log: ## Show git log
	@git log --oneline -10

git-push: ## Push to remote
	@git push origin main

git-pull: ## Pull from remote
	@git pull origin main
