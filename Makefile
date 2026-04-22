# ============================================================================
# MAKEFILE FOR RPI VNC REMOTE SETUP
# ============================================================================

SHELL := /bin/bash

.PHONY: help install test test-all test-unit test-integration test-security
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
	@echo "$(YELLOW)Installing rpi-vnc-remote.sh to /usr/local/bin...$(NC)"
	@sudo cp src/rpi-vnc-remote.sh /usr/local/bin/rpi-vnc-remote
	@sudo chmod +x /usr/local/bin/rpi-vnc-remote
	@echo "$(GREEN)✓ Installation complete$(NC)"

uninstall: ## Remove script from /usr/local/bin
	@echo "$(YELLOW)Removing rpi-vnc-remote from /usr/local/bin...$(NC)"
	@sudo rm -f /usr/local/bin/rpi-vnc-remote
	@echo "$(GREEN)✓ Uninstallation complete$(NC)"

# ============================================================================
# TESTING
# ============================================================================

test: ## Show test help (use test-all to run all tests)
	@echo "$(BLUE)Test Help:$(NC)"
	@cd tests && bash run_tests.sh -h

test-all: ## Run all tests
	@echo "$(BLUE)Running all tests...$(NC)"
	@cd tests && bash run_tests.sh -a

test-list: ## List available tests
	@echo "$(BLUE)Available tests:$(NC)"
	@cd tests && bash run_tests.sh -l

test-unit: ## Run unit tests only
	@echo "$(BLUE)Running unit tests...$(NC)"
	@cd tests && bash run_tests.sh unit/test_syntax.sh
	@cd tests && bash run_tests.sh unit/test_config.sh
	@cd tests && bash run_tests.sh unit/test_utils.sh
	@cd tests && bash run_tests.sh unit/test_modules.sh
	@cd tests && bash run_tests.sh unit/test_edge_cases.sh
	@cd tests && bash run_tests.sh unit/test_error_handling.sh
	@cd tests && bash run_tests.sh unit/test_performance.sh
	@cd tests && bash run_tests.sh unit/test_compatibility.sh
	@cd tests && bash run_tests.sh unit/test_security_improvements.sh

test-integration: ## Run integration tests only
	@echo "$(BLUE)Running integration tests...$(NC)"
	@bash tests/integration/test_docker.sh

test-security: ## Run security tests only
	@echo "$(BLUE)Running security tests...$(NC)"
	@bash tests/security/test_security.sh

test-syntax: ## Run syntax validation only
	@echo "$(BLUE)Running syntax validation...$(NC)"
	@cd tests && bash run_tests.sh unit/test_syntax.sh

test-security-improvements: ## Run security improvements tests only
	@echo "$(BLUE)Running security improvements tests...$(NC)"
	@cd tests && bash run_tests.sh unit/test_security_improvements.sh

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
	@cd docker && docker-compose up

docker-compose-down: ## Stop Docker Compose services
	@echo "$(BLUE)Stopping Docker Compose services...$(NC)"
	@cd docker && docker-compose down

docker-clean: ## Remove Docker images and containers
	@echo "$(YELLOW)Cleaning Docker resources...$(NC)"
	@docker rmi rpi-vnc-remote-test 2>/dev/null || true
	@cd docker && docker-compose down -v 2>/dev/null || true
	@echo "$(GREEN)✓ Docker clean complete$(NC)"

# ============================================================================
# LINTING
# ============================================================================

lint: ## Run shellcheck on all shell scripts
	@echo "$(BLUE)Running shellcheck...$(NC")
	@shellcheck src/rpi-vnc-remote.sh
	@shellcheck src/lib/*.sh
	@shellcheck tests/unit/*.sh
	@shellcheck tests/integration/*.sh
	@shellcheck tests/security/*.sh
	@shellcheck tests/run_tests.sh
	@echo "$(GREEN)✓ Linting complete$(NC)"

# ============================================================================
# CLEANUP
# ============================================================================

clean: ## Clean temporary files
	@echo "$(YELLOW)Cleaning temporary files...$(NC)"
	@rm -f ttyd*
	@rm -f *.log
	@echo "$(GREEN)✓ Clean complete$(NC)"

clean-all: clean docker-clean ## Clean everything including Docker
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
	@cd src && source lib/config.sh && source lib/ssl.sh && setup_ssl

ssl-renew: ## Renew SSL certificates
	@echo "$(BLUE)Renewing SSL certificates...$(NC)"
	@cd src && source lib/config.sh && source lib/ssl.sh && setup_ssl

ssl-check: ## Check SSL certificate expiry
	@echo "$(BLUE)Checking SSL certificate expiry...$(NC)"
	@cd src && source lib/config.sh && source lib/ssl.sh && check_ssl_expiry

user-create: ## Create temporary user
	@echo "$(BLUE)Creating temporary user...$(NC)"
	@cd src && source lib/config.sh && source lib/user.sh && create_temp_user

user-remove: ## Remove temporary user
	@echo "$(BLUE)Removing temporary user...$(NC)"
	@cd src && source lib/config.sh && source lib/utils.sh && remove_temp_user

deps-install: ## Install system dependencies
	@echo "$(BLUE)Installing system dependencies...$(NC)"
	@cd src && source lib/utils.sh && install_dependencies

ttyd-install: ## Install ttyd
	@echo "$(BLUE)Installing ttyd...$(NC)"
	@cd src && source lib/utils.sh && install_ttyd

vnc-start: ## Start VNC server
	@echo "$(BLUE)Starting VNC server...$(NC)"
	@cd src && source lib/config.sh && source lib/services.sh && start_vnc_server

vnc-stop: ## Stop VNC server
	@echo "$(BLUE)Stopping VNC server...$(NC)"
	@cd src && source lib/config.sh && source lib/utils.sh && kill_vnc_server

ttyd-start: ## Start ttyd
	@echo "$(BLUE)Starting ttyd...$(NC)"
	@cd src && source lib/config.sh && source lib/services.sh && start_ttyd

ttyd-stop: ## Stop ttyd
	@echo "$(BLUE)Stopping ttyd...$(NC)"
	@pkill -f ttyd || echo "$(YELLOW)No ttyd process found$(NC)"

novnc-start: ## Start noVNC
	@echo "$(BLUE)Starting noVNC...$(NC)"
	@cd src && source lib/config.sh && source lib/services.sh && start_novnc

services-start: ## Start all services (VNC, ttyd, noVNC)
	@echo "$(BLUE)Starting all services...$(NC)"
	@cd src && source lib/config.sh && source lib/services.sh && start_vnc_server && start_ttyd && start_novnc

services-stop: ## Stop all services
	@echo "$(BLUE)Stopping all services...$(NC)"
	@cd src && source lib/config.sh && source lib/utils.sh && cleanup

beef-inject: ## Inject BeEF hook (requires BEEF_HOOK_URL)
	@if [ -z "$(BEEF_HOOK_URL)" ]; then \
		echo "$(YELLOW)Error: BEEF_HOOK_URL not set$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Injecting BeEF hook...$(NC)"
	@cd src && source lib/config.sh && source lib/services.sh && inject_beef

cleanup: ## Run cleanup (remove services and temp user)
	@echo "$(BLUE)Running cleanup...$(NC)"
	@cd src && source lib/config.sh && source lib/utils.sh && cleanup

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
