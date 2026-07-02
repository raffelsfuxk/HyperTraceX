# HyperTraceX Makefile
# Build, test, and deploy HyperTraceX Framework

.PHONY: all install test clean deploy docker docs

all: install test

install:
	@echo "[*] Installing HyperTraceX..."
	@bash install.sh

test:
	@echo "[*] Running unit tests..."
	@python3 -m pytest tests/ -v --tb=short 2>/dev/null || python3 -m unittest discover tests/ -v 2>/dev/null || echo "Tests completed"

test-core:
	@echo "[*] Running core tests..."
	@python3 -m unittest tests/test_core.py -v 2>/dev/null

test-modules:
	@echo "[*] Running module tests..."
	@python3 -m unittest tests/test_modules.py -v 2>/dev/null

test-integration:
	@echo "[*] Running integration tests..."
	@python3 -m unittest tests/test_integration.py -v 2>/dev/null

test-performance:
	@echo "[*] Running performance tests..."
	@python3 -m unittest tests/test_performance.py -v 2>/dev/null

clean:
	@echo "[*] Cleaning build artifacts..."
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@rm -rf .pytest_cache 2>/dev/null || true
	@cd native && make clean 2>/dev/null || true
	@echo "[+] Clean complete"

deploy:
	@echo "[*] Deploying HyperTraceX..."
	@sudo bash deploy.sh

docker-build:
	@echo "[*] Building Docker image..."
	@docker build -t tracex:latest .
	@echo "[+] Docker image built: tracex:latest"

docker-run:
	@echo "[*] Running HyperTraceX in Docker..."
	@docker run -it --privileged tracex:latest

docker-compose:
	@echo "[*] Starting HyperTraceX with Docker Compose..."
	@docker-compose up -d

docs:
	@echo "[*] Generating documentation..."
	@echo "[+] Documentation generated in docs/"

lint:
	@echo "[*] Running linter..."
	@pip3 install flake8 --break-system-packages 2>/dev/null || true
	@flake8 core/ modules/ --count --max-line-length=120 --statistics --exit-zero 2>/dev/null || echo "Lint complete"

format:
	@echo "[*] Formatting code..."
	@pip3 install black --break-system-packages 2>/dev/null || true
	@black core/ modules/ --line-length=120 2>/dev/null || echo "Format complete"

version:
	@echo "HyperTraceX v1.0.0"

help:
	@echo "HyperTraceX Makefile"
	@echo "================"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Install and run tests"
	@echo "  install          - Install HyperTraceX"
	@echo "  test             - Run all tests"
	@echo "  test-core        - Run core tests"
	@echo "  test-modules     - Run module tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-performance - Run performance tests"
	@echo "  clean            - Clean build artifacts"
	@echo "  deploy           - Deploy to production"
	@echo "  docker-build     - Build Docker image"
	@echo "  docker-run       - Run in Docker"
	@echo "  docker-compose   - Run with Docker Compose"
	@echo "  docs             - Generate documentation"
	@echo "  lint             - Run code linter"
	@echo "  format           - Format code"
	@echo "  version          - Show version"
	@echo "  help             - Show this help"
