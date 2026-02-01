.PHONY: help install install-scripts install-configs build serve clean test

help:
	@echo "GPU Security Toolkit - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install          - Install all scripts and configs"
	@echo "  install-scripts  - Install forensic and response scripts only"
	@echo "  install-configs  - Install configuration files only"
	@echo "  build            - Build mdBook documentation"
	@echo "  serve            - Serve mdBook documentation locally"
	@echo "  clean            - Clean build artifacts"
	@echo "  test             - Run tests"
	@echo ""
	@echo "Example: sudo make install"

install: install-scripts install-configs
	@echo "✓ Installation complete"
	@echo ""
	@echo "Scripts installed to: /usr/local/bin/"
	@echo "Configs installed to: /etc/gpu-security/"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Run security baseline: sudo baseline-<your-platform>.sh"
	@echo "  2. Configure monitoring: sudo systemctl enable dcgm"
	@echo "  3. Read documentation: make serve"

install-scripts:
	@echo "Installing forensic and response scripts..."
	install -m 755 scripts/collect_gpu_evidence.sh /usr/local/bin/
	install -m 755 scripts/analyze_gpu_process.sh /usr/local/bin/
	install -m 755 scripts/capture_gpu_network.sh /usr/local/bin/
	install -m 755 scripts/reconstruct_timeline.sh /usr/local/bin/
	install -m 755 scripts/respond_cryptomining.sh /usr/local/bin/
	install -m 755 scripts/respond_model_theft.sh /usr/local/bin/
	install -m 755 scripts/respond_container_escape.sh /usr/local/bin/
	install -m 755 scripts/baseline-workstation.sh /usr/local/bin/
	install -m 755 scripts/baseline-multigpu.sh /usr/local/bin/
	install -m 755 scripts/baseline-hpc.sh /usr/local/bin/
	install -m 755 scripts/baseline-k8s.sh /usr/local/bin/
	@echo "✓ Scripts installed"

install-configs:
	@echo "Installing configuration files..."
	mkdir -p /etc/gpu-security
	install -m 644 configs/dcgm/policies.conf /etc/gpu-security/ 2>/dev/null || true
	install -m 644 configs/prometheus/gpu-alerts.yml /etc/gpu-security/ 2>/dev/null || true
	mkdir -p /forensics
	chmod 700 /forensics
	@echo "✓ Configs installed"

build:
	@echo "Building mdBook documentation..."
	mdbook build
	@echo "✓ Documentation built to ./book/"

serve:
	@echo "Serving documentation at http://localhost:3000"
	mdbook serve --open

clean:
	@echo "Cleaning build artifacts..."
	rm -rf book/
	@echo "✓ Clean complete"

test:
	@echo "Running tests..."
	@bash tests/test-scripts.sh
	@echo "✓ Tests complete"
