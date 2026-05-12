# Makefile — bitcoinlib_v03.py development helpers
.PHONY: audit install build-signer lint

# D2: Vulnerability scanning — also enforced in CI (.github/workflows/audit.yml)
audit:
	pip-audit --strict -r requirements.txt

# Install with hash verification (D1 hash-pinned install)
install:
	pip install --require-hashes -r requirements.txt

# Rebuild the Rust signing module (run after modifying signer/src/lib.rs)
build-signer:
	cd signer && \
	VIRTUAL_ENV=$(CURDIR)/.venv \
	PATH="$(CURDIR)/.venv/bin:$(PATH)" \
	PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 \
	$(CURDIR)/.venv/bin/maturin develop --release

# D3: Static analysis — 0 High, 0 Medium required
lint:
	bandit -r bitcoinlib_v03.py
