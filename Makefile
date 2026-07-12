GO ?= go

.PHONY: build test cover check hooks

build:
	$(GO) build ./...

test:
	$(GO) test ./...

# Integrated coverage report (writes coverage.html).
cover:
	@COVERAGE_MIN=0 ./scripts/check-coverage.sh >/dev/null
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

# The coverage gate — fails below the threshold in .coverage-min.
check:
	./scripts/check-coverage.sh

# Install the git hooks (coverage gate on pre-commit).
hooks:
	git config core.hooksPath .githooks
	@echo "git hooks enabled (.githooks) — commits now run the coverage gate"
