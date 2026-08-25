# =============================================================================
# RedirX — developer Makefile
#
#   make            → list targets
#   make check      → everything CI runs (fmt + vet + lint + test + build)
#   make release    → local GoReleaser snapshot (dist/, no upload)
#
# Overrideables:
#   make build VERSION=9.9.9-custom
#   make lint GOLANGCI_LINT_VERSION=v1.64.8
# =============================================================================

BINARY      := redirx
PKG         := ./...
MAIN        := ./cmd/redirx

# Version falls back to git describe (tag/commit/dirty) so dev builds are
# traceable; release pipelines inject their own via ldflags. Any leading 'v'
# is stripped because the CLI template renders its own.
VERSION ?= $(patsubst v%,%,$(shell git describe --tags --always --dirty 2>/dev/null || echo dev))

MODULE      := $(shell go list -m)
CLI_PKG     := $(MODULE)/cmd/cli
LDFLAGS     := -s -w -X $(CLI_PKG).version=$(VERSION)

GOLANGCI_LINT_VERSION ?= v2.6.2

.DEFAULT_GOAL := help
.PHONY: help all build test test-race cover fmt vet lint check tidy clean install uninstall release-snapshot

## help: show this help
help:
	@echo "RedirX — make targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | sed 's/:.*→/ →/'

## all: fmt + vet + test + build (quick local loop)
all: fmt vet test build

## build: compile ./redirx with version stamped from git
# CGO off for release binaries: static linking, cross-compiles anywhere.
# NOT exported globally — the race detector in test-race requires cgo.
build:
	@echo "▶ building $(BINARY) $(VERSION)"
	@CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) $(MAIN)

## test: run unit tests
test:
	@echo "▶ testing"
	@go test $(PKG) -count=1

## test-race: unit tests under the race detector
test-race:
	@echo "▶ race testing"
	@go test -race -count=1 $(PKG)

## cover: open an HTML coverage report in the browser
cover:
	@go test -coverprofile=coverage.out $(PKG) >/dev/null
	@go tool cover -html=coverage.out
	@rm -f coverage.out

## fmt: format every file in place
fmt:
	@echo "▶ gofmt"
	@find . -name '*.go' -not -path './dist/*' -print0 | xargs -0 gofmt -w

## vet: static analysis
vet:
	@echo "▶ go vet"
	@go vet $(PKG)

## lint: golangci-lint via pinned version (always — system binaries drift)
lint:
	@echo "▶ golangci-lint ($(GOLANGCI_LINT_VERSION))"
	@go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

## check: the exact gate CI enforces — run before pushing
check: fmt vet lint test-race build
	@echo "✓ all checks passed"

## tidy: prune module graph and verify consistency
tidy:
	@go mod tidy
	@go mod verify

## install: build + place into $(GOPATH)/bin
install:
	@echo "▶ installing $(BINARY) $(VERSION)"
	@CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' $(MAIN)

## uninstall: remove the installed binary
uninstall:
	@rm -f $$(go env GOPATH)/bin/$(BINARY)

## release-snapshot: full GoReleaser pipeline into dist/ — no upload, no tag needed
release-snapshot: clean
	@echo "▶ goreleaser snapshot"
	@go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean

## clean: remove build artifacts
clean:
	@rm -rf dist coverage.out $(BINARY)
	@echo "✓ clean"
