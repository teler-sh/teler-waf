.DEFAULT_GOAL := help

GO_MOD_VERSION := $(shell grep -Po '^go \K([0-9]+\.[0-9]+(\.[0-9]+)?)$$' go.mod)
GO := go${GO_MOD_VERSION}
BENCH_TARGET := .
COVER_COUNT := 1

ifeq ($(shell which ${GO}),)
	GO = go
endif

help: ## Displays this help message.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: vet ## Runs the tests and vetting
	$(GO) test -v -race -count=1 ./...

vet: ## Run vetting checks
	$(GO) vet ./...

semgrep: ## Run semgrep
	semgrep --config auto

lint: ## Run golangci-lint
	golangci-lint run ./...

report: ## Run goreportcard
	goreportcard-cli

test-all: semgrep lint test report ## Run the tests, vetting, and golangci-lint, and semgrep

tidy: ## Tidy up the modules
	$(GO) mod tidy

ci: tidy vet ## Run the tidy, vet, and tests checks (specific for CI)
	$(GO) test -cover -race -count=1 ./...

cover: FILE := coverage.txt
cover: ## Run coverage
	$(GO) test -race -coverprofile=$(FILE) -covermode=atomic -count=$(COVER_COUNT) $(TARGET)
	$(GO) tool cover -func=$(FILE)

cover-all: ## Run coverage but recursive
cover-all: COVER_COUNT := 2
cover-all: TARGET := ./...
cover-all: cover

bench: ## Run benchmarking
	$(GO) test -run "^$$" -bench "$(BENCH_TARGET)" -cpu=4 $(ARGS)

bench-initialize: ## Run benchmarking for initializing
bench-initialize: BENCH_TARGET := ^BenchmarkInitialize
bench-initialize: bench

bench-analyze: ## Run benchmarking for analyzing
bench-analyze: BENCH_TARGET := ^BenchmarkAnalyze
bench-analyze: bench

bench-analyze-dev: ## Run benchmarking for analyzing (uncached)
bench-analyze-dev: BENCH_TARGET := ^BenchmarkAnalyze.+WithDevelopment$
bench-analyze-dev: bench

licensing: ## Run licensing Go files
	go-license --config .github/license.yaml $(ARGS) *.go **/*.go

license-verify: ## Verifying files license
license-verify: ARGS := --verify
license-verify: licensing

pprof: ## Run pprof
pprof: ARGS := -cpuprofile=cpu.out -memprofile=mem.out
pprof: bench