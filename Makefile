.PHONY: help test ci
.DEFAULT_GOAL := help

help: ## Displays this help message.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

semgrep: ## Run semgrep
	semgrep --config auto

lint: ## Run golangci-lint
	golangci-lint run ./...

vet: ## Run vetting checks
	go vet ./...

report: ## Run goreportcard
	goreportcard-cli

## Runs the tests and vetting
test: vet
	go test -v -cover -race -count=1 ./...

test-all: semgrep lint test report ## Runs the tests, vetting, and golangci-lint, and semgrep

ci: vet ## Runs the tests and vetting checks (specific for CI)
	go test -cover -race -count=1 ./...

## Runs the tests and benchmarking
bench:
	go test -bench . -cpu=4

coverage: FILE := /tmp/teler-coverage.out # Define coverage file
coverage: ## Runs the tests and check & view the test coverage
	go test -coverprofile=$(FILE) ./...
	go tool cover -func=$(FILE)
	rm -f $(FILE)
