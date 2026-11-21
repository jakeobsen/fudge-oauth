# fudge-oauth: Fudge's sign-in relay. Run `make help` for targets.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
IMAGE       ?= fudge-oauth:dev

.PHONY: help build test lint image run

help: ## List the targets
	@awk -F':.*## ' '/^[a-z-]+:.*## / { printf "  %-8s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the binary into ./fudge-oauth
	CGO_ENABLED=0 go build -trimpath -o fudge-oauth ./cmd/fudge-oauth

test: ## Run the tests with the race detector
	go test -race ./...

lint: ## gofmt, go vet and staticcheck
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	go run $(STATICCHECK) ./...

image: ## Build the container image
	docker build --tag $(IMAGE) .

run: build ## Run locally with FUDGE_OAUTH_CONFIG (default ./fudge-oauth.yaml)
	FUDGE_OAUTH_CONFIG="$${FUDGE_OAUTH_CONFIG:-fudge-oauth.yaml}" ./fudge-oauth
