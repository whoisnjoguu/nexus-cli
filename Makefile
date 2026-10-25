BINARY := nexus-cli
PKG    := ./...
PORT   ?= 8075

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.DEFAULT_GOAL := build

.PHONY: build install run test vet fmt tidy check clean help docker


build: 
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

install: 
	go install -ldflags "$(LDFLAGS)" .

run: build 
	./$(BINARY) dev --port $(PORT)

test: 
	go test $(PKG)

vet: 
	go vet $(PKG)

fmt: 
	gofmt -w .

tidy: 
	go mod tidy

check: fmt vet test 

clean:
	rm -rf $(BINARY) .docker

IMAGE       ?= nexus-cli:dev
DOCKER_ARCH ?= $(shell go env GOARCH)

# Build a local container image for linux/$(DOCKER_ARCH) using the same Dockerfile as releases.
docker:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(DOCKER_ARCH) go build -ldflags "$(LDFLAGS)" -o .docker/linux/$(DOCKER_ARCH)/nexus-cli .
	docker build --platform linux/$(DOCKER_ARCH) -f Dockerfile -t $(IMAGE) .docker

help: 
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
