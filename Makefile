BINARY := nexus-cli
PKG    := ./...
PORT   ?= 8075

.DEFAULT_GOAL := build

.PHONY: build install run test vet fmt tidy check clean help


build: 
	go build -o $(BINARY) .

install: 
	go install .

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
	rm $(BINARY)

help: 
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
