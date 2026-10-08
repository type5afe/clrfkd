BIN     := bin/clrfkd
LAB     := bin/clrfkd-lab
PKG     := ./cmd/clrfkd
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/type5afe/clrfkd/internal/cli.Version=$(VERSION)

.PHONY: all build lab test race vet fmt check install rename clean

all: check build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)
	go build -trimpath -o $(LAB) ./cmd/clrfkd-lab

test:
	go test ./...

race:
	go test -race -count=2 ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# What CI runs.
check: vet
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go test -race ./...

install:
	go install -trimpath -ldflags '$(LDFLAGS)' $(PKG)

# Start the deliberately vulnerable target. Localhost only.
lab: build
	./$(LAB) -addr 127.0.0.1:8099

# Point the module at your own repository, e.g.
#   make rename MODULE=github.com/you/clrfkd
rename:
	@test -n "$(MODULE)" || { echo "usage: make rename MODULE=github.com/you/clrfkd"; exit 1; }
	@old=$$(go list -m); \
	 grep -rl "$$old" --include='*.go' --include='Makefile' --include='README.md' . \
	   | xargs sed -i "s|$$old|$(MODULE)|g"; \
	 go mod edit -module "$(MODULE)"; \
	 gofmt -l -w . >/dev/null; \
	 echo "module is now $$(go list -m)"
	@$(MAKE) --no-print-directory check

clean:
	rm -rf bin
