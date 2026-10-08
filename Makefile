BIN     := bin/clrfkd
LAB     := bin/clrfkd-lab
PKG     := ./cmd/clrfkd
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/type5afe/clrfkd/internal/cli.Version=$(VERSION)

.PHONY: all build lab test race vet fmt check install rename dist clean

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

# Build release archives for every platform into dist/.
# Reproducible: -trimpath plus CGO disabled, and the version comes from the tag.
dist:
	@rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
	  os=$$(echo $$p | cut -d/ -f1); arch=$$(echo $$p | cut -d/ -f2); ext=; \
	  [ "$$os" = windows ] && ext=.exe; \
	  name=clrfkd_$(VERSION)_$${os}_$${arch}; \
	  echo "  $$os/$$arch"; \
	  mkdir -p dist/$$name; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	    go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$$name/clrfkd$$ext $(PKG) || exit 1; \
	  cp README.md LICENSE dist/$$name/; \
	  if [ "$$os" = windows ] && command -v zip >/dev/null; then \
	    (cd dist && zip -qr $$name.zip $$name); \
	  else \
	    tar -C dist -czf dist/$$name.tar.gz $$name; \
	  fi; \
	  rm -rf dist/$$name; \
	done
	@cd dist && sha256sum clrfkd_* > SHA256SUMS
	@echo; ls -1 dist

clean:
	rm -rf bin dist
