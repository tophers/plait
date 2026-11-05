SQLC_VERSION := v1.31.1
DIST_ARCHES := amd64 arm64
DIST_VERSION := $(shell git log -1 --format=%h -- . ':!dist' 2>/dev/null || echo dev)$(shell git diff --quiet HEAD -- . ':!dist' 2>/dev/null || echo -dirty)

.PHONY: dist dist-check build test test-js vendor-js integration phase0 install-test generate vet

dist:
	@for a in $(DIST_ARCHES); do \
		echo "linux/$$a $(DIST_VERSION)"; \
		GOOS=linux GOARCH=$$a CGO_ENABLED=0 go build -trimpath -buildvcs=false \
			-ldflags "-s -w -X main.version=$(DIST_VERSION)" -o dist/linux-$$a/ ./cmd/... || exit 1; \
	done
	cd dist && shasum -a 256 linux-*/* > SHA256SUMS

# Fails if the committed binaries do not match the current source.
dist-check: dist
	git diff --exit-code --stat -- dist

build:
	go build -o bin/ ./cmd/...

test:
	go test -race ./...

test-js:
	cd web && npm ci --ignore-scripts && node --test test/

vendor-js:
	cd web && npm ci --ignore-scripts && node build.mjs

integration:
	./harness/run-in-docker.sh agent-integration.sh
	./harness/run-in-docker.sh controller-integration.sh
	./harness/run-in-docker.sh ui-integration.sh

# Phase 0 networking proof in network namespaces (SPEC §8).
phase0:
	./harness/run-in-docker.sh phase0.sh

install-test:
	./harness/install-test.sh

vet:
	go vet ./...

generate:
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate
