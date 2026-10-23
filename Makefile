MODULE      := github.com/HT4w5/bandage
PKG_INFO    := $(MODULE)/internal/identity
BIN_DIR     := bin
CMD         := ./cmd/bandage
BIN         := $(BIN_DIR)/bandage
CMD_SPLINT  := ./cmd/splint
BIN_SPLINT  := $(BIN_DIR)/splint

GO          ?= go

VERSION     ?= $(shell tr -d '[:space:]' 2>/dev/null < .version || echo dev)
COMMIT      ?= $(shell git rev-parse --short=7 HEAD 2>/dev/null)
DIRTY       ?= $(shell if git rev-parse --git-dir >/dev/null 2>&1; then if git diff-index --quiet HEAD -- 2>/dev/null; then echo false; else echo true; fi; fi)

SOURCE_DATE_EPOCH ?=
BUILD_DATE ?= $(shell if [ -n "$(SOURCE_DATE_EPOCH)" ]; then \
	date -u -d "@$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
	date -u -r "$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ; \
	else date -u +%Y-%m-%dT%H:%M:%SZ; fi)

LDFLAGS     := -s -w \
	-X '$(PKG_INFO).version=$(VERSION)' \
	-X '$(PKG_INFO).commit=$(COMMIT)' \
	-X '$(PKG_INFO).buildDate=$(BUILD_DATE)' \
	-X '$(PKG_INFO).dirtyFlag=$(DIRTY)'

GOFLAGS     ?= -trimpath
BUILD_FLAGS := $(GOFLAGS) -ldflags "$(LDFLAGS)"

.PHONY: all build clean test bench bench-pkg

all: build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(BUILD_FLAGS) -o $(BIN) $(CMD)
	$(GO) build $(BUILD_FLAGS) -o $(BIN_SPLINT) $(CMD_SPLINT)

test:
	$(GO) test -race -count=1 ./...

# bench runs the whole benchmark suite with -benchmem. For a stable
# comparison run each side ten times and diff with benchstat
# (golang.org/x/perf/cmd/benchstat):
#   go test -run=^$ -bench=. -benchmem -count=10 ./... > old.txt
#   (make your change)
#   go test -run=^$ -bench=. -benchmem -count=10 ./... > new.txt
#   benchstat old.txt new.txt
bench:
	$(GO) test -run=^$$ -bench=. -benchmem ./...

# bench-pkg runs one package's benchmarks:
#   make bench-pkg PKG=./internal/infra/parse/nginx
bench-pkg:
	@test -n "$(PKG)" || { echo "usage: make bench-pkg PKG=./internal/infra/parse/nginx" >&2; exit 2; }
	$(GO) test -run=^$$ -bench=. -benchmem $(PKG)

clean:
	rm -rf $(BIN_DIR)
