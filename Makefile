.PHONY: build test install fuzz fuzz-race fmt lint tidy clean fuzz-bypass fuzz-docker-build fuzz-docker

BINARY      := ./bin/luna
INSTALL_DIR := $(HOME)/.local/bin
GO          := go

onboard-bundle:
	cd internal/onboard && go run gen_bundle.go

build:
	@mkdir -p ./bin
	$(GO) build -ldflags="-s -w" -o $(BINARY) ./main.go
	@echo "Built: $(BINARY)"

install: build
	@mkdir -p $(INSTALL_DIR)
	install -m 755 $(BINARY) $(INSTALL_DIR)/luna
	@echo "Installed: $(INSTALL_DIR)/luna"

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

# Native go-fuzz regression (seeds from Fuzz targets) + exploratory fuzz locally.
fuzz:
	$(GO) test -fuzz=FuzzClassify -fuzztime=5m ./internal/security/

fuzz-race:
	$(GO) test -fuzz=FuzzClassify -fuzztime=5m -race ./internal/security/

fmt:
	$(GO) fmt ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found — install from https://golangci-lint.run/usage/install/"; exit 1; }
	golangci-lint run ./...
	

tidy:
	$(GO) mod tidy

clean:
	rm -f $(BINARY)

run: build
	SYSADM_HOSTS_FILE=hosts.yaml $(BINARY)

fuzz-bypass:
	$(GO) test -fuzz=FuzzMutationBypass -fuzztime=5m ./internal/security/

fuzz-docker-build:
	docker compose -f docker-compose.fuzz.yml build

fuzz-docker:
	docker compose -f /docker-compose.fuzz.yml up --abort-on-container-exit
