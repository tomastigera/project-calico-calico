include ../metadata.mk
include ../lib.Makefile

PROJECT_NAME ?= cc-dashboard-query-api

GCP_PROJECT ?= tigera-tesla
TAG_NAME ?= $(shell git describe --always --tags --long)
DOCKERFILE=Dockerfile

BINDIR=bin

docker-build: $(BINDIR)/$(PROJECT_NAME)
	$(DOCKER_BUILD) \
		--file ./$(DOCKERFILE) \
		-t "gcr.io/$(GCP_PROJECT)/tigera/$(PROJECT_NAME):$(TAG_NAME)" .

$(BINDIR)/$(PROJECT_NAME): $(shell find . -name '*.go') ../go.mod
	$(CONTAINERIZED_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	CGO_ENABLED=0 go build -v -o $@ ./pkg/internal/cmd/api-server/main.go'

.PHONY: fmt-vet
fmt-vet: ## Run go fmt and go vet against code.
		$(CONTAINERIZED) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
		go fmt ./... && go vet ./...'

.PHONY: test
test: fmt-vet
	$(CONTAINERIZED) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
		go test ./... $(TESTARGS)'

clean:
	rm -f $(BINDIR)/$(PROJECT_NAME)
	rmdir $(BINDIR) 2>/dev/null || true
