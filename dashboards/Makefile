# Copyright 2025 Tigera Inc. All rights reserved.

include ../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/dashboards

###############################################################################
# Env vars related to building
###############################################################################
SRC_FILES = $(shell find . -name '*.go')
BINDIR = bin

###############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# Binary build
###############################################################################
.PHONY: build
build: $(BINDIR)/dashboard-api-$(ARCH)

$(BINDIR)/dashboard-api-$(ARCH): $(SRC_FILES)
	$(call build_binary, pkg/internal/cmd/api-server/main.go, $@)

.PHONY: clean
clean:
	rm -fr $(BINDIR)/

###############################################################################
# Testing
###############################################################################
.PHONY: ut
ut:
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./... -cover -count 1'

###############################################################################
# CI
###############################################################################
.PHONY: ci

ci: clean static-checks build ut

###############################################################################
# Calico Cloud targets
###############################################################################
PROJECT_NAME ?= cc-dashboard-query-api

GCP_PROJECT ?= tigera-tesla
TAG_NAME ?= $(if $(git-release-tag-for-current-commit),$(git-release-tag-for-current-commit),$(shell git describe --always --tags --long))
DOCKERFILE=Dockerfile

docker-build: $(BINDIR)/$(PROJECT_NAME)
	$(DOCKER_BUILD) \
		--file ./$(DOCKERFILE) \
		-t "gcr.io/$(GCP_PROJECT)/tigera/$(PROJECT_NAME):$(TAG_NAME)" .

$(BINDIR)/$(PROJECT_NAME): $(SRC_FILES)
	$(CONTAINERIZED_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	CGO_ENABLED=0 go build -v -o $@ ./pkg/internal/cmd/api-server/main.go'

docker-push: docker-build
	docker push "gcr.io/$(GCP_PROJECT)/tigera/$(PROJECT_NAME):$(TAG_NAME)"

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

## targets for auto opening prs on helm-charts repo with tag updates
helm-pr:
	git clone git@github.com:tigera/helm-charts.git helm-charts-$(ENV) && cd helm-charts-$(ENV) && \
	/usr/bin/yq write -i charts/cc-dashboard-query-api/values.mgmt-$(ENV).yaml --tag '!!str' apiImageTag ${TAG_NAME} && \
	/usr/bin/yq write -i charts/cc-tenants/values.gcp-us-$(ENV)-01.yaml --tag '!!str' ccDashboardQueryApi.apiImageTag ${TAG_NAME} && \
	git checkout -B ${TAG_NAME}-$(ENV)-release && \
	git add . && \
	git commit -am "Release ${PROJECT_NAME} ${TAG_NAME} to $(ENV) environment" && \
	git push -u origin ${TAG_NAME}-$(ENV)-release && \
	/usr/bin/hub pull-request -m "PR for ${TAG_NAME} CC Dashboard Query API $(ENV) Release" $(PR_OPTS)
