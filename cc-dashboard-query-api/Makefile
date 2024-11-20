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

clean:
	rm -f $(BINDIR)/$(PROJECT_NAME)
	rmdir $(BINDIR) 2>/dev/null || true

## targets for auto opening prs on helm-charts repo with tag updates
helm-pr:
	git clone git@github.com:tigera/helm-charts.git helm-charts-$(ENV) && cd helm-charts-$(ENV) && \
	/usr/bin/yq write -i charts/cc-dashboard-query-api/values.mgmt-$(ENV).yaml --tag '!!str' apiImageTag ${TAG_NAME} && \
	/usr/bin/yq write -i charts/cc-tenants/values.gcp-us-$(ENV)-01.yaml --tag '!!str' ccDashboardQueryApi.apiImageTag ${TAG_NAME} && \
	git checkout -B ${TAG_NAME}-$(ENV)-release && \
	git add . && \
	git commit -am "Release ${TAG_NAME} to $(ENV) environment" && \
	git push -u origin ${TAG_NAME}-$(ENV)-release && \
	/usr/bin/hub pull-request -m "PR for ${TAG_NAME} CC Dashboard Query API $(ENV) Release" $(PR_OPTS)
