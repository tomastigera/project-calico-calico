# Copyright 2022 Tigera Inc. All rights reserved.
include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/linseed

#############################################
# Env vars related to packaging and releasing
#############################################
LINSEED_IMAGE	?=linseed
BUILD_IMAGES?=$(LINSEED_IMAGE)

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# Env vars related to building
###############################################################################
SRC_FILES = $(shell find pkg cmd -name '*.go') \
		$(shell find ../api/pkg -name '*.go') \
		$(shell find ../libcalico-go/lib -name '*.go') \
		$(shell find ../lma/pkg -name '*.go') \
		$(shell find ../goldmane/proto/ '*.go')

###############################################################################
# BUILD BINARY
###############################################################################
# This section builds the output binaries.
build: bin/linseed-$(ARCH)

.PHONY: bin/linseed-$(ARCH)
bin/linseed-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/$*/*.go, $@)
else
	$(call build_binary, cmd/$*/*.go, $@)
endif

###############################################################################
# BUILD IMAGE
###############################################################################
LINSEED_CONTAINER_CREATED=.linseed.created-$(ARCH)

# Build the docker image.
.PHONY: $(BUILD_IMAGES)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(LINSEED_IMAGE)

$(LINSEED_IMAGE): $(LINSEED_CONTAINER_CREATED)
$(LINSEED_CONTAINER_CREATED): Dockerfile bin/linseed-$(ARCH)
	$(DOCKER_BUILD) -t $(LINSEED_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean: stop-elastic
	rm -rf bin \
		fv/cert/*.{crt,csr,key,srl} \
		report/*.xml \
		config/
	find . -name '*.coverprofile' -type f -delete
	rm -f $(LINSEED_CREATED)
	-docker image rm -f $$(docker images $(LINSEED_IMAGE) -a -q)

###############################################################################
# Testing
###############################################################################
MOCKERY_FILE_PATHS= \
	pkg/internal/lma/elastic/index/Helper \
	pkg/backend/api/FlowBackend \
	pkg/backend/api/FlowLogBackend \
	pkg/backend/api/L7FlowBackend \
	pkg/backend/api/L7LogBackend \
	pkg/backend/api/DNSFlowBackend \
	pkg/backend/api/DNSLogBackend \
	pkg/backend/api/EventsBackend \
	pkg/backend/api/AuditBackend \
	pkg/backend/api/BGPBackend \
	pkg/backend/api/ProcessBackend \
	pkg/backend/api/WAFBackend \
	pkg/backend/api/RuntimeBackend \
	pkg/backend/api/BenchmarksBackend \
	pkg/backend/api/ReportsBackend \
	pkg/backend/api/SnapshotsBackend \


#############################################
# Run unit level tests
#############################################
UT_WHAT=./pkg... ./cmd/...

.PHONY: ut
## Run only Unit Tests.
ut: stop-elastic run-elastic ut-fast
ut-fast: gen-certs
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test $(UT_WHAT) -cover -count 1'

st:
	@echo "No STs"

###############################################################################
# FV Tests
###############################################################################

# Run Linseed as a local Docker container.
# Normally we run Linseed in multi-tenant mode, expecting all requests to have "tenant-a".
# But this can be overridden by pre-setting TENANT_ID_ENV.
TENANT_ID_ENV ?= -e LINSEED_EXPECTED_TENANT_ID="tenant-a"
LOG_LEVEL_ENV ?= -e LINSEED_LOG_LEVEL="debug"
run-image: stop-image stop-elastic run-elastic k8s-setup gen-certs
	docker run --detach \
		--net=host \
		--name=tigera-$(LINSEED_IMAGE) \
		--user=$(LOCAL_USER_ID):$(LOCAL_GROUP_ID) \
		-v $(REPO_ROOT)/linseed/fv/cert/localhost.crt:/certs/https/tls.crt \
		-v $(REPO_ROOT)/linseed/fv/cert/localhost.key:/certs/https/tls.key \
		-v $(REPO_ROOT)/linseed/fv/cert/RootCA.crt:/certs/https/client.crt \
		-v $(CERTS_PATH)/ca.pem:/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
		-v $(REPO_ROOT)/linseed/fv/linseed-token:/var/run/secrets/kubernetes.io/serviceaccount/token \
		-v $(REPO_ROOT)/linseed/fv/tenant-namespace:/var/run/secrets/kubernetes.io/serviceaccount/namespace \
		-e KUBERNETES_SERVICE_HOST=127.0.0.1 \
		-e KUBERNETES_SERVICE_PORT=6443 \
		-e ELASTIC_HOST="localhost" \
		-e ELASTIC_SCHEME="http" \
		-e LINSEED_ENABLE_METRICS="true" \
		$(LOG_LEVEL_ENV) \
		$(TENANT_ID_ENV) \
		tigera/$(LINSEED_IMAGE):latest
	# Wait until Linseed is accepting requests on its readiness port.
	while ! curl -k http://localhost:8080/readiness; do echo "Waiting for linseed to come up..."; sleep 2; done

stop-image:
	-docker rm -f $(shell docker ps -aq --filter "name=tigera-$(LINSEED_IMAGE)")

## Run the FVs
WHAT=.
fv: clean image run-elastic k8s-setup fv-fast
fv-fast: build-tests gen-certs
	 cd fv && ./fv.test -test.run $(WHAT)


# Copy certificate from the Elasticsearch container
copy-es-cacert:
	docker cp tigera-elastic:/usr/share/elasticsearch/config/certs/http_ca.crt fv/cert/http_ca.crt
	chmod +r fv/cert/http_ca.crt

## Perform all the necessary setup for a local Kubernetes API server used in the Linseed FVs.
k8s-setup: linseed-token-file fv-token-file auth

## Create auth resources in Kubernetes.
auth:
	$(DOCKER_RUN) \
		-v $(CERTS_PATH):/home/user/certs \
		-e KUBECONFIG=/home/user/certs/kubeconfig \
	       	$(CALICO_BUILD) sh -c 'kubectl create -f /go/src/$(PACKAGE_NAME)/fv/kube/auth.yaml'


## Create a token file for use in the FV tests. This simulates the serviceaccount token provided to linseed by k8s.
linseed-token-file: run-k8s-apiserver
	rm -f fv/linseed-token
	docker exec $(APISERVER_NAME) kubectl create sa tigera-linseed
	docker exec $(APISERVER_NAME) kubectl create token tigera-linseed --duration=24h > fv/linseed-token

## Create a token file for the FV clients to use which is authenticated by Linseed.
fv-token-file:  run-k8s-apiserver
	rm -f fv/client-token
	rm -f fv/client-token-multi-cluster
	docker exec $(APISERVER_NAME) kubectl create sa tigera-linseed-fv
	docker exec $(APISERVER_NAME) kubectl create token tigera-linseed-fv --duration=24h > fv/client-token
	docker exec $(APISERVER_NAME) kubectl create sa tigera-linseed-fv-multi-cluster
	docker exec $(APISERVER_NAME) kubectl create token tigera-linseed-fv-multi-cluster --duration=24h > fv/client-token-multi-cluster

# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
build-tests: $(shell find ./fv -type f -name '*.go' -print)
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./fv -c -o fv/fv.test'

# Generate certificates for use by Linseed UT/FV tests.
gen-certs:
	openssl genrsa -out $(REPO_ROOT)/linseed/fv/cert/RootCA.key 2048
	openssl req -x509 -new -nodes -key $(REPO_ROOT)/linseed/fv/cert/RootCA.key -days 3 -sha256 \
		-out $(REPO_ROOT)/linseed/fv/cert/RootCA.crt \
		-subj "/C=US/CN=linseed-fv-ca"

	openssl genrsa -out $(REPO_ROOT)/linseed/fv/cert/localhost.key 2048
	openssl req -new -key $(REPO_ROOT)/linseed/fv/cert/localhost.key \
		-out $(REPO_ROOT)/linseed/fv/cert/localhost.csr \
		-subj "/C=US/CN=localhost.local"
	openssl x509 -req -in $(REPO_ROOT)/linseed/fv/cert/localhost.csr \
		-CA $(REPO_ROOT)/linseed/fv/cert/RootCA.crt \
		-CAkey $(REPO_ROOT)/linseed/fv/cert/RootCA.key \
		-CAcreateserial -out $(REPO_ROOT)/linseed/fv/cert/localhost.crt -days 3 -sha256 \
		-extfile $(REPO_ROOT)/linseed/fv/cert/localhost-tls.cnf

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

## run CI cycle - build, test, etc.
## Run UTs and only if they pass build image and continue along.
## Building the image is required for fvs.
ci: clean static-checks image test

## Deploys images to registry
cd: image-all cd-common
