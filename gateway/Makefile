# Copyright 2025 Tigera Inc. All rights reserved.
include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/gateway

#############################################
# Env vars related to packaging and releasing
#############################################
WAF_HTTP_FILTER_IMAGE	?=waf-http-filter
GW_L7_COLLECTOR_IMAGE	?=gateway-l7-collector
BUILD_IMAGES?=$(WAF_HTTP_FILTER_IMAGE) $(GW_L7_COLLECTOR_IMAGE)
BUILD_TAGS   ?= coraza.rule.multiphase_evaluation
EXTRA_GOTEST_ARGS ?= 

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# Env vars related to building
###############################################################################
SRC_FILES = $(shell find pkg cmd -name '*.go')

###############################################################################
# BUILD BINARY
###############################################################################
# This section builds the output binaries.
build: bin/waf-http-filter-$(ARCH) bin/gateway-l7-collector-$(ARCH)

.PHONY: bin/waf-http-filter-$(ARCH)
bin/waf-http-filter-$(ARCH): $(SRC_FILES)
	$(call build_binary, cmd/waf-http-filter/*.go, $@)

.PHONY: bin/gateway-l7-collector-$(ARCH)
bin/gateway-l7-collector-$(ARCH): $(SRC_FILES)
	$(call build_binary, cmd/gateway-l7-collector/*.go, $@)


###############################################################################
# BUILD IMAGE
###############################################################################
WAF_HTTP_FILTER_CONTAINER_CREATED=.waf-http-filter.created-$(ARCH)
GW_L7_COLLECTOR_CONTAINER_CREATED=.gateway-l7-collector.created-$(ARCH)

# Build the docker image.
.PHONY: $(BUILD_IMAGES)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(WAF_HTTP_FILTER_IMAGE) $(GW_L7_COLLECTOR_IMAGE)

$(WAF_HTTP_FILTER_IMAGE): $(WAF_HTTP_FILTER_CONTAINER_CREATED)
$(WAF_HTTP_FILTER_CONTAINER_CREATED): Dockerfile bin/waf-http-filter-$(ARCH)
	$(DOCKER_BUILD) -t $(WAF_HTTP_FILTER_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(WAF_HTTP_FILTER_IMAGE)
	touch $@

$(GW_L7_COLLECTOR_IMAGE): $(GW_L7_COLLECTOR_CONTAINER_CREATED)
$(GW_L7_COLLECTOR_CONTAINER_CREATED): Dockerfile-l7-collector bin/gateway-l7-collector-$(ARCH)
	$(DOCKER_BUILD) -t $(GW_L7_COLLECTOR_IMAGE):latest-$(ARCH) -f Dockerfile-l7-collector .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(GW_L7_COLLECTOR_IMAGE)
	touch $@

.PHONY: clean
clean:
	rm -rf bin \
		report/*.xml \
		config/
	find . -name '*.coverprofile' -type f -delete
	rm -f $(WAF_HTTP_FILTER_CONTAINER_CREATED) $(GW_L7_COLLECTOR_CONTAINER_CREATED)
	-docker image rm -f $$(docker images $(WAF_HTTP_FILTER_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(GW_L7_COLLECTOR_IMAGE) -a -q)


#############################################
# Run unit level tests
#############################################

.PHONY: ut
## Run only Unit Tests.
ut:
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./pkg/... -cover -count 1 -tags=$(BUILD_TAGS) $(EXTRA_GOTEST_ARGS)'

st:
	@echo "No STs"

###############################################################################
# FV Tests
###############################################################################
start-fv-deps: stop-fv-deps
	docker run --rm --detach --net=host --name=echo-server ealen/echo-server:latest --port=8088
	docker run --rm --detach --net=host --name=envoy \
		-v $(REPO_ROOT)/gateway/fv/testdata:/shared \
		envoyproxy/envoy:v1.35-latest \
		--config-path /shared/test-config.yaml \
		--component-log-level ext_proc:trace

stop-fv-deps:
	-docker stop echo-server envoy

## Run the FVs
fv: clean start-fv-deps fv-fast
fv-fast:
	# Mounting the fv/testdata directory as a /shared volume so that moving a file from a test
	# moves it on disk, and is picked up by the envoy proxy that's mounting the same directory
	# as a similar volume so that we can dynamically reconfigure envoy during tests.
	$(DOCKER_RUN) \
	    -v $(REPO_ROOT)/gateway/fv/testdata:/shared \
		$(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go test ./fv -count 1  -tags=$(BUILD_TAGS) $(EXTRA_GOTEST_ARGS)'


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
