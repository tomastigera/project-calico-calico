# Copyright 2022-2023 Tigera Inc. All rights reserved.
include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/policy-recommendation

#############################################
# Env vars related to packaging and releasing
#############################################
POLICY_RECOMMENDATION_IMAGE ?=policy-recommendation
BUILD_IMAGES        ?=$(POLICY_RECOMMENDATION_IMAGE)

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
		$(shell find ../libcalico-go/lib -name '*.go') \
		$(shell find ../lma/pkg -name '*.go')

###############################################################################
# BUILD BINARY
###############################################################################
# This section builds the output binaries.
build: bin/policy-recommendation-$(ARCH)

.PHONY: bin/policy-recommendation-$(ARCH)
bin/policy-recommendation-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/main.go, $@)
else
	$(call build_binary, ./cmd/main.go, $@)
endif

###############################################################################
# BUILD IMAGE
###############################################################################
POLICY_RECOMMENDATION_CONTAINER_CREATED=.policy-recommendation.created-$(ARCH)

# Build the docker image.
.PHONY: $(BUILD_IMAGES)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(POLICY_RECOMMENDATION_IMAGE): $(POLICY_RECOMMENDATION_CONTAINER_CREATED)
$(POLICY_RECOMMENDATION_CONTAINER_CREATED): Dockerfile bin/policy-recommendation-$(ARCH)
	$(DOCKER_BUILD) -t $(POLICY_RECOMMENDATION_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean:
	rm -rf bin \
	rm -f $(POLICY_RECOMMENDATION_CONTAINER_CREATED)
	find . -name "*.coverprofile" -type f -delete
	-docker image rm -f $$(docker images $(POLICY_RECOMMENDATION_IMAGE) -a -q)

###############################################################################
# Testing
###############################################################################
GINKGO_ARGS += -cover -timeout 20m
GINKGO = ginkgo $(GINKGO_ARGS)


#############################################
# Run fv tests
#############################################
.PHONY: fv
fv:
	echo "running FVs"
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./... -cover -count 1'

#############################################
# Run unit level tests
#############################################
.PHONY: ut
## Run only Unit Tests.
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) $(GINKGO) -r pkg/*'

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

st:
	@echo "No STs available"
