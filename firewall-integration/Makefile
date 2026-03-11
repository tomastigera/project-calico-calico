# Copyright 2019-2022 Tigera Inc. All rights reserved.
include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/firewall-integration
BRANCH_NAME     ?= $(PIN_BRANCH)

#############################################
# Env vars related to packaging and releasing
#############################################
FIREWALL_INTEGRATION_IMAGE 	?=firewall-integration
BUILD_IMAGES        				?=$(FIREWALL_INTEGRATION_IMAGE)

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# Env vars related to building
###############################################################################
## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

###############################################################################
# BUILD BINARY
###############################################################################
# This section builds the output binaries.
build: bin/firewall-integration-$(ARCH)

.PHONY: bin/firewall-integration-$(ARCH)
bin/firewall-integration-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/server/*.go, $@)
else
	$(call build_binary, cmd/server/*.go, $@)
endif

###############################################################################
# BUILD IMAGE
###############################################################################
FIREWALL_INTEGRATION_CONTAINER_CREATED=.firewall-integration.created-$(ARCH)

# Build the docker image.
.PHONY: $(BUILD_IMAGES)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(FIREWALL_INTEGRATION_IMAGE)

$(FIREWALL_INTEGRATION_IMAGE): $(FIREWALL_INTEGRATION_CONTAINER_CREATED)
IMAGE_DEPS = Dockerfile
$(FIREWALL_INTEGRATION_CONTAINER_CREATED): $(IMAGE_DEPS) bin/firewall-integration-$(ARCH) | register
	$(DOCKER_BUILD) -t $(FIREWALL_INTEGRATION_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean:
	rm -rf bin report/*.xml
	rm -f $(FIREWALL_INTEGRATION_CONTAINER_CREATED)
	find . -name "*.coverprofile" -type f -delete
	-docker image rm -f $$(docker images $(FIREWALL_INTEGRATION_IMAGE) -a -q)

###############################################################################
# Testing
###############################################################################
GINKGO_ARGS += -cover -timeout 20m
GINKGO = ginkgo $(GINKGO_ARGS)

#############################################
# Run unit level tests
#############################################
.PHONY: ut
## Run only Unit Tests.
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) $(GINKGO) --junit-report=firewall-integration_ut.xml --output-dir=report/ -r pkg/*'

#############################################
# Run FV tests
#############################################
.PHONY: fv
fv:
	echo "running FVs"
	$(DOCKER_GO_BUILD) ./run-fvs

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

## run CI cycle - build, test, etc.
## Run UTs and only if they pass build image and continue along.
## Building the image is required for fvs.
ci: clean static-checks image ut fv

## Deploys images to registry
cd: image-all cd-common
