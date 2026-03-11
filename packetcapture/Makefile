# Copyright 2019-2022 Tigera Inc. All rights reserved.
include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/packetcapture

#############################################
# Env vars related to packaging and releasing
#############################################
PACKETCAPTURE_IMAGE ?=packetcapture
BUILD_IMAGES        ?=$(PACKETCAPTURE_IMAGE)

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
build: bin/packetcapture-$(ARCH)

.PHONY: bin/packetcapture-$(ARCH)
bin/packetcapture-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd, $@)
else
	$(call build_binary, ./cmd, $@)
endif

###############################################################################
# BUILD IMAGE
###############################################################################
PACKETCAPTURE_CONTAINER_CREATED=.packetcapture.created-$(ARCH)

# Build the docker image.
.PHONY: $(BUILD_IMAGES)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(PACKETCAPTURE_IMAGE): $(PACKETCAPTURE_CONTAINER_CREATED)
IMAGE_DEPS = Dockerfile
$(PACKETCAPTURE_CONTAINER_CREATED): $(IMAGE_DEPS) bin/packetcapture-$(ARCH) | register
	$(DOCKER_BUILD) -t $(PACKETCAPTURE_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean:
	rm -rf bin \
		report/*.xml \
		release-notes-*
	rm -f $(PACKETCAPTURE_CONTAINER_CREATED)
	-docker image rm -f $$(docker images $(PACKETCAPTURE_IMAGE) -a -q)

###############################################################################
# Testing
###############################################################################
MOCKERY_FILE_PATHS= \
	pkg/cache/ClientCache \
	pkg/capture/FileCommands \
	pkg/capture/K8sCommands

GINKGO_ARGS += -cover -timeout 20m
GINKGO = ginkgo $(GINKGO_ARGS)

#############################################
# Run unit level tests
#############################################

.PHONY: ut
## Run only Unit Tests.
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) $(GINKGO) --junit-report=packetcapture_ut.xml --output-dir=report/ -r pkg/*'

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

## run CI cycle - build, test, etc.
## Run UTs and only if they pass build image and continue along.
## Building the image is required for fvs.
ci: clean static-checks image ut

## Deploys images to registry
cd: image-all cd-common
