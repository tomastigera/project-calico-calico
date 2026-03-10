# Copyright 2019-2022 Tigera Inc. All rights reserved.
include ../metadata.mk

PACKAGE_NAME   ?= github.com/projectcalico/calico/voltron

#############################################
# Env vars related to packaging and releasing
#############################################
COMPONENTS            ?=guardian voltron
VOLTRON_IMAGE         ?=voltron
GUARDIAN_IMAGE        ?=guardian
BUILD_IMAGES          ?=$(VOLTRON_IMAGE) $(GUARDIAN_IMAGE)

##############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

##########################################################################################
# Define some constants
##########################################################################################
BRANCH_NAME ?= $(PIN_BRANCH)

# Some env vars that devs might find useful:
#  TEST_DIRS=   : only run the unit tests from the specified dirs
#  UNIT_TESTS=  : only run the unit tests matching the specified regexp

BINDIR        ?= bin
SRC_FILES = $(shell find . -name '*.go') \
		$(shell find ../api/pkg -name '*.go') \
		$(shell find ../libcalico-go/lib/logutils -name '*.go') \
		$(shell find ../lma/pkg -name '*.go')
TEST_DIRS     ?= $(shell find pkg -name '*_test.go' -exec dirname {} \; | sort -u)
ifdef UNIT_TESTS
UNIT_TEST_FLAGS=-run $(UNIT_TESTS) -v
endif

##########################################################################################
# BUILD
##########################################################################################
build: $(BINDIR)/voltron-$(ARCH) $(BINDIR)/guardian-$(ARCH)

.PHONY: $(BINDIR)/voltron-$(ARCH)
$(BINDIR)/voltron-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/voltron/main.go, $@)
else
	$(call build_binary, ./cmd/voltron/main.go, $@)
endif

.PHONY: $(BINDIR)/guardian-$(ARCH)
$(BINDIR)/guardian-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/guardian/main.go, $@)
else
	$(call build_binary, ./cmd/guardian/main.go, $@)
endif

#############################################
# Docker Image
#############################################
VOLTRON_CONTAINER_CREATED=.voltron.created-$(ARCH)
GUARDIAN_CONTAINER_CREATED=.guardian.created-$(ARCH)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(VOLTRON_IMAGE): $(VOLTRON_CONTAINER_CREATED)
$(VOLTRON_CONTAINER_CREATED): docker-image/voltron/Dockerfile $(BINDIR)/voltron-$(ARCH)
	$(DOCKER_BUILD) -t $(VOLTRON_IMAGE):latest-$(ARCH) -f docker-image/voltron/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(VOLTRON_IMAGE)
	touch $@

$(GUARDIAN_IMAGE): $(GUARDIAN_CONTAINER_CREATED)
$(GUARDIAN_CONTAINER_CREATED): docker-image/guardian/Dockerfile $(BINDIR)/guardian-$(ARCH)
	$(DOCKER_BUILD) -t $(GUARDIAN_IMAGE):latest-$(ARCH) -f docker-image/guardian/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(GUARDIAN_IMAGE)
	touch $@

##########################################################################################
# CLEAN UP
##########################################################################################
.PHONY: clean
clean:
	rm -rf $(BINDIR) report/*.xml
	find . -name "*.coverprofile" -type f -delete
	rm -f $(VOLTRON_CONTAINER_CREATED)
	rm -f $(GUARDIAN_CONTAINER_CREATED)
	-docker image rm -f $$(docker images $(VOLTRON_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(GUARDIAN_IMAGE) -a -q)

##########################################################################################
# TESTING
##########################################################################################
GINKGO_ARGS += -cover -timeout 20m
GINKGO = ginkgo $(GINKGO_ARGS)

#############################################
# Run unit level tests
#############################################
.PHONY: ut
## Run only Unit Tests.
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) $(GINKGO) --junit-report=voltron_ut.xml --output-dir=report/ -r --keep-going pkg/* internal/*'

#############################################
# Run package level functional level tests
#############################################
.PHONY: fv
## Run only Package Functional Tests.
fv:
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) $(GINKGO) -r test/fv'

st:
	@echo "No STs"

##########################################################################################
# CI/CD
##########################################################################################
.PHONY: ci cd

#############################################
# Run CI cycle - build, test, etc.
#############################################
## Run all CI steps for build and test, likely other targets.
ci: clean static-checks image ut fv

#############################################
# Deploy images to registry
#############################################
## Run all CD steps, normally pushing images out to registries.
cd: image-all cd-common

gen-mocks:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'mockery'
