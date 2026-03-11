##############################################################################
# Copyright 2020-2022 Tigera Inc. All rights reserved.
##############################################################################
include ../metadata.mk

PACKAGE_NAME          ?= github.com/projectcalico/calico/l7-collector

L7_COLLECTOR_IMAGE    ?=l7-collector
ENVOY_IMAGE           ?=envoy
BUILD_IMAGES          ?=$(L7_COLLECTOR_IMAGE) $(ENVOY_IMAGE)

##############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

###############################################################################
# Building the binary
###############################################################################
build: bin/l7-collector-$(ARCH)

.PHONY: bin/l7-collector-$(ARCH)
bin/l7-collector-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/l7-collector/*.go, $@)
else
	$(call build_binary, cmd/l7-collector/*.go, $@)
endif

###############################################################################
# Building the image
###############################################################################
L7_COLLECTOR_CONTAINER_CREATED=.l7-collector.created-$(ARCH)
ENVOY_IMAGE_CREATED=.envoy.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(L7_COLLECTOR_IMAGE) $(ENVOY_IMAGE)

$(L7_COLLECTOR_IMAGE): $(L7_COLLECTOR_CONTAINER_CREATED)
IMAGE_DEPS = Dockerfile
$(L7_COLLECTOR_CONTAINER_CREATED): $(IMAGE_DEPS) bin/l7-collector-$(ARCH) | register
	$(DOCKER_BUILD) -t $(L7_COLLECTOR_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(L7_COLLECTOR_IMAGE)
	touch $@

$(ENVOY_IMAGE): $(ENVOY_IMAGE_CREATED)
ENVOY_IMAGE_DEPS = envoy/Dockerfile
$(ENVOY_IMAGE_CREATED): $(ENVOY_IMAGE_DEPS) | register
	$(DOCKER_BUILD) -t $(ENVOY_IMAGE):latest-$(ARCH) -f envoy/Dockerfile envoy
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(ENVOY_IMAGE)
	touch $@

.PHONY: clean
clean:
	rm -rf bin report/*.xml
	rm -f $(L7_COLLECTOR_CONTAINER_CREATED)
	-docker image rm -f $$(docker images $(L7_COLLECTOR_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(ENVOY_IMAGE) -a -q)

###############################################################################
# UTs
###############################################################################
.PHONY: ut
ut: bin/l7-collector-$(ARCH)
	mkdir -p report
	$(DOCKER_GO_BUILD) sh -c "$(GIT_CONFIG_SSH) \
	    ginkgo --junit-report=l7-collector_ut.xml --output-dir=report/ -r --skip-package deps,fv --focus='$(GINKGO_FOCUS)' $(GINKGO_ARGS) $(WHAT)"

.PHONY: fv
fv: bin/l7-collector-$(ARCH)
	$(DOCKER_RUN) \
	    $(LOCAL_BUILD_MOUNTS) \
	    $(CALICO_BUILD) sh -c "$(GIT_CONFIG_SSH) \
	    ginkgo fv -r --skip-package deps --focus='$(GINKGO_FOCUS)' $(GINKGO_ARGS) $(WHAT)"

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

ci: clean static-checks image ut

cd: image-all cd-common
