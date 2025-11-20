# Copyright 2024 Tigera Inc. All rights reserved.

include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/snort3

#############################################
# Env vars related to packaging and releasing
#############################################
SNORT3_IMAGE ?= snort
BUILD_IMAGES ?= $(SNORT3_IMAGE)

SNORT3_VERSION = 3.9.7.0

# required for ci/cd
DEV_REGISTRIES = $(THIRD_PARTY_REGISTRY)
BRANCH_NAME = v$(SNORT3_VERSION)-$(THIRD_PARTY_RELEASE_BRANCH)
LATEST_IMAGE_TAG = $(BRANCH_NAME)

###############################################################################
# Include lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../../lib.Makefile

###############################################################################
# BUILD IMAGE
###############################################################################
SNORT3_IMAGE_CREATED=.snort3.created-$(ARCH)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(SNORT3_IMAGE)

$(SNORT3_IMAGE): $(SNORT3_IMAGE_CREATED)
$(SNORT3_IMAGE_CREATED): Dockerfile snort3-community.rules
	$(DOCKER_BUILD) --build-arg SNORT3_VERSION=$(SNORT3_VERSION) -t $(SNORT3_IMAGE):$(LATEST_IMAGE_TAG)-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=$(LATEST_IMAGE_TAG)
	touch $@

.PHONY: clean
clean:
	rm -f $(SNORT3_IMAGE_CREATED)
	-docker image rm -f $$(docker images $(SNORT3_IMAGE) -a -q)

###############################################################################
# CI/CD
###############################################################################
.PHONY: cd
cd: image-all var-require-one-of-CONFIRM-DRYRUN var-require-all-BRANCH_NAME
	$(MAKE) retag-build-images-with-registries push-images-to-registries IMAGETAG=$(LATEST_IMAGE_TAG) EXCLUDEARCH="$(EXCLUDEARCH)"

.PHONY: push-manifest
push-manifest:
	$(MAKE) push-manifests IMAGETAG=$(LATEST_IMAGE_TAG)

.PHONY: release-retag-image
release-retag-image: var-require-one-of-CONFIRM-DRYRUN var-require-all-RELEASE_BRANCH
	$(CRANE) cp $(THIRD_PARTY_REGISTRY_CD)/$(SNORT3_IMAGE):$(SNORT3_VERSION)-master \
		$(THIRD_PARTY_REGISTRY_CD)/$(SNORT3_IMAGE):$(SNORT3_VERSION)-$(RELEASE_BRANCH)$(double_quote)
