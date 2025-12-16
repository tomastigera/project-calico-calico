# Copyright 2024-2025 Tigera Inc. All rights reserved.

include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/fluentd-base

#############################################
# Env vars related to packaging and releasing
#############################################
FLUENTD_BASE_IMAGE ?= fluentd-base
BUILD_IMAGES ?= $(FLUENTD_BASE_IMAGE)

FLUENTD_VERSION ?= 1.19.1

# required for ci/cd
DEV_REGISTRIES = $(THIRD_PARTY_REGISTRY)
BRANCH_NAME = v$(FLUENTD_VERSION)-$(THIRD_PARTY_RELEASE_BRANCH)
LATEST_IMAGE_TAG = $(BRANCH_NAME)

ifeq ($(OS),Windows_NT)
SHELL := powershell.exe
.SHELLFLAGS := -NoProfile -Command

# Get the Windows build number.
$(eval WINDOWS_BUILD_VERSION := $(shell (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild))

# Get Windows ltsc version based on build number.
ifeq ($(WINDOWS_BUILD_VERSION),17763)
WINDOWS_VERSION := ltsc2019
else ifeq ($(WINDOWS_BUILD_VERSION),20348)
WINDOWS_VERSION := ltsc2022
else
$(error Unknown WINDOWS_BUILD_VERSION)
endif

ARCHES = windows-$(WINDOWS_VERSION)
else
ARCHES = amd64 arm64
endif

###############################################################################
# Include lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../../lib.Makefile

###############################################################################
# BUILD IMAGE
###############################################################################
FLUENTD_BASE_IMAGE_CREATED=.fluentd-base.created-$(ARCH)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image:
	$(MAKE) $(addprefix build-image-,$(VALIDARCHES))

build-image-%:
ifeq ($(OS),Windows_NT)
	docker build --pull --build-arg WINDOWS_VERSION=$(WINDOWS_VERSION) -t $(FLUENTD_BASE_IMAGE):$(LATEST_IMAGE_TAG)-$* -f Dockerfile.windows .
else
	$(DOCKER_BUILD) --build-arg FLUENTD_VERSION=$(FLUENTD_VERSION) -t $(FLUENTD_BASE_IMAGE):$(LATEST_IMAGE_TAG)-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=$(LATEST_IMAGE_TAG)
	touch $(FLUENTD_BASE_IMAGE_CREATED)
endif

.PHONY: clean
clean:
	rm -f $(FLUENTD_BASE_IMAGE_CREATED)
	-docker image rm -f $$(docker images $(FLUENTD_BASE_IMAGE) -a -q)

###############################################################################
# CI/CD
###############################################################################
.PHONY: cd
cd: image-all var-require-one-of-CONFIRM-DRYRUN var-require-all-BRANCH_NAME
	$(MAKE) retag-build-images-with-registries push-images-to-registries IMAGETAG=$(LATEST_IMAGE_TAG) EXCLUDEARCH="$(EXCLUDEARCH)"

.PHONY: push-manifest
push-manifest:
	$(MAKE) push-manifests IMAGETAG=$(LATEST_IMAGE_TAG)	

.PHONY: push-windows-manifest
push-windows-manifest: var-require-one-of-CONFIRM-DRYRUN var-require-all-BRANCH_NAME $(addprefix sub-windows-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGES)))
sub-windows-manifest-%:
	$(DOCKER) manifest create $(call unescapefs,$*):$(LATEST_IMAGE_TAG)-windows $(addprefix --amend ,$(addprefix $(call unescapefs,$*):$(LATEST_IMAGE_TAG)-windows-,$(WINDOWS_VERSIONS))); \
	for win_ver in $(WINDOWS_VERSIONS); do \
		ver=$$(docker manifest inspect mcr.microsoft.com/windows/nanoserver:$${win_ver} | jq -r '.manifests[0].platform."os.version"'); \
		image=$(call unescapefs,$*):$(LATEST_IMAGE_TAG)-windows-$${win_ver}; \
		$(DOCKER) manifest annotate --os windows --arch amd64 --os-version $${ver} $(call unescapefs,$*):$(LATEST_IMAGE_TAG)-windows $${image}; \
	done; \
	$(DOCKER) manifest push --purge $(call unescapefs,$*):$(LATEST_IMAGE_TAG)-windows;

.PHONY: release-retag-image
release-retag-image: var-require-one-of-CONFIRM-DRYRUN var-require-all-RELEASE_BRANCH
	$(CRANE) cp $(THIRD_PARTY_REGISTRY_CD)/$(FLUENTD_BASE_IMAGE):$(FLUENTD_VERSION)-master \
		$(THIRD_PARTY_REGISTRY_CD)/$(FLUENTD_BASE_IMAGE):$(FLUENTD_VERSION)-$(RELEASE_BRANCH)
	$(CRANE) cp $(THIRD_PARTY_REGISTRY_CD)/$(FLUENTD_BASE_IMAGE):$(FLUENTD_VERSION)-master-windows \
		$(THIRD_PARTY_REGISTRY_CD)/$(FLUENTD_BASE_IMAGE):$(FLUENTD_VERSION)-$(RELEASE_BRANCH)-windows
