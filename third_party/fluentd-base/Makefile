# Copyright 2024 Tigera Inc. All rights reserved.

include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/fluentd-base

#############################################
# Env vars related to packaging and releasing
#############################################
FLUENTD_BASE_IMAGE ?= fluentd-base
BUILD_IMAGES ?= $(FLUENTD_BASE_IMAGE)

FLUENTD_VERSION ?= 1.18.0

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
# See notes in https://github.com/tigera/fluentd-base/blob/windows-versions/README.md
# on how we map windows versions.
ifeq ($(WINDOWS_BUILD_VERSION),17763)
WINDOWS_LTSC_VERSION := ltsc2019
else ifeq ($(WINDOWS_BUILD_VERSION),20348)
WINDOWS_LTSC_VERSION := ltsc2022
else
$(error Unknown WINDOWS_BUILD_VERSION)
endif

ARCHES = windows-$(WINDOWS_LTSC_VERSION)
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
	docker build --pull --build-arg FLUENTD_UPSTREAM_VERSION=v$(FLUENTD_VERSION)-$*-1.0 -t $(FLUENTD_BASE_IMAGE):$(LATEST_IMAGE_TAG)-$* -f Dockerfile.windows .
else
	$(DOCKER_BUILD) --build-arg ARCH=$(ARCH) --build-arg FLUENTD_VERSION=$(FLUENTD_VERSION) -t $(FLUENTD_BASE_IMAGE):$(LATEST_IMAGE_TAG)-$(ARCH) -f Dockerfile .
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

WINDOWS_LTSC_VERSIONS ?= ltsc2019 ltsc2022
NANOSERVER_VERSIONS ?= 1809 ltsc2022

.PHONY: push-windows-manifest
push-windows-manifest: var-require-one-of-CONFIRM-DRYRUN var-require-all-BRANCH_NAME $(addprefix sub-windows-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGES)))
sub-windows-manifest-%:
	$(DOCKER) manifest create $(call unescapefs,$*):$(LATEST_IMAGE_TAG)-windows $(addprefix --amend ,$(addprefix $(call unescapefs,$*):$(LATEST_IMAGE_TAG)-windows-,$(WINDOWS_LTSC_VERSIONS))); \
	for win_ver in $(NANOSERVER_VERSIONS); do \
		ver=$$(docker manifest inspect mcr.microsoft.com/windows/nanoserver:$${win_ver} | jq -r '.manifests[0].platform."os.version"'); \
		image=$(call unescapefs,$*):$(LATEST_IMAGE_TAG)-windows-$$(printf '%s' $${win_ver} | sed 's/ltsc//g'); \
		$(DOCKER) manifest annotate --os windows --arch amd64 --os-version $${ver} $(call unescapefs,$*):$(LATEST_IMAGE_TAG)-windows $${image}; \
	done; \
	$(DOCKER) manifest push --purge $(call unescapefs,$*):$(LATEST_IMAGE_TAG)-windows;
