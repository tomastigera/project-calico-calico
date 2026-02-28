# Copyright 2024 Tigera Inc. All rights reserved.
include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/dex

#############################################
# Env vars related to packaging and releasing
#############################################
DEX_IMAGE    ?= dex
BUILD_IMAGES ?= $(DEX_IMAGE)

DEX_VERSION = v2.45.0

###############################################################################
# Include lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../../lib.Makefile

###############################################################################
# BUILD BINARY
###############################################################################
# This section builds the output binaries.
DEX_DOWNLOADED=.dex.downloaded

build: dex/bin/dex-$(ARCH) wrapper/bin/dex-wrapper-$(ARCH)

# Commit the changes made by init-cmd if the tree is dirty
init-source: $(DEX_DOWNLOADED)
$(DEX_DOWNLOADED):
	mkdir -p dex
	curl -sfL https://github.com/dexidp/dex/archive/refs/tags/$(DEX_VERSION).tar.gz | tar xz --strip-components 1 -C dex
	patch -d dex -p1 < patches/0001-Remove-unused-code-that-requires-code-generation.patch
	touch $@

.PHONY: dex/bin/dex-$(ARCH)
dex/bin/dex-$(ARCH): init-source
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
		cd dex && CGO_ENABLED=0 go build -o bin/dex-$(ARCH) -v -buildvcs=false -ldflags "-X main.version=$(DEX_VERSION) -s -w" ./cmd/dex/*.go'

.PHONY: wrapper/bin/dex-wrapper-$(ARCH)
wrapper/bin/dex-wrapper-$(ARCH):
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
		cd wrapper && CGO_ENABLED=0 go build -o bin/dex-wrapper-$(ARCH) -v -buildvcs=false ./cmd'

###############################################################################
# BUILD IMAGE
###############################################################################
DEX_CONTAINER_CREATED=.dex.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(DEX_IMAGE)

$(DEX_IMAGE): $(DEX_CONTAINER_CREATED)
$(DEX_CONTAINER_CREATED): dex/bin/dex-$(ARCH) wrapper/bin/dex-wrapper-$(ARCH)
	$(DOCKER_BUILD) -t $(DEX_IMAGE):latest-$(ARCH) -f docker-image/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

ci: image

cd: image-all cd-common

###############################################################################
# Misc.
###############################################################################

clean:
	rm -rf dex
	rm -f $(DEX_DOWNLOADED) $(DEX_CONTAINER_CREATED)-* wrapper/bin/dex-wrapper-*
	-docker image rm -f $$(docker images $(DEX_IMAGE) -a -q)
