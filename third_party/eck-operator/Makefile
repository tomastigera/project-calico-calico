# Copyright 2022-2024 Tigera Inc. All rights reserved.
include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/eck-operator

#############################################
# Env vars related to packaging and releasing
#############################################
ECK_OPERATOR_IMAGE    ?= eck-operator
BUILD_IMAGES          ?= $(ECK_OPERATOR_IMAGE)

ECK_OPERATOR_VERSION = v2.16.1

VERSION ?= $(shell cat cloud-on-k8s/VERSION)

###############################################################################
# Include lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../../lib.Makefile

###############################################################################
# Env vars related to building
###############################################################################
LDFLAGS ?= -X $(PACKAGE_NAME)/cloud-on-k8s/pkg/about.version=$(VERSION) \
	-X $(PACKAGE_NAME)/cloud-on-k8s/pkg/about.buildHash=$(shell cd cloud-on-k8s && git rev-parse --short=8 --verify HEAD) \
	-X $(PACKAGE_NAME)/cloud-on-k8s/pkg/about.buildDate=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ') \
	-X $(PACKAGE_NAME)/cloud-on-k8s/pkg/about.buildSnapshot=false

###############################################################################
# BUILD BINARY
###############################################################################
ECK_OPERATOR_DOWNLOADED=.eck-operator.downloaded
FILES_GENERATED=.eck-operator.generated

FIPS ?= false

ifeq ($(FIPS),true)
CGO_ENABLED=1
GOEXPERIMENT=boringcrypto
TAGS=osusergo,netgo
else
CGO_ENABLED=0
endif

.PHONY: init-source
init-source: $(ECK_OPERATOR_DOWNLOADED)
$(ECK_OPERATOR_DOWNLOADED):
	mkdir -p cloud-on-k8s
	curl -sfL https://github.com/elastic/cloud-on-k8s/archive/refs/tags/$(ECK_OPERATOR_VERSION).tar.gz | tar xz --strip-components 1 -C cloud-on-k8s
	patch -d cloud-on-k8s -p1 < patches/0001-Chown-for-elasticserach-folder-recursively.patch
	patch -d cloud-on-k8s -p1 < patches/0002-Upgrade-x-net-crypto-to-v0.35.0-update-x-oauth-to-v0.patch
	touch $@

.PHONY: build
build: bin/$(ECK_OPERATOR_IMAGE)-$(ARCH)

generate: $(FILES_GENERATED)
$(FILES_GENERATED):
	$(DOCKER_RUN) -e GOARCH=amd64 -e ARCH=amd64 $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			cd cloud-on-k8s && \
			make go-generate && \
			make generate-config-file'
	touch $@

.PHONY: bin/$(ECK_OPERATOR_IMAGE)-$(ARCH)
bin/$(ECK_OPERATOR_IMAGE)-$(ARCH): register $(ECK_OPERATOR_DOWNLOADED) generate
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) -e GOEXPERIMENT=$(GOEXPERIMENT) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			cd cloud-on-k8s && \
			go build -buildvcs=false -o ../$@ -v -tags $(TAGS) -ldflags="$(LDFLAGS) -s -w" cmd/main.go'
ifeq ($(FIPS),true)
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'strings bin/eck-operator-$(ARCH) | grep '_Cfunc__goboringcrypto_' 1> /dev/null'
endif

###############################################################################
# BUILD IMAGE
###############################################################################
ECK_OPERATOR_CONTAINER_CREATED=.eck-operator.created-$(ARCH)

PHONY: $(BUILD_IMAGES)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(ECK_OPERATOR_IMAGE)

$(ECK_OPERATOR_IMAGE): $(ECK_OPERATOR_CONTAINER_CREATED)
$(ECK_OPERATOR_CONTAINER_CREATED): bin/$(ECK_OPERATOR_IMAGE)-$(ARCH)
	$(DOCKER_BUILD) -t $(ECK_OPERATOR_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

ci: image

.PHONY: cd
cd: image-all cd-common

###############################################################################
# Misc.
###############################################################################
.PHONY: clean
clean:
	rm -fr bin/ cloud-on-k8s/
	rm -f $(ECK_OPERATOR_DOWNLOADED) $(FILES_GENERATED)
	-docker image rm -f $$(docker images $(ECK_OPERATOR_IMAGE) -a -q)
