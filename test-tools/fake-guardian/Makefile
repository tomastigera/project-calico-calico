include ../../metadata.mk

PACKAGE_NAME?=github.com/projectcalico/calico/test-tools/fake-guardian

IMAGE_NAME  ?=fake-guardian
BUILD_IMAGES          ?=$(IMAGE_NAME)

###############################################################################
# Shortcut targets
###############################################################################
default: build image
test: ut ## Run the tests for the current platform/architecture

###############################################################################
# Variables controlling the image
###############################################################################
IMAGE_CREATED=.container.created-$(ARCH)
# Files to be built
SRC_FILES=$(shell find . -name '*.go')

CONTROLLER_RUNTIME_VERSION=v0.19.0
K8S_VERSION=1.29.5

###############################################################################
# Include ../../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../../lib.Makefile

###############################################################################
## Clean enough that a new release build will be clean
###############################################################################
.PHONY: clean
clean:
	rm -rf bin
	rm -f $(IMAGE_CREATED)
	find . -name '*.pyc' -delete
	-docker image rm -f $$(docker images $(IMAGE_NAME) -a -q)

###############################################################################
# Building the binary
###############################################################################

LDFLAGS = -X main.VERSION=$(GIT_VERSION)

.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/fake-guardian-,$(VALIDARCHES))

.PHONY: build
## Build the binary for the current architecture and platform
build: bin/fake-guardian-$(ARCH)
bin/fake-guardian-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./cmd/fake-guardian, $@)

###############################################################################
# Building the image
###############################################################################
## Create the image for the current ARCH
image: $(IMAGE_NAME)

## Create the images for all supported ARCHes
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(IMAGE_NAME): $(IMAGE_CREATED)
$(IMAGE_CREATED): register Dockerfile bin/fake-guardian-$(ARCH)
	$(DOCKER_BUILD) --build-arg CONTROLLER_RUNTIME_VERSION=$(CONTROLLER_RUNTIME_VERSION) --build-arg K8S_VERSION=$(K8S_VERSION) -t $(IMAGE_NAME):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

## Run the tests in a container. Useful for CI, Mac dev
ut:
	echo "Currently has no UT tests."

fv:
	echo "Currently has no FV tests."

st:
	echo "Currently has no STs."

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: clean static-checks image test
## Deploys images to registry
cd: image-all cd-common
