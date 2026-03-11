include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/l7-admission-controller

###############################################################################

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

# Name of the images.
# e.g., <registry>/<name>:<tag>
L7_ADMISSION_CONTROLLER_IMAGE ?=l7-admission-controller
BUILD_IMAGES ?= $(L7_ADMISSION_CONTROLLER_IMAGE)

LDFLAGS = -X main.VERSION=$(GIT_VERSION)

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf bin report
	-docker image rm -f $$(docker images $(L7_ADMISSION_CONTROLLER_IMAGE) -a -q)

###############################################################################
# Building the binary
###############################################################################
.PHONY: build
build: bin/l7-admission-controller-$(ARCH)

bin/l7-admission-controller-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./cmd/l7-admission-controller, $@)

###############################################################################
# Building the image
###############################################################################
L7_ADMISSION_CONTROLLER_IMAGE_CREATED=.l7-admission-controller.created-$(ARCH)

image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image $(L7_ADMISSION_CONTROLLER_IMAGE)
image: $(L7_ADMISSION_CONTROLLER_IMAGE)

$(L7_ADMISSION_CONTROLLER_IMAGE): $(L7_ADMISSION_CONTROLLER_IMAGE_CREATED)
IMAGE_DEPS = Dockerfile
$(L7_ADMISSION_CONTROLLER_IMAGE_CREATED): $(IMAGE_DEPS) bin/l7-admission-controller-$(ARCH) | register
	$(DOCKER_BUILD) -t $(L7_ADMISSION_CONTROLLER_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# UTs
###############################################################################
.PHONY: ut
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) sh -c 'gotestsum --junitfile report/tests.xml -- -v ./... -cover -count 1'

###############################################################################
# CI
###############################################################################

.PHONY: ci
ci: clean static-checks image ut

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd: image-all cd-common
