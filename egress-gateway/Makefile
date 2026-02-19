include ../metadata.mk

PACKAGE_NAME?=github.com/projectcalico/calico/egress-gateway

EGRESS_GATEWAY_IMAGE  ?=egress-gateway
BUILD_IMAGES          ?=$(EGRESS_GATEWAY_IMAGE)

###############################################################################
# Shortcut targets
###############################################################################
default: build image
test: ut ## Run the tests for the current platform/architecture

###############################################################################
# Variables controlling the image
###############################################################################
GATEWAY_CONTAINER_CREATED=.egress_gateway.created-$(ARCH)
# Files that go into the image
GATEWAY_DAEMON_EXECUTABLE=./bin/egressd-$(ARCH)
# Files to be built
SRC_FILES=$(shell find . -name '*.go' | grep -v vendor) ../felix/proto/felixbackend.pb.go $(shell find ../libcalico-go -name '*.go' | grep -v vendor)

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
## Clean enough that a new release build will be clean
###############################################################################
.PHONY: clean
clean:
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.created-$(ARCH)' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf .go-pkg-cache bin Makefile.common*
	rm -rf certs *.tar
	rm -rf dist
	rm -rf Makefile.common*
	# Delete images that we built in this repo
	-docker rmi $(EGRESS_GATEWAY_IMAGE):latest-$(ARCH)

###############################################################################
# Protobufs, defer to felix's makefile.
###############################################################################

protobuf ../felix/proto/felixbackend.pb.go: ../felix/proto/felixbackend.proto
	$(MAKE) --directory ../felix protobuf

###############################################################################
# Building the binary
###############################################################################

.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/egressd-,$(VALIDARCHES))

.PHONY: build
## Build the binary for the current architecture and platform
build: bin/egressd-$(ARCH)
bin/egressd-amd64: ARCH=amd64
bin/egressd-arm64: ARCH=arm64
bin/egressd-%: $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/egressd, $@)
else
	$(call build_binary, ./cmd/egressd, $@)
endif

###############################################################################
# Building the image
###############################################################################
## Create the image for the current ARCH
image: $(EGRESS_GATEWAY_IMAGE)

## Create the images for all supported ARCHes
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(EGRESS_GATEWAY_IMAGE): $(GATEWAY_CONTAINER_CREATED)
$(GATEWAY_CONTAINER_CREATED): Dockerfile $(GATEWAY_DAEMON_EXECUTABLE) init-gateway.sh
	$(DOCKER_BUILD) -t $(EGRESS_GATEWAY_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

## Run the tests in a container. Useful for CI, Mac dev
ut: ../felix/proto/felixbackend.pb.go
	mkdir -p report
	$(DOCKER_RUN) $(CALICO_BUILD) /bin/bash -c "$(GIT_CONFIG_SSH) go test -v $(GOTEST_ARGS) ./..."

fv:
	echo "egress-gateway currently has no FV tests."

st:
	echo "egress-gateway ST tests are currently in the node 'k8st' framework."
	echo "To run them: make --directory ../node egress-ip-tests"

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: clean static-checks image test
## Deploys images to registry
cd: image-all cd-common
