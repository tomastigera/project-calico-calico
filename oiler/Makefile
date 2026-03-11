# Copyright 2025 Tigera Inc. All rights reserved.
include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/oiler

#############################################
# Env vars related to packaging and releasing
#############################################
OILER_IMAGE	?=oiler
BUILD_IMAGES?=$(OILER_IMAGE)

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# Env vars related to building
###############################################################################
## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

###############################################################################
# BUILD BINARY
###############################################################################
# This section builds the output binaries.
build: bin/oiler-$(ARCH)

.PHONY: bin/oiler-$(ARCH)
bin/oiler-$(ARCH): $(SRC_FILES)
	$(call build_binary, cmd/$*/*.go, $@)

###############################################################################
# BUILD IMAGE
###############################################################################
OILER_CONTAINER_CREATED=.oiler.created-$(ARCH)

# Build the docker image.
.PHONY: $(BUILD_IMAGES)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(OILER_IMAGE)

$(OILER_IMAGE): $(OILER_CONTAINER_CREATED)
IMAGE_DEPS = Dockerfile
$(OILER_CONTAINER_CREATED): $(IMAGE_DEPS) bin/oiler-$(ARCH) | register
	$(DOCKER_BUILD) -t $(OILER_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean: stop-elastic
	rm -rf bin \
		report/*.xml \
		config/
	find . -name '*.coverprofile' -type f -delete
	rm -f $(OILER_CREATED)
	-docker image rm -f $$(docker images $(OILER_IMAGE) -a -q)

###############################################################################
# Testing
###############################################################################
#MOCKERY_FILE_PATHS= \
#	pkg/ \

#############################################
# Run unit level tests
#############################################
# Comma separated paths to packages containing fv tests

.PHONY: ut
## Run only Unit Tests.
ut: ut-fast

ut-fast:
	mkdir -p report
	# We run the tests n times to try and weed out test flakes.
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) gotestsum --junitfile report/tests.xml -- ./pkg/... ./cmd/... -cover -count 5'


st:
	@echo "No STs available"

###############################################################################
# FV Tests
###############################################################################

## Run the FVs
WHAT=.
fv: clean image run-elastic k8s-setup fv-fast
fv-fast: build-tests
	 cd fv && ./fv.test -test.run $(WHAT)

# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
build-tests: $(shell find ./fv -type f -name '*.go' -print)
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./fv -c --tags fvtests -o fv/fv.test'

## Perform all the necessary setup for a local Kubernetes API server used in the Oiler FVs.
k8s-setup: fv/oiler-token rbac

## Create rbac resources in Kubernetes.
rbac:
	$(DOCKER_RUN) \
		-v $(CERTS_PATH):/home/user/certs \
		-e KUBECONFIG=/home/user/certs/kubeconfig \
	       	$(CALICO_BUILD) sh -c 'kubectl create -f /go/src/$(PACKAGE_NAME)/fv/kube/rbac.yaml'


## Create a token file for use in the FV tests. This simulates the serviceaccount token provided to oiler by k8s.
fv/oiler-token: run-k8s-apiserver
	rm -f $@
	docker exec $(APISERVER_NAME) kubectl create sa tigera-oiler
	docker exec $(APISERVER_NAME) kubectl create token tigera-oiler --duration=24h > $@

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

## run CI cycle - build, test, etc.
## Run UTs and only if they pass build image and continue along.
## Building the image is required for fvs.
ci: clean static-checks build test

## Deploys images to registry
cd: image-all cd-common
