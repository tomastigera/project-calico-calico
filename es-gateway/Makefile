include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/es-gateway

###############################################################################
# Env vars related to building
###############################################################################
SRC_FILES        = $(shell find pkg cmd -name '*.go') $(shell find ../libcalico-go/lib/logutils -name '*.go')
ES_GATEWAY_IMAGE ?=es-gateway
BUILD_IMAGES     ?=$(ES_GATEWAY_IMAGE)

###############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# BUILD BINARY
###############################################################################
# This section builds the output binaries.
build: bin/es-gateway-$(ARCH)

.PHONY: bin/es-gateway-$(ARCH)
bin/es-gateway-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd, $@)
else
	$(call build_binary, ./cmd, $@)
endif

###############################################################################
# Building the image
###############################################################################
ES_GATEWAY_CONTAINER_CREATED=.es-gateway.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(ES_GATEWAY_IMAGE)

$(ES_GATEWAY_IMAGE): $(ES_GATEWAY_CONTAINER_CREATED)
$(ES_GATEWAY_CONTAINER_CREATED): Dockerfile bin/es-gateway-$(ARCH)
	$(DOCKER_BUILD) -t $(ES_GATEWAY_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean: stop-elastic
	rm -rf bin
	rm -f $(ES_GATEWAY_CONTAINER_CREATED)
	-docker image rm -f $$(docker images $(ES_GATEWAY_IMAGE) -a -q)

###############################################################################
# Testing
###############################################################################
GINKGO_ARGS += -cover -timeout 20m
GINKGO = ginkgo $(GINKGO_ARGS)

#############################################
# Run unit level tests
#############################################

.PHONY: ut
## Run only Unit Tests.
ut:
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) $(GINKGO) pkg/*'

# Disable challenger tests

# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
#build-tests: $(shell find ./fv -type f -name '*.go' -print)
#	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./fv -c --tags fvtests -o fv/fv.test'

#WHAT=.
#fv: clean image run-elastic fv-fast
#fv-fast: build-tests
#	 cd fv && ./fv.test -test.run $(WHAT)

st:
	echo "ST tests not available"
###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

## run CI cycle - build, test, etc.
## Run UTs and only if they pass build image and continue along.
## Building the image is required for fvs.
ci: clean static-checks image test

## Deploys images to registry
cd: image-all cd-common
