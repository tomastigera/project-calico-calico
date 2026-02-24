include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/hack/cub-generator

LOCAL_CHECKS = goimports check-gen-files

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../../lib.Makefile

###############################################################################

###############################################################################
# Env vars related to building
###############################################################################
SRC_FILES = $(shell find pkg cmd -name '*.go')

###############################################################################
# BUILD BINARY
###############################################################################
# This section builds the output binaries.
build: bin/cub-generator-$(ARCH)

.PHONY: bin/cub-generator-$(ARCH)
bin/cub-generator-$(ARCH): $(SRC_FILES)
	$(call build_binary, cmd/$*/*.go, $@)

###############################################################################
# Tests
###############################################################################
WHAT?=.
GINKGO_FOCUS?=.*

.PHONY:ut
## Run the fast set of unit tests in a container.
ut:
	$(DOCKER_RUN) --privileged $(CALICO_BUILD) \
		sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r --focus="$(GINKGO_FOCUS)" $(WHAT)'

.PHONY:fv
fv:
	@echo "No FVs available"

st:
	@echo "No STs available"

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean static-checks build test
