##############################################################################
# Copyright 2019-2022 Tigera Inc. All rights reserved.
##############################################################################
include ../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/queryserver

#############################################
# Env vars related to packaging and releasing
#############################################
QUERYSERVER_IMAGE ?=queryserver
BUILD_IMAGES      ?=$(QUERYSERVER_IMAGE)

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# Env vars related to building
###############################################################################
# All queryserver Go source files.
SRC_FILES = $(shell find queryserver pkg -type f -name '*.go') \
		$(shell find ../api/pkg -name '*.go') \
		$(shell find ../calicoctl -name '*.go') \
		$(shell find ../felix -name '*.go') \
		$(shell find ../lma/pkg -name '*.go') \
		$(shell find ../libcalico-go/lib -name '*.go') \
		$(shell find ../licensing/client -name '*.go')

###############################################################################
# BUILD BINARY
###############################################################################
# This section builds the output binaries.
build: bin/queryserver-$(ARCH)

.PHONY: bin/queryserver-$(ARCH)
bin/queryserver-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, queryserver/$*/*.go, $@)
else
	$(call build_binary, queryserver/$*/*.go, $@)
endif

###############################################################################
# BUILD IMAGE
###############################################################################
QUERYSERVER_CONTAINER_CREATED=.queryserver.created-$(ARCH)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(QUERYSERVER_IMAGE)

$(QUERYSERVER_IMAGE): $(QUERYSERVER_CONTAINER_CREATED)
$(QUERYSERVER_CONTAINER_CREATED): Dockerfile bin/queryserver-$(ARCH)
	$(DOCKER_BUILD) -t $(QUERYSERVER_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean:
	rm -rf bin
	rm -f $(QUERYSERVER_CONTAINER_CREATED)
	-docker image rm -f $$(docker images $(QUERYSERVER_IMAGE) -a -q)

###############################################################################
# Testing
###############################################################################
.PHONY: ut
ut: run-etcd
	mkdir -p report
	$(DOCKER_RUN) $(CALICO_BUILD) ./run-uts

.PHONY: fv
fv: run-etcd
	$(DOCKER_RUN) $(CALICO_BUILD) ./run-fvs

# Mocks auto generated testify mocks by mockery. Run `make gen-mocks` to regenerate the testify mocks.
MOCKERY_FILE_PATHS= \
	pkg/querycache/client/QueryInterface

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean static-checks image ut fv

## Deploys images to registry
cd: image-all cd-common
