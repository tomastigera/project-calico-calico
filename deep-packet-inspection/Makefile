# Copyright 2021-2022 Tigera Inc. All rights reserved.
include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/deep-packet-inspection

#############################################
# Env vars related to packaging and releasing
#############################################
DEEP_PACKET_INSPECTION_IMAGE	?=deep-packet-inspection
BUILD_IMAGES			?=$(DEEP_PACKET_INSPECTION_IMAGE)

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# Env vars related to building
###############################################################################
SRC_FILES = $(shell find pkg cmd -name '*.go') \
		$(shell find ../api/pkg -name '*.go') \
		$(shell find ../libcalico-go/lib -name '*.go') \
		$(shell find ../linseed/pkg -name '*.go') \
		$(shell find ../typha/pkg -name '*.go')

###############################################################################
# BUILD BINARY
###############################################################################

# This section builds the output binaries.
build: bin/deep-packet-inspection-$(ARCH)

.PHONY: bin/deep-packet-inspection-$(ARCH)
bin/deep-packet-inspection-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/*.go, $@)
else
	$(call build_binary, cmd/*.go, $@)
endif

###############################################################################
# BUILD IMAGE
###############################################################################
DEEP_PACKET_INSPECTION_IMAGE_CREATED=.deep-packet-inspection.created-$(ARCH)

# Build the docker image.
.PHONY: $(BUILD_IMAGES)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(DEEP_PACKET_INSPECTION_IMAGE)

$(DEEP_PACKET_INSPECTION_IMAGE): $(DEEP_PACKET_INSPECTION_IMAGE_CREATED)
$(DEEP_PACKET_INSPECTION_IMAGE_CREATED): Dockerfile bin/deep-packet-inspection-$(ARCH)
	$(DOCKER_BUILD_THIRD_PARTY) -t $(DEEP_PACKET_INSPECTION_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean:
	rm -rf bin \
		report/*.xml \
		config/
	find . -name '*.coverprofile' -type f -delete
	rm -f $(DEEP_PACKET_INSPECTION_IMAGE_CREATED)
	-docker image rm -f $$(docker images $(DEEP_PACKET_INSPECTION_IMAGE) -a -q)

###############################################################################
# Testing
###############################################################################
MOCKERY_FILE_PATHS= \
	pkg/processor/Processor \
	pkg/exec/Exec \
	pkg/dispatcher/Dispatcher \
	pkg/eventgenerator/EventGenerator \
	pkg/alert/Forwarder \
	pkg/dpiupdater/DPIStatusUpdater \
	pkg/file/FileMaintainer

GINKGO_ARGS += -cover -timeout 20m
GINKGO = ginkgo $(GINKGO_ARGS)

#############################################
# Run unit level tests
#############################################
# Comma separated paths to packages containing fv tests
FV_PACKAGE=pkg/syncer

.PHONY: ut
## Run only Unit Tests.
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) $(GINKGO) --junit-report=deep-packet-inspection_ut.xml --output-dir=report/ -r --skip-package=$(FV_PACKAGE) pkg/*'


###############################################################################
# FV Tests
###############################################################################
FV_GINKGO_FOCUS?=Syncer

## Run the ginkgo FVs
fv: run-k8s-apiserver
	 $(DOCKER_RUN) \
	 	-e KUBECONFIG=/home/user/certs/kubeconfig \
		-v $(CERTS_PATH):/home/user/certs \
	 	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 $(CALICO_BUILD) \
		 sh -c '$(GIT_CONFIG_SSH) ginkgo --focus="$(FV_GINKGO_FOCUS)" $(GINKGO_ARGS) ./$(FV_PACKAGE)/'

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

## run CI cycle - build, test, etc.
## Run UTs and only if they pass build image and continue along.
## Building the image is required for fvs.
ci: clean static-checks image ut fv

## Deploys images to registry
cd: image-all cd-common
