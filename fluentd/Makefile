# Copyright 2019-2024 Tigera Inc. All rights reserved.

include ../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/fluentd

FLUENTD_IMAGE ?= fluentd
WINDOWS_IMAGE ?= $(FLUENTD_IMAGE)-windows

# If this is a windows release build the windows image.  ARCHES will contain the values
# in WINDOWS_VERSIONS (defined in metadata.mk), prefixed with "windows-".
ifdef WINDOWS_RELEASE
BUILD_IMAGES ?= $(WINDOWS_IMAGE)
ARCHES ?= $(patsubst %,windows-%,$(WINDOWS_VERSIONS))
else
BUILD_IMAGES ?= $(FLUENTD_IMAGE)
endif

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

###############################################################################
# Build
###############################################################################
EKS_SRC_FILES = $(shell find eks/ -name '*.go')
EKS_VERSION_FLAGS=-X main.VERSION=$(GIT_VERSION) \
	-X main.BUILD_DATE=$(DATE) \
	-X main.GIT_TAG=$(GIT_DESCRIPTION) \
	-X main.GIT_COMMIT=$(GIT_COMMIT)

.PHONY: build
build: bin/eks-log-forwarder-startup-$(ARCH)

## build cloudwatch plugin initializer
bin/eks-log-forwarder-startup-$(ARCH): $(EKS_SRC_FILES)
	@echo "Building eks init-container executable"
	mkdir -p $(@D)
	$(DOCKER_GO_BUILD) \
	    sh -c '$(GIT_CONFIG_SSH) CGO_ENABLED=0 go build -C eks -o $@ -v -ldflags "$(EKS_VERSION_FLAGS) -s -w"'
	cp eks/$@ $@

bin/eks-log-forwarder-startup.exe: $(EKS_SRC_FILES)
	@echo "Building eks init-container executable for windows"
	mkdir -p $(@D)
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) CGO_ENABLED=0 GOARCH=amd64 GOOS=windows OS=windows go build -C eks -o $@ -v -ldflags "$(EKS_VERSION_FLAGS) -s -w"'
	cp eks/$@ $@

clean:
	rm -rf eks/bin Makefile.common*
	-docker image rm -f $$(docker images $(FLUENTD_IMAGE) -a -q)
	rm -rf bin
	rm -rf dist

###############################################################################
# Image
###############################################################################
FLUENTD_IMAGE_CREATED=.fluentd.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES)) 
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(FLUENTD_IMAGE)

$(FLUENTD_IMAGE): $(FLUENTD_IMAGE_CREATED)
$(FLUENTD_IMAGE_CREATED): Dockerfile bin/eks-log-forwarder-startup-$(ARCH)
	$(DOCKER_BUILD) --build-arg THIRD_PARTY_REGISTRY=$(THIRD_PARTY_REGISTRY) -t $(FLUENTD_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

WINDOWS_IMAGE_REQS := Dockerfile-windows bin/eks-log-forwarder-startup.exe
image-windows: $(WINDOWS_IMAGE_REQS)

###############################################################################
# CI/CD
###############################################################################
ifdef UNIT_TESTS
	UNIT_TEST_FLAGS=-run $(UNIT_TESTS) -v
endif

## test cloudwatch plugin initializer
ut: bin/eks-log-forwarder-startup-$(ARCH)
ifeq ($(ARCH),amd64)
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go test -C eks $(UNIT_TEST_FLAGS)'
endif

st:

## fluentd config tests
fv: image
ifeq ($(ARCH),amd64)
	cd test && IMAGETAG=latest-$(ARCH) IMAGE=tigera/$(FLUENTD_IMAGE) ./test.sh
endif

ci: test image

## push fluentd image to GCR_REPO.
#  Note: this is called from both Linux and Windows so ARCH_TAG is required.
cd: image-all cd-common
