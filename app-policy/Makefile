include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/app-policy

###############################################################################

GENERATED_FILES=../felix/proto/felixbackend.pb.go
SRC_FILES=$(shell find . -name '*.go' |grep -v vendor) $(GENERATED_FILES)

# Name of the images.
# e.g., <registry>/<name>:<tag>
DIKASTES_IMAGE ?=dikastes
BUILD_IMAGES ?= $(DIKASTES_IMAGE)

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

CONTAINER_CREATED=.image.created-$(ARCH)
CONTAINER_FIPS_CREATED=.image.created-$(ARCH)-fips

FIPS ?= false

ifeq ($(FIPS),true)
CONTAINER_MARKER=$(CONTAINER_FIPS_CREATED)
VALIDARCHES=amd64
BINDIR=bin/$(ARCH)-fips
else
CONTAINER_MARKER=$(CONTAINER_CREATED)
BINDIR=bin
endif

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
	rm -rf bin report geoip
	-docker image rm -f $$(docker images $(DIKASTES_IMAGE) -a -q)

.PHONY: clean-generated
# Delete (checked-in) generated files. Intentionally not part of the main clean target since these files are
# checked in and deleting them makes the repo "dirty" as far as git is concerned.
clean-generated:
	rm -rf $(GENERATED_FILES)

###############################################################################
# Building the binary
###############################################################################
.PHONY: build-all
## Build the binaries for all architectures and platforms
$(VALIDARCHES):
	$(MAKE) build ARCH=$@

build-all: $(VALIDARCHES)

.PHONY: build
## Build the binary for the current architecture and platform
build:
	$(MAKE) $(BINDIR)/dikastes-$(ARCH) ARCH=$(ARCH)

$(BINDIR)/dikastes-amd64: ARCH=amd64
$(BINDIR)/dikastes-arm64: ARCH=arm64
$(BINDIR)/dikastes-%: protobuf $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/dikastes, $@)
else
	$(call build_cgo_binary, ./cmd/dikastes, $@)
endif


###############################################################################
# Protobufs,
#
# defer to felix's makefile for felixbackend stuff
###############################################################################

../felix/proto/felixbackend.pb.go: ../felix/proto/felixbackend.proto
	$(MAKE) --directory ../felix protobuf

protobuf: $(GENERATED_FILES)

###############################################################################
# Building the image
###############################################################################
# Look for city-lite release filename pattern: dbip-city-lite-YYYY-MM.mmdb.gz.
# The Semaphore pipeline caches this file to avoid repeated downloads.
# .DELETE_ON_ERROR ensures partial/corrupt files are removed on failure.
.DELETE_ON_ERROR: geoip/dbip-city-lite.mmdb
geoip/dbip-city-lite.mmdb:
	mkdir -p geoip
	$(eval MMDB_RELEASE=$(shell curl -s https://db-ip.com/db/download/ip-to-city-lite | grep -o 'dbip-city-lite-[0-9]\{4\}-[0-9]\{2\}.mmdb.gz'))
	curl -sfL https://download.db-ip.com/free/$(MMDB_RELEASE) | zcat > geoip/dbip-city-lite.mmdb

.PHONY: image $(DIKASTES_IMAGE)
image: $(DIKASTES_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image FIPS=$(FIPS) ARCH=$*

$(DIKASTES_IMAGE): $(CONTAINER_MARKER)
$(CONTAINER_CREATED): geoip/dbip-city-lite.mmdb Dockerfile $(BINDIR)/dikastes-$(ARCH)
	$(DOCKER_BUILD) --build-arg BINDIR=$(BINDIR) -t $(DIKASTES_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

$(CONTAINER_FIPS_CREATED): geoip/dbip-city-lite.mmdb Dockerfile $(BINDIR)/dikastes-$(ARCH)
	$(DOCKER_BUILD) --build-arg BINDIR=$(BINDIR) -t $(DIKASTES_IMAGE):latest-fips-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

bin/LICENSE: ../LICENSE.md
	cp ../LICENSE.md $@
###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev
ut: geoip/dbip-city-lite.mmdb protobuf ut-exec

ut-exec:
	mkdir -p report
	$(DOCKER_GO_BUILD) sh -c "gotestsum --junitfile report/app_policy_ut.xml -- -count 1 ./..."


###############################################################################
# CI
###############################################################################

.PHONY: ci
ci: check-generated-files static-checks image ut

## Check if generated files are out of date
.PHONY: check-generated-files
check-generated-files:
	$(MAKE) clean
	$(MAKE) protobuf
	if (git describe --tags --dirty | grep -c dirty >/dev/null); then \
	  echo "Generated files are out of date."; \
	  git diff; \
	  false; \
	else \
	  echo "Generated files are up to date."; \
	fi

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd: image-all cd-common
