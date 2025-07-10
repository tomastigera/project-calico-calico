include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/app-policy

###############################################################################

GENERATED_FILES=../felix/proto/felixbackend.pb.go
SRC_FILES=$(shell find . -name '*.go' |grep -v vendor) $(GENERATED_FILES)

# Name of the images.
# e.g., <registry>/<name>:<tag>
DIKASTES_IMAGE ?=dikastes
BUILD_IMAGES ?= $(DIKASTES_IMAGE)

LDFLAGS = -X main.VERSION=$(GIT_VERSION)

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
	rm -rf bin report
	rm -f $(MMDB_FILES)
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
.PHONY: image $(DIKASTES_IMAGE)
image: $(DIKASTES_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image FIPS=$(FIPS) ARCH=$*

$(DIKASTES_IMAGE): $(CONTAINER_MARKER)
$(CONTAINER_CREATED): mmdb Dockerfile $(BINDIR)/dikastes-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(DIKASTES_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

$(CONTAINER_FIPS_CREATED): Dockerfile $(BINDIR)/dikastes-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(DIKASTES_IMAGE):latest-fips-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

bin/LICENSE: ../LICENSE.md
	cp ../LICENSE.md $@
###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev
ut: mmdb protobuf ut-exec

ut-exec:
	$(DOCKER_GO_BUILD) sh -c "gotestsum --junitfile report/tests.xml -- -count 1 ./..."


###############################################################################
# CI
###############################################################################

.PHONY: ci
ci: check-generated-files image ut static-checks

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

###############################################################################
MMDB_DIR=./bin/database
MMDB_SRC_URL=https://download.db-ip.com/free/dbip-city-lite-2025-06.mmdb.gz
MMDB_FILES=$(MMDB_DIR)/dbip-city-lite.mmdb
$(MMDB_FILES):
	@echo "[INFO] Downloading MMDB from DB-IP.com (city) $@ ..."
	mkdir -p $(MMDB_DIR)
	wget -O $(MMDB_DIR)/dbip-city-lite.mmdb.gz $(MMDB_SRC_URL)
	gzip --force -d $(MMDB_DIR)/dbip-city-lite.mmdb.gz
	cp $(MMDB_DIR)/dbip-city-lite.mmdb ./internal/testdata/geoip/

.PHONY: mmdb
mmdb: $(MMDB_FILES)
