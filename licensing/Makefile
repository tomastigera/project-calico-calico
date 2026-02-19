include ../metadata.mk

PACKAGE_NAME?=github.com/projectcalico/calico/licensing

CARROTCTL_IMAGE       ?=tigera/carrotctl
BUILD_IMAGES          ?=$(CARROTCTL_IMAGE)

###############################################################################
# Include ../lib.Makefile before anything else
###############################################################################
include ../lib.Makefile

###############################################################################

CARROTCTL_DIR=carrotctl
SRC_FILES=$(shell find $(CARROTCTL_DIR) -name '*.go')

CARROTCTL_VERSION?=$(shell git describe --tags --dirty --always)
CARROTCTL_GIT_REVISION?=$(shell git rev-parse --short HEAD)
CARROTCTL_BUILD_DATE?=$(shell date -u +'%FT%T%z')

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	find . -name '*.created-$(ARCH)' -exec rm -f {} +
	rm -rf bin build certs *.tar report/
	docker rmi $(CARROTCTL_IMAGE):latest-$(ARCH) || true
	docker rmi $(CARROTCTL_IMAGE):$(VERSION)-$(ARCH) || true
ifeq ($(ARCH),amd64)
	docker rmi $(CARROTCTL_IMAGE):latest || true
	docker rmi $(CARROTCTL_IMAGE):$(VERSION) || true
endif

###############################################################################
# Building the binary
###############################################################################
LOCAL_DOCKER_ARGS := -i -e ARCH=$(ARCH) -e CARROTCTL_VERSION=$(CARROTCTL_VERSION) \
	                -e CARROTCTL_BUILD_DATE=$(CARROTCTL_BUILD_DATE) \
	                -e CARROTCTL_GIT_REVISION=$(CARROTCTL_GIT_REVISION) \
	                -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin

.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/carrotctl-linux-,$(VALIDARCHES)) bin/carrotctl-windows-amd64.exe bin/carrotctl-darwin-amd64

.PHONY: build
## Build the binary for the current architecture and platform
build: bin/carrotctl-$(BUILDOS)-$(ARCH)

# The supported different binary names. For each, ensure that an BUILDOS and ARCH is set
bin/carrotctl-%-amd64: ARCH=amd64
bin/carrotctl-%-arm64: ARCH=arm64
bin/carrotctl-darwin-amd64: BUILDOS=darwin
bin/carrotctl-windows-amd64: BUILDOS=windows
bin/carrotctl-linux-%: BUILDOS=linux

bin/carrotctl-%: $(SRC_FILES)
	$(DOCKER_RUN) $(LOCAL_DOCKER_ARGS) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
	    go build -v -o bin/carrotctl-$(BUILDOS)-$(ARCH) -ldflags "$(LDFLAGS) -s -w" "$(CARROTCTL_DIR)/carrotctl.go"'

.PHONY: calico/carrotctl
# Overrides for the binaries that need different output names
bin/carrotctl: bin/carrotctl-linux-amd64
	cp $< $@
bin/carrotctl-windows-amd64.exe: bin/carrotctl-windows-amd64
	mv $< $@

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev.
ut: $(SRC_FILES)
	mkdir -p report
	$(DOCKER_GO_BUILD) /bin/bash -c "$(GIT_CONFIG_SSH) go test -v ./... | go-junit-report > ./report/tests.xml"
	cat ./report/tests.xml
	@! grep '<failure' ./report/tests.xml

fv st:
	@echo "No FVs or STs available"

ci: clean static-checks build test
