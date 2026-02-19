include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/pod2daemon

# Name of the images.
# e.g., <registry>/<name>:<tag>
FLEXVOL_IMAGE   ?=pod2daemon-flexvol
CSI_IMAGE       ?=csi
REGISTRAR_IMAGE ?=node-driver-registrar
BUILD_IMAGES    ?=$(FLEXVOL_IMAGE) $(CSI_IMAGE) $(REGISTRAR_IMAGE)

###############################################################################
# Download and include ../lib.Makefile before anything else
###############################################################################
include ../lib.Makefile

###############################################################################


SRC_FILES=$(shell find -name '*.go')

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf report/
	rm -rf bin/flexvol-$(ARCH)
	rm -rf bin/$(CSI_IMAGE)-$(ARCH)
	rm -rf bin/$(REGISTRAR_IMAGE)-$(ARCH)
	rm -rf bin

	-docker image rm -f $$(docker images $(CSI_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(FLEXVOL_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(REGISTRAR_IMAGE) -a -q)

	$(MAKE) clean-registrar

###############################################################################
# Building the binary
###############################################################################
FIPS ?= false

FLEXVOL_CONTAINER_MARKER=$(FLEXVOL_CONTAINER_CREATED)
ifeq ($(FIPS),true)
CSI_CONTAINER_MARKER=$(CSI_CONTAINER_FIPS_CREATED)
REGISTRAR_CONTAINER_MARKER=$(REGISTRAR_CONTAINER_FIPS_CREATED)
VALIDARCHES=amd64
BINDIR=bin/$(ARCH)-fips
else
CSI_CONTAINER_MARKER=$(CSI_CONTAINER_CREATED)
REGISTRAR_CONTAINER_MARKER=$(REGISTRAR_CONTAINER_CREATED)
BINDIR=bin
endif

.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/flexvol-,$(VALIDARCHES)) $(addprefix $(BINDIR)/csi-driver-,$(VALIDARCHES)) $(addprefix $(BINDIR)/node-driver-registrar-,$(VALIDARCHES))

.PHONY: build
## Build the binary for the current architecture and platform
build: $(BINDIR)/node-driver-registrar-$(ARCH) bin/flexvol-$(ARCH) $(BINDIR)/csi-driver-$(ARCH)

# We need CGO to leverage Boring SSL.  However, pod2daemon doesn't perform any crypto,
# so we can disable it across the board.
bin/flexvol-amd64: ARCH=amd64
bin/flexvol-arm64: ARCH=arm64
bin/flexvol-%: $(SRC_FILES)
	$(call build_binary, flexvol/flexvoldriver.go, $@)

$(BINDIR)/csi-driver-amd64: ARCH=amd64
$(BINDIR)/csi-driver-arm64: ARCH=arm64
$(BINDIR)/csi-driver-%: $(SRC_FILES)
	$(call build_binary, csidriver/main.go, $@)

protobuf proto/udsver.pb.go: proto/udsver.proto
	$(DOCKER_RUN) -v $(CURDIR)/proto:/proto:rw \
		$(CALICO_BUILD) sh -c 'protoc --proto_path=/proto --go_out=/proto --go-grpc_out=. --go_opt=paths=source_relative udsver.proto'
	# Make sure the generated code won't cause a static-checks failure.
	$(MAKE) fix-changed

UPSTREAM_REGISTRAR_PROJECT ?= kubernetes-csi/$(REGISTRAR_IMAGE)
UPSTREAM_REGISTRAR_TAG     ?= f0fd46fc3fbdb6fe20fc2d2614631816b551a143 #https://github.com/kubernetes-csi/node-driver-registrar/commit/f0fd46fc3fbdb6fe20fc2d2614631816b551a143

REGISTRAR_TIGERA_BUILD_CMD="cd /go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT) && \
	go build -tags $(TAGS) -buildvcs=false -v -o $(BINDIR)/csi-node-driver-registrar cmd/csi-node-driver-registrar/*.go"
REGISTRAR_UPSTREAM_BUILD_CMD="cd /go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT) && make build BUILD_PLATFORMS=$(BUILD_PLATFORMS)"

ifeq ($(ARCH), $(filter $(ARCH),amd64))
# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)
CGO_ENABLED=1
ifeq ($(FIPS),true)
TAGS=fipsstrict
GOEXPERIMENT=boringcrypto
else
GOEXPERIMENT=""
endif
else ifeq ($(ARCH), $(filter $(ARCH),arm64))
CGO_ENABLED=0
REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)

else ifeq ($(ARCH), $(filter $(ARCH),win64))
# Note: We must use single quotes on BUILD_PLATFORMS since it is to be nested within another double-quoted string.
BUILD_PLATFORMS='windows amd64 amd64'
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
endif

$(BINDIR)/node-driver-registrar-%: clone-registrar-upstream
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) -e GOEXPERIMENT=$(GOEXPERIMENT) \
			-v $(REPO_ROOT)/pod2daemon/$(REGISTRAR_IMAGE):/go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT):rw \
			$(CALICO_BUILD) \
			/bin/bash -c $(REGISTRAR_BUILD_CMD)
			mv $(REGISTRAR_IMAGE)/$(BINDIR)/csi-node-driver-registrar $@

clone-registrar-upstream:
ifeq ("$(wildcard ./$(REGISTRAR_IMAGE))", "")
	@echo "Directory does not exist."
	git clone --depth 1 --single-branch https://github.com/$(UPSTREAM_REGISTRAR_PROJECT).git
else
	@echo "Upstream repo already cloned."
endif
	cd $(REGISTRAR_IMAGE) && \
	  git checkout $(UPSTREAM_REGISTRAR_TAG) || \
	  git fetch --tags origin $(UPSTREAM_REGISTRAR_TAG) && \
	  git checkout $(UPSTREAM_REGISTRAR_TAG)
	rm -rf ./$(REGISTRAR_IMAGE)/vendor

clean-registrar:
	rm -rf ./$(REGISTRAR_IMAGE)

###############################################################################
# Building the image
###############################################################################
FLEXVOL_CONTAINER_CREATED=.pod2daemon-flexvol.created-$(ARCH)
CSI_CONTAINER_CREATED=.calico-csi.created-$(ARCH)
REGISTRAR_CONTAINER_CREATED=.csi-registrar.created-$(ARCH)
CSI_CONTAINER_FIPS_CREATED=.calico-csi.created-$(ARCH)-fips
REGISTRAR_CONTAINER_FIPS_CREATED=.csi-registrar.created-$(ARCH)-fips

.PHONY: image calico/pod2daemon-flexvol
image: $(FLEXVOL_IMAGE) $(CSI_IMAGE) $(REGISTRAR_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image FIPS=$(FIPS) ARCH=$*

$(FLEXVOL_IMAGE): $(FLEXVOL_CONTAINER_MARKER)
$(FLEXVOL_CONTAINER_CREATED): flexvol/docker-image/Dockerfile bin/flexvol-$(ARCH)
	cp ../LICENSE.md bin/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=bin -t $(FLEXVOL_IMAGE):latest-$(ARCH) -f flexvol/docker-image/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(FLEXVOL_IMAGE)
	touch $@

$(CSI_IMAGE): $(CSI_CONTAINER_MARKER)
$(CSI_CONTAINER_CREATED): csidriver/Dockerfile $(BINDIR)/csi-driver-$(ARCH)
	cp ../LICENSE.md $(BINDIR)/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(CSI_IMAGE):latest-$(ARCH) -f csidriver/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(CSI_IMAGE)
	touch $@

$(CSI_CONTAINER_FIPS_CREATED): csidriver/Dockerfile $(BINDIR)/csi-driver-$(ARCH)
	cp ../LICENSE.md $(BINDIR)/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(CSI_IMAGE):latest-fips-$(ARCH) -f csidriver/Dockerfile .
	$(MAKE) FIPS=true retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips BUILD_IMAGES=$(CSI_IMAGE) LATEST_IMAGE_TAG=latest-fips
	touch $@

$(REGISTRAR_IMAGE): $(REGISTRAR_CONTAINER_MARKER)
$(REGISTRAR_CONTAINER_CREATED): node-driver-registrar-docker/Dockerfile $(BINDIR)/node-driver-registrar-$(ARCH)
	cp ../LICENSE.md $(BINDIR)/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) --build-arg UPSTREAM_VER=$(UPSTREAM_REGISTRAR_TAG) -t $(REGISTRAR_IMAGE):latest-$(ARCH) -f node-driver-registrar-docker/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(REGISTRAR_IMAGE)
	touch $@

$(REGISTRAR_CONTAINER_FIPS_CREATED): node-driver-registrar-docker/Dockerfile $(BINDIR)/node-driver-registrar-$(ARCH)
	cp ../LICENSE.md $(BINDIR)/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) --build-arg UPSTREAM_VER=$(UPSTREAM_REGISTRAR_TAG) -t $(REGISTRAR_IMAGE):latest-fips-$(ARCH) -f node-driver-registrar-docker/Dockerfile .
	$(MAKE) FIPS=true retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips BUILD_IMAGES=$(REGISTRAR_IMAGE) LATEST_IMAGE_TAG=latest-fips
	touch $@

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev
ut: $(SRC_FILES)
	mkdir -p report
	$(DOCKER_RUN) --privileged $(CALICO_BUILD) sh -c 'set -o pipefail && cd /go/src/$(PACKAGE_NAME) && go test -v ./... | go-junit-report > ./report/tests.xml'

fv st:
	@echo "No FVs or STs available"

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean clean-registrar static-checks image ut

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd: image-all cd-common
