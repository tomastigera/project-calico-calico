###############################################################################
# Istio Component Makefile
# Builds the Istio install-cni and pilot-discovery components
###############################################################################
include ../../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/istio/istio

# Image names matching the prior tigera/istio repository convention
ISTIO_CNI_IMAGE ?= istio-install-cni
ISTIO_PILOT_IMAGE ?= istio-pilot
BUILD_IMAGES ?= $(ISTIO_CNI_IMAGE) $(ISTIO_PILOT_IMAGE)

# Upstream version (configurable)
ISTIO_VERSION ?= 1.27.3
# Commit SHA for version verification (ensures reproducibility and detects upstream tag changes)
# To update: git ls-remote https://github.com/istio/istio.git refs/tags/1.27.3^{}
ISTIO_GIT_SHA ?= df538c2279a633544e6c0961a03ab772729933be

# Git commit for image tagging
GIT_COMMIT := $(shell git rev-parse HEAD || echo '<unknown>')
GIT_COMMIT_SHORTER := $(shell git rev-parse --short=10 HEAD || echo '<unknown>')
BRANCH_NAME ?= $(GIT_COMMIT)
LATEST_IMAGE_TAG ?= $(ISTIO_VERSION)-$(GIT_COMMIT_SHORTER)

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../../lib.Makefile

###############################################################################
# Source Download and Patching
###############################################################################
ISTIO_DOWNLOADED = .istio.downloaded

.PHONY: init-source
init-source: $(ISTIO_DOWNLOADED)

$(ISTIO_DOWNLOADED):
	@echo "Cloning istio $(ISTIO_VERSION)..."
	git clone --depth 1 --branch $(ISTIO_VERSION) https://github.com/istio/istio.git
	@echo "Verifying commit SHA for reproducibility..."
	@cd istio && \
		ACTUAL_SHA=$$(git rev-parse HEAD) && \
		if [ "$$ACTUAL_SHA" != "$(ISTIO_GIT_SHA)" ]; then \
			echo "ERROR: Commit SHA mismatch!"; \
			echo "  Expected: $(ISTIO_GIT_SHA)"; \
			echo "  Got:      $$ACTUAL_SHA"; \
			echo "This may indicate the upstream tag was force-pushed."; \
			echo "Verify the change is intentional and update ISTIO_GIT_SHA in Makefile."; \
			exit 1; \
		fi
	@echo "Commit SHA verified: $(ISTIO_GIT_SHA)"
	@echo "Applying patches..."
	@for patch in patches/*.patch; do \
		if [ -f "$$patch" ]; then \
			echo "Applying $$patch..."; \
			patch -d istio -p1 < "$$patch" || exit 1; \
		fi; \
	done
	touch $@

###############################################################################
# Build
###############################################################################
# Linker flags for smaller binaries
LD_FLAGS := -s -w -extldflags -static

.PHONY: build
build: bin/pilot-discovery-$(ARCH) bin/install-cni-$(ARCH)

# Build pilot-discovery binary
bin/pilot-discovery-$(ARCH): $(ISTIO_DOWNLOADED)
	@echo "Building pilot-discovery for $(ARCH)..."
	mkdir -p bin
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
		cd istio && \
		CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build \
			-tags "vtprotobuf,disable_pgv" \
			-ldflags "$(LD_FLAGS)" \
			-o ../bin/pilot-discovery-$(ARCH) \
			./pilot/cmd/pilot-discovery'

# Build install-cni binary
bin/install-cni-$(ARCH): $(ISTIO_DOWNLOADED)
	@echo "Building install-cni for $(ARCH)..."
	mkdir -p bin
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
		cd istio && \
		CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build \
			-tags "agent,disable_pgv,grpcnotrace,retrynotrace" \
			-ldflags "$(LD_FLAGS)" \
			-o ../bin/install-cni-$(ARCH) \
			./cni/cmd/install-cni'

###############################################################################
# Image
###############################################################################
ISTIO_CNI_IMAGE_CREATED = .istio-cni.created-$(ARCH)
ISTIO_PILOT_IMAGE_CREATED = .istio-pilot.created-$(ARCH)

# Build images for all architectures
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))

sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

# istio-install-cni image
$(ISTIO_CNI_IMAGE): $(ISTIO_CNI_IMAGE_CREATED)

$(ISTIO_CNI_IMAGE_CREATED): register Dockerfile.cni bin/install-cni-$(ARCH)
	$(DOCKER_BUILD) -t $(ISTIO_CNI_IMAGE):latest-$(ARCH) -f Dockerfile.cni .
	docker tag $(ISTIO_CNI_IMAGE):latest-$(ARCH) $(ISTIO_CNI_IMAGE):$(LATEST_IMAGE_TAG)-$(ARCH)
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_CNI_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# istio-pilot image
$(ISTIO_PILOT_IMAGE): $(ISTIO_PILOT_IMAGE_CREATED)

$(ISTIO_PILOT_IMAGE_CREATED): register Dockerfile.pilot bin/pilot-discovery-$(ARCH)
	$(DOCKER_BUILD) -t $(ISTIO_PILOT_IMAGE):latest-$(ARCH) -f Dockerfile.pilot .
	docker tag $(ISTIO_PILOT_IMAGE):latest-$(ARCH) $(ISTIO_PILOT_IMAGE):$(LATEST_IMAGE_TAG)-$(ARCH)
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_PILOT_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: image

.PHONY: cd
cd: image var-require-one-of-CONFIRM-DRYRUN var-require-all-BRANCH_NAME
	$(MAKE) retag-build-images-with-registries push-images-to-registries \
		IMAGETAG=$(LATEST_IMAGE_TAG) EXCLUDEARCH="$(EXCLUDEARCH)" VALIDARCHES=$(ARCH)

.PHONY: push-manifest
push-manifest:
	$(MAKE) push-manifests IMAGETAG=$(LATEST_IMAGE_TAG)

###############################################################################
# Release
###############################################################################
.PHONY: release-build
release-build: .release-$(VERSION).created

.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	touch $@

.PHONY: release-publish
release-publish: release-prereqs .release-$(VERSION).published

.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@

###############################################################################
# Clean
###############################################################################
.PHONY: clean
clean:
	@echo "Cleaning istio build artifacts..."
	rm -f $(ISTIO_DOWNLOADED)
	rm -f $(ISTIO_CNI_IMAGE_CREATED) $(ISTIO_PILOT_IMAGE_CREATED)
	rm -f .istio-cni.created-* .istio-pilot.created-*
	rm -fr bin/ istio/
	rm -f .release-*
	-docker image rm -f $$(docker images $(ISTIO_CNI_IMAGE) -a -q) 2>/dev/null
	-docker image rm -f $$(docker images $(ISTIO_PILOT_IMAGE) -a -q) 2>/dev/null
