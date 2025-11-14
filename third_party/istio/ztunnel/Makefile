###############################################################################
# Ztunnel Component Makefile
# Builds the Istio ztunnel proxy component
###############################################################################
include ../../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/istio/ztunnel

# Override DEV_REGISTRIES to push to quay.io (ArgoCI script logs into quay.io)
# Must use = not ?= because metadata.mk already sets DEV_REGISTRIES
DEV_REGISTRIES = quay.io/tigera

ZTUNNEL_IMAGE ?= istio-ztunnel
BUILD_IMAGES ?= $(ZTUNNEL_IMAGE)

ZTUNNEL_VERSION = 1.27.3
# Commit SHA for version verification (ensures reproducibility and detects upstream tag changes)
# To update: git ls-remote https://github.com/istio/ztunnel.git refs/tags/1.27.3
ZTUNNEL_GIT_SHA = 7c3bc5b7d33ddf57ccfe47a3c8bc331f6a4a0f11

# Git commit for image tagging (following envoybinary pattern)
GIT_COMMIT := $(shell git rev-parse HEAD || echo '<unknown>')
GIT_COMMIT_SHORTER := $(shell git rev-parse --short=10 HEAD || echo '<unknown>')
BRANCH_NAME = $(GIT_COMMIT)
LATEST_IMAGE_TAG = $(ZTUNNEL_VERSION)-$(GIT_COMMIT_SHORTER)

# Rust build image - using Calico's rust-build container
# TODO: Update to use TIGERA_DOCKER_REGISTRY when we push to quay.io
CALICO_RUST_BUILD_IMAGE = docker.io/calico/rust-build:calico-rust-build

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../../lib.Makefile

###############################################################################
# Source Download and Patching
###############################################################################
ZTUNNEL_DOWNLOADED = .ztunnel.downloaded

.PHONY: init-source
init-source: $(ZTUNNEL_DOWNLOADED)

$(ZTUNNEL_DOWNLOADED):
# we clone from git because istio releases do not include the vendored dependencies
	@echo "Cloning ztunnel $(ZTUNNEL_VERSION)..."
	git clone --depth 1 --branch $(ZTUNNEL_VERSION) https://github.com/istio/ztunnel.git
	@echo "Verifying commit SHA for reproducibility..."
	@cd ztunnel && \
		ACTUAL_SHA=$$(git rev-parse HEAD) && \
		if [ "$$ACTUAL_SHA" != "$(ZTUNNEL_GIT_SHA)" ]; then \
			echo "ERROR: Commit SHA mismatch!"; \
			echo "  Expected: $(ZTUNNEL_GIT_SHA)"; \
			echo "  Got:      $$ACTUAL_SHA"; \
			echo "This may indicate the upstream tag was force-pushed."; \
			echo "Verify the change is intentional and update ZTUNNEL_GIT_SHA in Makefile."; \
			exit 1; \
		fi
	@echo "Commit SHA verified: $(ZTUNNEL_GIT_SHA)"
	@echo "Applying patches..."
	@for patch in patches/*.patch; do \
		if [ -f "$$patch" ]; then \
			echo "Applying $$patch..."; \
			patch -d ztunnel -p1 < "$$patch" || exit 1; \
		fi; \
	done
	touch $@

###############################################################################
# Build
###############################################################################

# Map ARCH to BoringSSL vendor directory name
BORING_ARCH_amd64 := linux_x86_64
BORING_ARCH_arm64 := linux_arm64
BORING_ARCH := $(BORING_ARCH_$(ARCH))

.PHONY: build
build: bin/ztunnel-$(ARCH)

bin/ztunnel-$(ARCH): $(ZTUNNEL_DOWNLOADED)
	@echo "Building ztunnel for $(ARCH) (BoringSSL: $(BORING_ARCH))..."
	@if [ -z "$(BORING_ARCH)" ]; then echo "Error: Unsupported ARCH: $(ARCH)"; exit 1; fi
	@echo "Patching .cargo/config.toml for $(BORING_ARCH)..."
	@# Save original and ensure restoration even on failure
	@cp ztunnel/.cargo/config.toml ztunnel/.cargo/config.toml.orig
	@trap 'mv ztunnel/.cargo/config.toml.orig ztunnel/.cargo/config.toml 2>/dev/null || true' EXIT; \
		sed 's|linux_x86_64|$(BORING_ARCH)|g' ztunnel/.cargo/config.toml.orig > ztunnel/.cargo/config.toml && \
		mkdir -p bin && \
		docker run --rm \
			--platform=linux/$(ARCH) \
			-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
			-v $(CURDIR)/ztunnel:/work \
			-e CARGO_TARGET_DIR=/work/target \
			$(CALICO_RUST_BUILD_IMAGE) \
			sh -c '. /etc/profile.d/rust.sh && cd /work && cargo build --release' && \
		echo "Copying binary from build directory..." && \
		cp ztunnel/target/release/ztunnel bin/ztunnel-$(ARCH) && \
		chmod +x bin/ztunnel-$(ARCH) && \
		mv ztunnel/.cargo/config.toml.orig ztunnel/.cargo/config.toml

###############################################################################
# Image
###############################################################################
ZTUNNEL_IMAGE_CREATED = .ztunnel.created-$(ARCH)

# Build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))

sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(ZTUNNEL_IMAGE): $(ZTUNNEL_IMAGE_CREATED)

$(ZTUNNEL_IMAGE_CREATED): register Dockerfile build
	$(DOCKER_BUILD) -t $(ZTUNNEL_IMAGE):latest-$(ARCH) -f Dockerfile .
	# Tag with version-gitsha for cd target
	docker tag $(ZTUNNEL_IMAGE):latest-$(ARCH) $(ZTUNNEL_IMAGE):$(LATEST_IMAGE_TAG)-$(ARCH)
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
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
	touch $@

.PHONY: release-publish
release-publish: release-prereqs .release-$(VERSION).published

.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE)
	touch $@

###############################################################################
# Clean
###############################################################################
.PHONY: clean
clean:
	@echo "Cleaning ztunnel build artifacts..."
	rm -f $(ZTUNNEL_DOWNLOADED)
	rm -f $(ZTUNNEL_IMAGE_CREATED)
	rm -fr bin/ ztunnel/
	rm -f .release-*
	-docker image rm -f $$(docker images $(ZTUNNEL_IMAGE) -a -q)
