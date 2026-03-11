include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/kube-controllers
TESLA ?= false

# Name of the images.
# e.g., <registry>/<name>:<tag>
KUBE_CONTROLLERS_IMAGE  ?=kube-controllers
FLANNEL_MIGRATION_IMAGE ?=flannel-migration-controller

LOCAL_CHECKS = LIBBPF_FILE_CREATED
ifdef RELEASE
BUILD_IMAGES ?=$(KUBE_CONTROLLERS_IMAGE)
else
BUILD_IMAGES ?=$(KUBE_CONTROLLERS_IMAGE) $(FLANNEL_MIGRATION_IMAGE)
endif

ifeq ($(TESLA),true)
	RELEASE_REGISTRIES    = gcr.io/tigera-tesla/tigera
	BUILD_TAGS            ?= tesla
	IMAGETAG_PREFIX       ?= tesla
endif

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

# Mocks auto generated testify mocks by mockery. Run `make gen-mocks` to regenerate the testify mocks.
MOCKERY_FILE_PATHS= \
	pkg/elasticsearch/ClientBuilder \

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.
KUBE_CONTROLLER_CONTAINER_CREATED=.image.created-$(ARCH)
KUBE_CONTROLLER_CONTAINER_FIPS_CREATED=.image.created-$(ARCH)-fips

FIPS ?= false

ifeq ($(FIPS),true)
KUBE_CONTROLLER_CONTAINER_MARKER=$(KUBE_CONTROLLER_CONTAINER_FIPS_CREATED)
VALIDARCHES=amd64
BINDIR=bin/$(ARCH)-fips
else
KUBE_CONTROLLER_CONTAINER_MARKER=$(KUBE_CONTROLLER_CONTAINER_CREATED)
BINDIR=bin
endif

LIBBPF_FILE_CREATED=../felix/bpf-gpl/.libbpf-$(LIBBPF_VERSION)

###############################################################################

## Removes all build artifacts.
clean:
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -f report/*.xml
	rm -f tests/fv/fv.test
	rm -rf bin image.created-$(ARCH) build report/*.xml release-notes-*
	-docker image rm -f $$(docker images $(FLANNEL_MIGRATION_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(KUBE_CONTROLLERS_IMAGE) -a -q)

###############################################################################
# Building the binary
###############################################################################
build: $(BINDIR)/kube-controllers-linux-$(ARCH) $(BINDIR)/check-status-linux-$(ARCH)
build-all: $(addprefix sub-build-,$(VALIDARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

$(BINDIR)/kube-controllers-linux-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/kube-controllers/, $@)
else
	$(call build_binary, ./cmd/kube-controllers/, $@)
endif

$(BINDIR)/wrapper-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/wrapper, $@)
else
	$(call build_binary, ./cmd/wrapper, $@)
endif

$(BINDIR)/check-status-linux-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./cmd/check-status, $@)

$(BINDIR)/kubectl-$(ARCH):
	curl -sSf -L --retry 5 -o $@ https://dl.k8s.io/release/$(K8S_VERSION)/bin/linux/$(ARCH)/kubectl
	chmod +x $@

LIBBPF_FILE_CREATED:
	make -C ../felix clone-libbpf

###############################################################################
# Building the image
###############################################################################
## Builds the controller binary and docker image.
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image FIPS=$(FIPS) ARCH=$*

image: $(KUBE_CONTROLLER_CONTAINER_MARKER)

IMAGE_DEPS = Dockerfile docker-image/flannel-migration/Dockerfile
# register is order-only (|) so binfmt setup doesn't trigger unnecessary rebuilds.
$(KUBE_CONTROLLER_CONTAINER_CREATED): $(IMAGE_DEPS) $(BINDIR)/kube-controllers-linux-$(ARCH) $(BINDIR)/check-status-linux-$(ARCH) $(BINDIR)/wrapper-$(ARCH) $(BINDIR)/kubectl-$(ARCH) | register
	cp ../LICENSE.md $(BINDIR)/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(KUBE_CONTROLLERS_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(FLANNEL_MIGRATION_IMAGE):latest-$(ARCH) -f docker-image/flannel-migration/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

$(KUBE_CONTROLLER_CONTAINER_FIPS_CREATED): $(IMAGE_DEPS) $(BINDIR)/kube-controllers-linux-$(ARCH) $(BINDIR)/check-status-linux-$(ARCH) $(BINDIR)/wrapper-$(ARCH) $(BINDIR)/kubectl-$(ARCH) | register
	cp ../LICENSE.md $(BINDIR)/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(KUBE_CONTROLLERS_IMAGE):latest-fips-$(ARCH) -f Dockerfile .
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(FLANNEL_MIGRATION_IMAGE):latest-fips-$(ARCH) -f docker-image/flannel-migration/Dockerfile .
	$(MAKE) FIPS=true retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

###############################################################################
# Static checks
###############################################################################
# Make sure that a copyright statement exists on all go files.

check-copyright:
	./check-copyrights.sh

###############################################################################
# Tests
###############################################################################
# Disable spider for now, it's barfing on a missing embed file.
#ifeq ($(SEMAPHORE_GIT_REF_TYPE), pull-request)
## Determine the tests to run using the test spider tool, which emits a list of impacted packages.
#MAYBE_WHAT=$(shell $(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) go run ../hack/test/spider -commit-range=${SEMAPHORE_GIT_COMMIT_RANGE} -filter-dir kube-controllers/')
#else
# By default, run all tests.
MAYBE_WHAT=.
#endif

# Filter the list of directories to only those that have tests.
ifneq ("$(MAYBE_WHAT)","")
WHAT=$(shell find $(MAYBE_WHAT) -name "*_test.go" | xargs dirname | sort -u)
endif

# The list of test binaries to build.
# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
TEST_BINARIES=$(addsuffix /ut.test,$(WHAT))

## Run the unit tests in a container.
test: ut
ut fv: $(TEST_BINARIES) $(KUBE_CONTROLLER_CONTAINER_CREATED)
	mkdir -p report
	KUBE_IMAGE=$(CALICO_BUILD) \
		   ETCD_IMAGE=$(ETCD_IMAGE) \
		   CALICO_API_GROUP=$(CALICO_API_GROUP) \
		   CONTAINER_NAME=$(KUBE_CONTROLLERS_IMAGE):latest-$(ARCH) \
		   MIGRATION_CONTAINER_NAME=$(FLANNEL_MIGRATION_IMAGE):latest-$(ARCH) \
		   CRDS=$(REPO_ROOT)/$(CALICO_CRD_PATH) \
		   CERTS_PATH=$(CERTS_PATH) \
		   ./run-uts $(WHAT)

st:
	@echo "No ST tests specified"

# Produce test binaries for each package that needs them.
# ginkgo doesn't let you produce a single test binary with multiple packages.
# Only do this if there are .go files in the path.
%/ut.test: $(SRC_FILES)
	if [ $$(find ./$* -name '*.go' | wc -l) -gt 0 ]; then \
		$(DOCKER_RUN) -e CGO_ENABLED=0 $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./$* -c -o $@'; \
	else \
		echo "Skipping $* as it has no .go files in it"; \
	fi

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean static-checks image ut

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd: image-all cd-common
