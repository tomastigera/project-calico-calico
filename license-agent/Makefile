include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/license-agent

LICENSE_AGENT_IMAGE        ?=license-agent
BUILD_IMAGES               ?=$(LICENSE_AGENT_IMAGE)

##############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

BINDIR        ?= bin
TEST_DIRS     ?= $(shell sh -c "find pkg -name \\*_test.go \
                   -exec dirname {} \\; | sort | uniq")
SRC_FILES      = $(shell sh -c "find pkg cmd -name \\*.go") \
			$(shell find ../libcalico-go/lib -name '*.go') \
			$(shell find ../licensing/client -name '*.go')

###############################################################################
# This section builds the output binaries.
###############################################################################
build: $(BINDIR)/license-agent-$(ARCH)

.PHONY: $(BINDIR)/license-agent-$(ARCH)
$(BINDIR)/license-agent-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/server, $@)
else
	$(call build_binary, ./cmd/server, $@)
endif

# Build the docker image.
.PHONY: $(LICENSE_AGENT_IMAGE)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(ARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

LICENSE_AGENT_CONTAINER_CREATED=.$(LICENSE_AGENT_IMAGE).created-$(ARCH)

image: $(LICENSE_AGENT_IMAGE)
$(LICENSE_AGENT_IMAGE): $(LICENSE_AGENT_CONTAINER_CREATED)
$(LICENSE_AGENT_CONTAINER_CREATED): Dockerfile $(BINDIR)/license-agent-$(ARCH)
	$(DOCKER_BUILD) --pull -t $(LICENSE_AGENT_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

##########################################################################
# Testing
##########################################################################
report-dir:
	mkdir -p report

.PHONY: ut
ut: report-dir
	$(DOCKER_RUN) \
		-v $(SECRETS_PATH):/secrets \
		$(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			go test $(UNIT_TEST_FLAGS) $(addprefix $(PACKAGE_NAME)/,$(TEST_DIRS))'

.PHONY: clean
clean:
	rm -rf $(BINDIR)
	rm -f $(LICENSE_AGENT_CONTAINER_CREATED)
	-docker image rm -f $$(docker images $(LICENSE_AGENT_IMAGE) -a -q)

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

## run CI cycle - build, test, etc.
## Run UTs and only if they pass build image and continue along.
## Building the image is required for fvs.
ci: clean static-checks image ut

## Deploys images to registry
cd: image-all cd-common
