include ../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/ingress-collector

INGRESS_COLLECTOR_IMAGE ?=ingress-collector
BUILD_IMAGES            ?=$(INGRESS_COLLECTOR_IMAGE)

##############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

##############################################################################
# Build
##############################################################################
## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

.PHONY: build
build: bin/ingress-collector-$(ARCH)
bin/ingress-collector-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/ingress-collector, $@)
else
	$(call build_binary, ./cmd/ingress-collector, $@)
endif

##############################################################################
# Image
##############################################################################
INGRESS_COLLECTOR_IMAGE_CREATED=.ingress-collector.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(INGRESS_COLLECTOR_IMAGE)

$(INGRESS_COLLECTOR_IMAGE): $(INGRESS_COLLECTOR_IMAGE_CREATED)
IMAGE_DEPS = Dockerfile
$(INGRESS_COLLECTOR_IMAGE_CREATED): $(IMAGE_DEPS) bin/ingress-collector-$(ARCH) | register
	$(DOCKER_BUILD) -t $(INGRESS_COLLECTOR_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

##############################################################################
# Clean
##############################################################################
.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	rm -fr bin report/*.xml
	rm -f $(INGRESS_COLLECTOR_IMAGE_CREATED)
	-docker image rm -f $$(docker images $(INGRESS_COLLECTOR_IMAGE) -a -q)

###############################################################################
# UTs
###############################################################################
WHAT?=.
GINKGO_FOCUS?=.*

.PHONY: ut
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) ginkgo --junit-report=ingress-collector_ut.xml --output-dir=report/ -r --skip-package fv --focus=$(GINKGO_FOCUS) $(GINKGO_ARGS) $(WHAT)'

.PHONY: fv
fv:
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) ginkgo -r --focus=$(GINKGO_FOCUS) $(GINKGO_ARGS) $(WHAT)'

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
# Force ci to always run a clean before running other targets.
# This is intentional so that irrespective of where ci is being run from
# the ci target will always run a clean.
# This change should be reverted when common Makefile runs the ci target
# in a way that always runs the "clean" target.
ci: clean static-checks image ut fv

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd: image-all cd-common
