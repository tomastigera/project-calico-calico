include ../metadata.mk

PACKAGE_NAME?=github.com/projectcalico/calico/elasticsearch

ELASTICSEARCH_IMAGE   ?=elasticsearch
BUILD_IMAGES          ?=$(ELASTICSEARCH_IMAGE)

###############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# Build
###############################################################################
.PHONY: build
build: bin/readiness-probe-$(ARCH)

.PHONY: bin/readiness-probe-$(ARCH)
bin/readiness-probe-$(ARCH): readiness-probe/main.go
	$(call build_binary, ./readiness-probe, $@)

.PHONY: clean
clean:
	rm -rf bin
	rm -f $(ELASTICSEARCH_IMAGE_MARKER)
	-docker image rm -f $$(docker images $(ELASTICSEARCH_IMAGE) -a -q)

###############################################################################
# Image
###############################################################################
ELASTICSEARCH_IMAGE_MARKER=.elasticsearch.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(ELASTICSEARCH_IMAGE)

$(ELASTICSEARCH_IMAGE): $(ELASTICSEARCH_IMAGE_MARKER)

$(ELASTICSEARCH_IMAGE_MARKER): register Dockerfile bin/readiness-probe-$(ARCH)
	$(DOCKER_BUILD_THIRD_PARTY) --build-arg ELASTIC_VERSION=$(ELASTIC_VERSION) \
		-t $(ELASTICSEARCH_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: clean image static-checks

.PHONY: cd
cd: image-all cd-common
