include ../metadata.mk

PACKAGE_NAME?=github.com/projectcalico/calico/elasticsearch-metrics

ELASTICSEARCH_METRICS_IMAGE ?=elasticsearch-metrics
BUILD_IMAGES                ?=$(ELASTICSEARCH_METRICS_IMAGE)

###############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# Build
###############################################################################
build: bin/elasticsearch-metrics-$(ARCH)

.PHONY: bin/elasticsearch-metrics-$(ARCH)
bin/elasticsearch-metrics-$(ARCH): cmd/main.go cmd/logger.go
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/*.go, $@)
else
	$(call build_binary, cmd/*.go, $@)
endif

clean:
	rm -rf bin
	rm -f $(ELASTICSEARCH_METRICS_IMAGE_CREATED)
	-docker image rm -f $$(docker images $(ELASTICSEARCH_METRICS_IMAGE) -a -q)

###############################################################################
# Image
###############################################################################
ELASTICSEARCH_METRICS_IMAGE_CREATED=.es-metrics.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(ELASTICSEARCH_METRICS_IMAGE)

$(ELASTICSEARCH_METRICS_IMAGE): $(ELASTICSEARCH_METRICS_IMAGE_CREATED)
$(ELASTICSEARCH_METRICS_IMAGE_CREATED): Dockerfile bin/elasticsearch-metrics-$(ARCH)
	$(DOCKER_BUILD) -t $(ELASTICSEARCH_METRICS_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# CI/CD
###############################################################################
ci: clean static-checks image

cd: image-all cd-common
