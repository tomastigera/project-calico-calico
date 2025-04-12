include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/prometheus

PROMETHEUS_IMAGE ?= prometheus
BUILD_IMAGES ?= $(PROMETHEUS_IMAGE)

PROMETHEUS_VERSION = v2.55.1

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../lib.Makefile

###############################################################################
# Build
###############################################################################
PROMETHEUS_DOWNLOADED=.prometheus.downloaded

.PHONY: init-source
init-source: $(PROMETHEUS_DOWNLOADED)
$(PROMETHEUS_DOWNLOADED):
	mkdir -p prometheus
	curl -sfL https://github.com/prometheus/prometheus/archive/refs/tags/$(PROMETHEUS_VERSION).tar.gz | tar xz --strip-components 1 -C prometheus
	patch -d prometheus -p1 < patches/0001-String-Go-binary-debug-symbols.patch
	patch -d prometheus -p1 < patches/0002-Patch-go-CVEs.patch
	touch $@

.PHONY: build
build: $(PROMETHEUS_DOWNLOADED)
	cd prometheus && \
	make assets && \
	make npm_licenses && \
	make assets-compress && \
	mkdir -p .go-pkg-cache
	$(DOCKER_RUN) -e ARCH=$(ARCH) -e CGO_ENABLED=$(CGO_ENABLED) -e GOEXPERIMENT=$(GOEXPERIMENT) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
		cd prometheus && \
			make promu && /go/bin/promu build --prefix .build/linux-$(ARCH)'

.PHONY: clean
clean:
	rm -f $(PROMETHEUS_DOWNLOADED)
	rm -f $(PROMETHEUS_IMAGE_CREATED)
	rm -fr bin/ prometheus/
	-docker image rm -f $$(docker images $(PROMETHEUS_IMAGE) -a -q)

###############################################################################
# Image
###############################################################################
PROMETHEUS_IMAGE_CREATED=.prometheus.created-$(ARCH)

# Build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(PROMETHEUS_IMAGE): $(PROMETHEUS_IMAGE_CREATED)
$(PROMETHEUS_IMAGE_CREATED): register Dockerfile build
	$(DOCKER_BUILD) -t $(PROMETHEUS_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: image

.PHONY: cd
cd: image-all cd-common
