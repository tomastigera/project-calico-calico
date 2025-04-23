include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/prometheus-operator

PROMETHEUS_OPERATOR_IMAGE ?= prometheus-operator
PROMETHEUS_CONFIG_RELOADER_IMAGE ?= prometheus-config-reloader
BUILD_IMAGES ?= $(PROMETHEUS_OPERATOR_IMAGE) ${PROMETHEUS_CONFIG_RELOADER_IMAGE}

PROMETHEUS_OPERATOR_VERSION = v0.76.2

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../lib.Makefile

###############################################################################
# Build
###############################################################################
PROMETHEUS_OPERATOR_DOWNLOADED=.prometheus-operator.downloaded

.PHONY: init-source
init-source: $(PROMETHEUS_OPERATOR_DOWNLOADED)
$(PROMETHEUS_OPERATOR_DOWNLOADED):
	mkdir -p prometheus-operator
	curl -sfL https://github.com/prometheus-operator/prometheus-operator/archive/refs/tags/$(PROMETHEUS_OPERATOR_VERSION).tar.gz | tar xz --strip-components 1 -C prometheus-operator
	patch -d prometheus-operator -p1 < patches/0001-Update-libraries.patch
	touch $@

build: bin/prometheus-operator-$(ARCH) bin/prometheus-config-reloader-$(ARCH)

.PHONY: bin/prometheus-config-reloader-$(ARCH)
bin/prometheus-config-reloader-$(ARCH): $(PROMETHEUS_OPERATOR_DOWNLOADED)
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			CGO_ENABLED=0 go build -C prometheus-operator -o ../$@ -v -buildvcs=false -ldflags "$(LDFLAGS) -s -w" cmd/prometheus-config-reloader/main.go'

.PHONY: bin/prometheus-operator-$(ARCH)
bin/prometheus-operator-$(ARCH): $(PROMETHEUS_OPERATOR_DOWNLOADED)
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			CGO_ENABLED=0 go build -C prometheus-operator -o ../$@ -v -buildvcs=false -ldflags "$(LDFLAGS) -s -w" cmd/operator/main.go'

.PHONY: clean
clean:
	rm -f $(PROMETHEUS_CONFIG_RELOADER_IMAGE_CREATED)
	rm -f $(PROMETHEUS_OPERATOR_DOWNLOADED)
	rm -f $(PROMETHEUS_OPERATOR_IMAGE_CREATED)
	rm -fr bin/ prometheus-operator/
	-docker image rm -f $$(docker images $(PROMETHEUS_OPERATOR_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(PROMETHEUS_CONFIG_RELOADER_IMAGE) -a -q)

###############################################################################
# Image
###############################################################################
PROMETHEUS_CONFIG_RELOADER_IMAGE_CREATED=.prometheus-config-reloader.created-$(ARCH)
PROMETHEUS_OPERATOR_IMAGE_CREATED=.prometheus-operator.created-$(ARCH)

# Build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(PROMETHEUS_OPERATOR_IMAGE): $(PROMETHEUS_OPERATOR_IMAGE_CREATED)
$(PROMETHEUS_OPERATOR_IMAGE_CREATED): prometheus-operator-docker/Dockerfile bin/prometheus-operator-$(ARCH)
	$(DOCKER_BUILD) -t $(PROMETHEUS_OPERATOR_IMAGE):latest-$(ARCH) -f prometheus-operator-docker/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(PROMETHEUS_OPERATOR_IMAGE)
	touch $@

$(PROMETHEUS_CONFIG_RELOADER_IMAGE): $(PROMETHEUS_CONFIG_RELOADER_IMAGE_CREATED)
$(PROMETHEUS_CONFIG_RELOADER_IMAGE_CREATED): prometheus-config-reloader-docker/Dockerfile bin/prometheus-config-reloader-$(ARCH)
	$(DOCKER_BUILD) -t $(PROMETHEUS_CONFIG_RELOADER_IMAGE):latest-$(ARCH) -f prometheus-config-reloader-docker/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(PROMETHEUS_CONFIG_RELOADER_IMAGE)
	touch $@

###############################################################################
# CI/CD
###############################################################################
ci: image

# The image name for GCR
cd: image-all cd-common
