include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/alertmanager

ALERTMANAGER_IMAGE    ?=alertmanager
BUILD_IMAGES          ?=$(ALERTMANAGER_IMAGE) 

ALERTMANAGER_VERSION = v0.28.1

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../lib.Makefile

###############################################################################
# Build
###############################################################################
ALERTMANAGER_DOWNLOADED=.alertmanager.downloaded

.PHONY: init-source
init-source: $(ALERTMANAGER_DOWNLOADED)
$(ALERTMANAGER_DOWNLOADED):
	mkdir -p alertmanager
	curl -sfL https://github.com/prometheus/alertmanager/archive/refs/tags/$(ALERTMANAGER_VERSION).tar.gz | tar xz --strip-components 1 -C alertmanager
	patch -d alertmanager -p1 < patches/0001-EV-5623-Upgrade-to-go-v1.23.patch
	touch $@

.PHONY: build
build: bin/amtool-$(ARCH) bin/alertmanager-$(ARCH)

.PHONY: assets
assets: $(ALERTMANAGER_DOWNLOADED)
	cd alertmanager && $(MAKE) assets apiv2

bin/alertmanager-$(ARCH): assets
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			CGO_ENABLED=0 go build -C alertmanager -buildvcs=false -o ../$@ -v -tags=$(TAGS) -ldflags="$(LD_FLAGS) -s -w" cmd/alertmanager/main.go'

bin/amtool-$(ARCH): assets
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			CGO_ENABLED=0 go build -C alertmanager -buildvcs=false -o ../$@ -v -tags=$(TAGS) -ldflags="$(LD_FLAGS)-s -w" cmd/amtool/main.go'

.PHONY: clean
clean:
	rm -f $(ALERTMANAGER_DOWNLOADED)
	rm -f $(ALERTMANAGER_IMAGE_CREATED)
	rm -fr bin/ alertmanager/
	-docker image rm -f $$(docker images $(ALERTMANAGER_IMAGE) -a -q)

###############################################################################
# Image
###############################################################################
ALERTMANAGER_IMAGE_CREATED=.alertmanager.created-$(ARCH)

# Build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

# Builds the alertmanager binary and ports them to their own images
$(ALERTMANAGER_IMAGE): $(ALERTMANAGER_IMAGE_CREATED)
$(ALERTMANAGER_IMAGE_CREATED): register Dockerfile build
	$(DOCKER_BUILD) -t $(ALERTMANAGER_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# CI/CD
###############################################################################
ci: image

cd: image-all cd-common
