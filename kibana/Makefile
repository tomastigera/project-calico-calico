include ../metadata.mk

PACKAGE_NAME?=github.com/projectcalico/calico/kibana

KIBANA_IMAGE?=kibana
BUILD_IMAGES?=$(KIBANA_IMAGE)

# Set GTM_INTEGRATION explicitly so that in case the defaults change, we will still not
# accidentally enable the integration
GTM_INTEGRATION?=disabled

ifeq ($(TESLA),true)
GTM_INTEGRATION=enabled
IMAGETAG_PREFIX?=tesla
endif


###############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# Image
###############################################################################
KIBANA_IMAGE_MARKER=.kibana.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(KIBANA_IMAGE)

$(KIBANA_IMAGE): $(KIBANA_IMAGE_MARKER)

$(KIBANA_IMAGE_MARKER): register docker-image/Dockerfile docker-image/create_kibana_config.sh
	$(DOCKER_BUILD_THIRD_PARTY) --build-arg GTM_INTEGRATION=$(GTM_INTEGRATION)\
		-t $(KIBANA_IMAGE):latest-$(ARCH) -f docker-image/Dockerfile docker-image
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean:
	-docker image rm -f $$(docker images $(KIBANA_IMAGE) -a -q)

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: clean image

.PHONY: cd
cd: image-all cd-common
