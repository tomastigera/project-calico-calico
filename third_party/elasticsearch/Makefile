include ../../metadata.mk

PACKAGE_NAME?=github.com/projectcalico/calico/third_party/elasticsearch

ELASTICSEARCH_IMAGE   ?=elasticsearch
BUILD_IMAGES          ?=$(ELASTICSEARCH_IMAGE)

ELASTIC_VERSION=8.19.8
TINI_VERSION=0.19.0

# required for ci/cd
DEV_REGISTRIES = $(THIRD_PARTY_REGISTRY)
BRANCH_NAME = v$(ELASTIC_VERSION)-$(THIRD_PARTY_RELEASE_BRANCH)
LATEST_IMAGE_TAG = $(BRANCH_NAME)

###############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../../lib.Makefile

###############################################################################
# Build
###############################################################################
ELASTIC_DOWNLOADED=.elasticsearch.downloaded

.PHONY: init-elastic
init-elastic: $(ELASTIC_DOWNLOADED)
$(ELASTIC_DOWNLOADED):
	mkdir -p build
	curl -sfL https://github.com/elastic/elasticsearch/archive/refs/tags/v$(ELASTIC_VERSION).tar.gz | tar xz -C build/
	patch -d build/elasticsearch-$(ELASTIC_VERSION) -p1 < patches/0001-Bump-packages-for-CVE-fixes.patch
	touch $@

GRADLE_TASK=:distribution:archives:linux-tar:assemble
ifeq ($(ARCH),amd64)
	override GRADLE_TASK=:distribution:archives:linux-tar:assemble
else ifeq ($(ARCH),arm64)
	override GRADLE_TASK=:distribution:archives:linux-aarch64-tar:assemble
endif

# FIXME(jiawei): Use ubi10/openjdk image when available.
OPENJDK_BUILD=registry.access.redhat.com/ubi9/openjdk-25:latest

.PHONY: build
build: init-elastic
	$(DOCKER_RUN) --user=$(LOCAL_USER_ID):$(LOCAL_GROUP_ID) -e GRADLE_USER_HOME=/go/src/$(PACKAGE_NAME)/build/.gradle \
		$(OPENJDK_BUILD) build/elasticsearch-$(ELASTIC_VERSION)/gradlew $(GRADLE_TASK) \
			-p build/elasticsearch-$(ELASTIC_VERSION) \
			-Dbuild.snapshot=false \
			-Dlicense.key=x-pack/license-tools/src/test/resources/public.key
	find build/elasticsearch-$(ELASTIC_VERSION)/ -name "elasticsearch-$(ELASTIC_VERSION)-linux-*.tar.gz" -exec cp {} build/ \;

.PHONY: clean
clean:
	rm -fr build
	rm -f $(ELASTIC_DOWNLOADED) $(ELASTICSEARCH_IMAGE_MARKER)
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

ELASTIC_ARCH=
ifeq ($(ARCH),amd64)
	override ELASTIC_ARCH=x86_64
else ifeq ($(ARCH),arm64)
	override ELASTIC_ARCH=aarch64
endif

$(ELASTICSEARCH_IMAGE_MARKER): Dockerfile build
	$(DOCKER_BUILD) --build-arg ELASTIC_ARCH=$(ELASTIC_ARCH) \
		--build-arg ELASTIC_VERSION=$(ELASTIC_VERSION) \
		--build-arg TINI_VERSION=$(TINI_VERSION) \
		-t $(ELASTICSEARCH_IMAGE):$(LATEST_IMAGE_TAG)-$(ARCH) \
		-f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=$(LATEST_IMAGE_TAG)
	touch $@

###############################################################################
# CI/CD
###############################################################################
.PHONY: cd
cd: image-all var-require-one-of-CONFIRM-DRYRUN var-require-all-BRANCH_NAME
	$(MAKE) retag-build-images-with-registries push-images-to-registries IMAGETAG=$(LATEST_IMAGE_TAG) EXCLUDEARCH="$(EXCLUDEARCH)"

.PHONY: push-manifest
push-manifest:
	$(MAKE) push-manifests IMAGETAG=$(LATEST_IMAGE_TAG)

.PHONY: release-retag-image
release-retag-image: var-require-one-of-CONFIRM-DRYRUN var-require-all-RELEASE_BRANCH
	$(CRANE) cp $(THIRD_PARTY_REGISTRY_CD)/$(ELASTICSEARCH_IMAGE):v$(ELASTIC_VERSION)-master \
		$(THIRD_PARTY_REGISTRY_CD)/$(ELASTICSEARCH_IMAGE):v$(ELASTIC_VERSION)-$(RELEASE_BRANCH)
