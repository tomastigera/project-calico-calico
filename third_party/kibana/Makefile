include ../../metadata.mk

PACKAGE_NAME?=github.com/projectcalico/calico/third_party/kibana

KIBANA_IMAGE?=kibana-ubi
BUILD_IMAGES?=$(KIBANA_IMAGE)

KIBANA_VERSION = 8.19.12

# required for ci/cd
DEV_REGISTRIES = $(THIRD_PARTY_REGISTRY)
BRANCH_NAME = v$(KIBANA_VERSION)-$(THIRD_PARTY_RELEASE_BRANCH)
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
KIBANA_DOWNLOADED=.kibana.downloaded

.PHONY: init-source
init-source: $(KIBANA_DOWNLOADED)
$(KIBANA_DOWNLOADED):
	git clone --depth 1 --branch v$(KIBANA_VERSION) --single-branch https://github.com/elastic/kibana.git
	patch -d kibana -p1 < patches/0001-apply-tigera-customization-to-kibana.patch
	patch -d kibana -p1 < patches/0002-Reduce-all-platforms-to-only-linux-variant.patch
	patch -d kibana -p1 < patches/0003-support-ubi-arm64-builds.patch
	patch -d kibana -p1 < patches/0004-Build-with-ubi10.patch
	patch -d kibana -p1 < patches/0005-Update-libraries-to-patch-CVE.patch
	cp -r plugins/tigera kibana/plugins/
	cp -r plugins/googletagmanager kibana/plugins/
	touch $@


# always register because build target will build images for all supported arches
.PHONY: register
register:
	docker run --privileged --rm calico/binfmt:qemu-v10.1.3 --install all || true

.PHONY: build
build: register $(KIBANA_DOWNLOADED)
	cd kibana && \
	. $(NVM_DIR)/nvm.sh && nvm install && nvm use && \
	( for i in 1 2 3 4 5; do \
		BUILD_TS_REFS_CACHE_ENABLE=false yarn kbn bootstrap && exit 0 || \
		{ echo "bootstrap attempt $$i/5 failed"; sleep 10; }; \
	done; exit 1 ) && \
	yarn build \
		--docker-cross-compile --docker-images \
		--skip-docker-cloud --skip-docker-cloud-fips --skip-docker-contexts --skip-docker-fips \
		--skip-docker-serverless --skip-docker-ubuntu --skip-docker-wolfi \
		--release

# Build Tigera plugin
.PHONY: tigera-plugin
tigera-plugin:
	cd kibana/plugins/tigera/ && \
	. $(NVM_DIR)/nvm.sh && nvm install && nvm use && \
	yarn --cwd ../.. install && \
	yarn kbn bootstrap && yarn build --kibana-version $(KIBANA_VERSION)


# Build Google Tag Manager plugin
.PHONY: gtm-plugin
gtm-plugin:
	cd kibana/plugins/googletagmanager/ && \
	. $(NVM_DIR)/nvm.sh && nvm install && nvm use && \
	yarn --cwd ../.. install && \
	yarn kbn bootstrap && yarn build --kibana-version $(KIBANA_VERSION)


.PHONY: clean
clean:
	rm -fr kibana/
	rm -f $(KIBANA_DOWNLOADED)
	-docker image rm -f $$(docker images docker.elastic.co/kibana/kibana-ubi -a -q)

###############################################################################
# Image
###############################################################################
KIBANA_IMAGE_MARKER=.kibana.created-$(ARCH)

.PHONY: image-all
image-all: build $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(KIBANA_IMAGE)

$(KIBANA_IMAGE): $(KIBANA_IMAGE_MARKER)

$(KIBANA_IMAGE_MARKER): tigera-plugin gtm-plugin
	docker buildx build --load --platform=linux/$(ARCH) \
		--build-arg KIBANA_VERSION=$(KIBANA_VERSION) \
		-t $(KIBANA_IMAGE):$(LATEST_IMAGE_TAG)-$(ARCH) \
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
	$(CRANE) cp $(THIRD_PARTY_REGISTRY_CD)/$(KIBANA_IMAGE):v$(KIBANA_VERSION)-master \
		$(THIRD_PARTY_REGISTRY_CD)/$(KIBANA_IMAGE):v$(KIBANA_VERSION)-$(RELEASE_BRANCH)
