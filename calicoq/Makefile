include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/calicoq

##############################################################################
# Define some constants
##############################################################################
CALICOQ_IMAGE         ?=calicoq
BUILD_IMAGES          ?=$(CALICOQ_IMAGE)

# Create an extended go-build image with docker binary installed for use with st target
TOOLING_IMAGE?=calico/go-build-with-docker
TOOLING_IMAGE_VERSION?=v0.24
TOOLING_IMAGE_CREATED=.go-build-with-docker.created

##############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

build: bin/calicoq-$(ARCH)
bin/calicoq-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./calicoq/calicoq.go, $@)

CALICOQ_IMAGE_CREATED=.calicoq.created-$(ARCH)

# Build image for testing
.PHONY: image $(BUILD_IMAGES)
image: $(BUILD_IMAGES)

# Build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(CALICOQ_IMAGE): $(CALICOQ_IMAGE_CREATED)
IMAGE_DEPS = Dockerfile
$(CALICOQ_IMAGE_CREATED): $(IMAGE_DEPS) bin/calicoq-$(ARCH) | register
	$(DOCKER_BUILD) -t $(CALICOQ_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean:
	rm -rf bin report/*.xml
	rm -f $(CALICOQ_IMAGE_CREATED) $(TOOLING_IMAGE_CREATED)

	-docker image rm -f $$(docker images $(CALICOQ_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(TOOLING_IMAGE) -a -q)

###############################################################################
# CI/CD
###############################################################################
# Location of a valid license to use in the tests. On semaphore, this is provided as part
# of the build environment.
TSEE_TEST_LICENSE?=${HOME}/secrets/license.yaml

.PHONY: ci
## Run what CI runs
ci: clean static-checks image test

## Deploys images to registry
cd: image-all cd-common

$(TOOLING_IMAGE_CREATED): Dockerfile-testenv
	$(DOCKER_BUILD) -t $(TOOLING_IMAGE):$(TOOLING_IMAGE_VERSION) -f Dockerfile-testenv .
	touch $@

.PHONY: ut
ut:
	mkdir -p report
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) ginkgo --junit-report=calicoq_ut.xml --output-dir=report/ --cover -r --skip-package calicoq/*'

bin/calicoctl:
	make -C ../calicoctl build
	cp ../calicoctl/bin/calicoctl-linux-$(ARCH) $@

.PHONY: fv
fv: image run-etcd bin/calicoctl
	$(DOCKER_RUN) \
		--entrypoint '/bin/sh' \
		-v $(CURDIR):/code/$(PACKAGE_NAME) \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(TSEE_TEST_LICENSE):$(TSEE_TEST_LICENSE) \
		-e ETCD_IMAGE=$(ETCD_IMAGE) \
		-e TSEE_TEST_LICENSE=$(TSEE_TEST_LICENSE) \
		-w /code/$(PACKAGE_NAME) \
		$(CALICO_BUILD) \
		-c 'CALICOQ=`pwd`/bin/calicoq-$(ARCH) fv/run-test'

.PHONY: st
st: image $(TOOLING_IMAGE_CREATED) bin/calicoctl
	$(DOCKER_RUN) \
		--entrypoint '/bin/sh' \
		-v $(CURDIR):/code/$(PACKAGE_NAME) \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(TSEE_TEST_LICENSE):$(TSEE_TEST_LICENSE) \
		-w /code/$(PACKAGE_NAME) \
		-e KUBECONFIG=st/kubeconfig \
		-e ETCD_IMAGE=$(ETCD_IMAGE) \
		-e TSEE_TEST_LICENSE=$(TSEE_TEST_LICENSE) \
		$(TOOLING_IMAGE):$(TOOLING_IMAGE_VERSION) \
		-c 'CALICOQ=`pwd`/bin/calicoq-$(ARCH) st/run-test'

.PHONY: scale-test
scale-test: image bin/calicoctl
	$(DOCKER_RUN) \
		--entrypoint '/bin/sh' \
		-v $(CURDIR):/code/$(PACKAGE_NAME) \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-w /code/$(PACKAGE_NAME) \
		-e ETCD_IMAGE=$(ETCD_IMAGE) \
		$(CALICO_BUILD) \
		-c 'CALICOQ=`pwd`/bin/calicoq-$(ARCH) scale-test/run-test'

###############################################################################
# Release
###############################################################################

release-build-binaries: var-require-all-VERSION build

## Builds and pushed binaries to the public s3 bucket.
release-publish-binaries: var-require-one-of-CONFIRM-DRYRUN release-build-binaries
ifdef CONFIRM
	aws --profile helm s3 cp bin/calicoq-amd64 s3://$(ARTIFACTS_BUCKET)/binaries/$(VERSION)/calicoq --acl public-read
else
	@echo [DRYRUN] aws --profile helm s3 cp bin/calicoq-amd64 s3://$(ARTIFACTS_BUCKET)/binaries/$(VERSION)/calicoq --acl public-read
endif
