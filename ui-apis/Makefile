include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/ui-apis

# Mocks auto generated testify mocks by mockery. Run `make gen-mocks` to regenerate the testify mocks.
MOCKERY_FILE_PATHS= \
	pkg/kibana/Client \

UI_APIS_IMAGE ?= ui-apis
BUILD_IMAGES  ?= $(UI_APIS_IMAGE)

##############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

BINDIR       ?= bin
BUILD_DIR    ?= build
TOP_SRC_DIRS  = pkg
SRC_FILES     = $(shell find pkg cmd -name '*.go') \
		$(shell find ../api/pkg -name '*.go') \
		$(shell find ../compliance/pkg -name '*.go') \
		$(shell find ../libcalico-go/lib -name '*.go') \
		$(shell find ../lma/pkg -name '*.go') \
		$(shell find ../linseed -name '*.go')
TEST_DIRS    ?= $(shell find $(TOP_SRC_DIRS) -name '*_test.go' -exec dirname {} \; | sort | uniq)
ifdef UNIT_TESTS
UNIT_TEST_FLAGS=-run $(UNIT_TESTS) -v
endif

###############################################################################
# This section builds the output binaries.
# Some will have dedicated targets to make it easier to type, for example
# "ui-apis" instead of "$(BINDIR)/ui-apis".
build: $(BINDIR)/ui-apis-$(ARCH) $(BINDIR)/dashboard-api-$(ARCH)

$(BINDIR)/ui-apis-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/server/*.go, $@)
else
	$(call build_binary, cmd/server/*.go, $@)
endif

$(BINDIR)/dashboard-api-$(ARCH):
	$(MAKE) -C ../dashboards $@
	ln -f ../dashboards/$@ $@

UI_APIS_CONTAINER_CREATED=.ui-apis.created-$(ARCH)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(ARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(UI_APIS_IMAGE)

$(UI_APIS_IMAGE): $(UI_APIS_CONTAINER_CREATED)
$(UI_APIS_CONTAINER_CREATED): register Dockerfile $(BINDIR)/ui-apis-$(ARCH) $(BINDIR)/dashboard-api-$(ARCH)
	$(DOCKER_BUILD) -t $(UI_APIS_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: clean
clean:
	rm -fr $(BINDIR)
	rm -f $(UI_APIS_CONTAINER_CREATED)
	# We build dashboard api as part of the ui-apis image build, so clean them as part of the clean.
	$(MAKE) -C ../dashboards clean
	-docker image rm -f $$(docker images $(UI_APIS_IMAGE) -a -q)

##########################################################################
# Testing
##########################################################################
.PHONY: ut
ut:
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test $(UNIT_TEST_FLAGS) $(addprefix $(PACKAGE_NAME)/,$(TEST_DIRS))'

.PHONY: build-linseed-image build-apiserver-image run-linseed run-tigera-apiserver k8s-auth
build-linseed-image:
	$(MAKE) -C ../linseed image

build-apiserver-image:
	$(MAKE) -C ../apiserver image

run-linseed:
	$(MAKE) -C ../linseed run-image \
		LOG_LEVEL_ENV='-e LINSEED_LOG_LEVEL="info"' \
		ELASTIC_MEMORY=6GB \
		ELASTIC_EXTRA_DOCKER_ARGS='-e "indexing_pressure.memory.limit=20%" -e "ES_JAVA_OPTS=-Xms5g -Xmx5g"'

run-tigera-apiserver:
	$(MAKE) -C ../apiserver run-image register-apiservice

k8s-auth:
	APISERVER_NAME=$(APISERVER_NAME) \
	PACKAGE_NAME=${PACKAGE_NAME} \
	test/setup_k8s_auth.sh

.PHONY: fv fv-images fv-fast
# run-linseed creates our kube-apiserver
fv: fv-images run-linseed run-tigera-apiserver k8s-auth fv-fast

fv-images: build-linseed-image build-apiserver-image

fv-fast:
	$(DOCKER_RUN) \
		-v $(CERTS_PATH):/home/user/certs \
		-v $(SECRETS_PATH):/home/user/secrets \
		-e KUBECONFIG=/home/user/certs/kubeconfig \
		$(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) ginkgo -r test/'

# Copy certificate from the Elasticsearch container
.PHONY: copy-es-cacert
copy-es-cacert:
	docker cp tigera-elastic:/usr/share/elasticsearch/config/certs/http_ca.crt test/http_ca.crt
	chmod +r test/http_ca.crt

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

## run CI cycle - build, test, etc.
## Run UTs and only if they pass build image and continue along.
## Building the image is required for fvs.
ci: clean static-checks image ut fv

## Deploys images to registry
cd: image-all cd-common
