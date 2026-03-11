include ../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/prometheus-service

##############################################################################
# Constants
##############################################################################
PROMETHEUS_SERVICE_IMAGE  ?=prometheus-service
BUILD_IMAGES          		?=$(PROMETHEUS_SERVICE_IMAGE)

PROMETHEUS_SERVICE_VERSION?=$(shell git describe --tags --dirty --always --abbrev=12)

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

###############################################################################
# Build
###############################################################################
# This section builds the output binaries.
# Some will have dedicated targets to make it easier to type, for example
# "prometheus-service" instead of "bin/prometheus-service".

BUILD_DIR?=build
TOP_SRC_DIRS=pkg
TEST_DIRS     ?= $(shell sh -c "find $(TOP_SRC_DIRS) -name \\*_test.go \
                   -exec dirname {} \\; | sort | uniq")
## SRC_FILES is auto-populated from deps.txt by lib.Makefile.


build: bin/prometheus-service-$(ARCH)

bin/prometheus-service-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/server, $@)
else
	$(call build_binary, ./cmd/server, $@)
endif

# Build the docker image.
.PHONY: $(BUILD_IMAGES) $(addsuffix -$(ARCH),$(BUILD_IMAGES))

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(ARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

PROMETHEUS_SERVICE_CONTAINER_CREATED=.$(PROMETHEUS_SERVICE_IMAGE).created-$(ARCH)

image: $(PROMETHEUS_SERVICE_IMAGE)
$(PROMETHEUS_SERVICE_IMAGE): $(PROMETHEUS_SERVICE_CONTAINER_CREATED)
IMAGE_DEPS = Dockerfile
$(PROMETHEUS_SERVICE_CONTAINER_CREATED): $(IMAGE_DEPS) bin/prometheus-service-$(ARCH) | register
	$(DOCKER_BUILD) -t $(PROMETHEUS_SERVICE_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest

.PHONY: clean
clean:
	rm -rf bin
	-docker image rm -f $$(docker images $(PROMETHEUS_SERVICE_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(PROMETHEUS_SERVICE_TEST_CONTAINER_NAME) -a -q)
	rm -rf fv/tls.*

##########################################################################
# Testing
##########################################################################
PROMETHEUS_SERVICE_TEST_CONTAINER_NAME="fv-prometheus-proxy-test"
PACKAGE_ROOT=$(shell sh -c "pwd")

report-dir:
	mkdir -p report

.PHONY: ut
ut: report-dir
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			gotestsum --junitfile report/prometheus_service_ut.xml -- $(UNIT_TEST_FLAGS) \$(addprefix $(PACKAGE_NAME)/,$(TEST_DIRS))'

.PHONY: fv
fv: image report-dir run-prometheus-service-proxy fv/fv.test
		cd fv && ./fv.test $(GINKGO_ARGS) --ginkgo.slow-spec-threshold=30s
		$(MAKE) clean

fv/fv.test: $(shell find ./fv -type f -name '*.go' -print)
# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
	$(DOCKER_RUN)	$(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./fv -c --tags fvtests -o fv/fv.test'


create-tls:
	$(DOCKER_RUN)	$(CALICO_BUILD) sh -c "cd fv && openssl req -nodes -x509 -sha256 -newkey rsa:4096 \
                                                  -keyout tls.key \
                                                  -out tls.crt \
                                                  -days 356 \
                                                  -subj '/C=CA/ST=BC/L=Burnaby/O=Tigera/OU=Eng/CN=localhost'  \
                                                  -addext 'subjectAltName = DNS:localhost' && chmod 644 tls.*"

run-prometheus-service-proxy: create-tls
	docker rm -f ${PROMETHEUS_SERVICE_TEST_CONTAINER_NAME} || true
	${DOCKER_RUN} \
		--detach \
		-v ${PACKAGE_ROOT}/fv/tls.crt:/tls/tls.crt:ro \
		-v ${PACKAGE_ROOT}/fv/tls.key:/tls/tls.key:ro \
		-e LISTEN_ADDR="localhost:8090" \
		-e LOG_LEVEL=debug \
		-e AUTHENTICATION_ENABLED=false \
		--name ${PROMETHEUS_SERVICE_TEST_CONTAINER_NAME} \
		tigera/${PROMETHEUS_SERVICE_IMAGE}:latest

	until $$(curl --insecure https://localhost:8090 2> /dev/null); do \
		echo "Waiting for Prometheus Service to come up..."; \
		sleep 3; \
	done

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## run CI cycle - build, test, etc.
## Run UTs and only if they pass build image and continue along.
ci: clean static-checks image ut fv

## Deploys images to registry
cd: image-all cd-common
