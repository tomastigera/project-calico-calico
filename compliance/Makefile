include ../metadata.mk

PACKAGE_NAME            ?= github.com/projectcalico/calico/compliance

COMPLIANCE_SERVER_IMAGE      =compliance-server
COMPLIANCE_CONTROLLER_IMAGE  =compliance-controller
COMPLIANCE_SNAPSHOTTER_IMAGE =compliance-snapshotter
COMPLIANCE_REPORTER_IMAGE    =compliance-reporter
COMPLIANCE_BENCHMARKER_IMAGE =compliance-benchmarker

BUILD_IMAGES ?=$(COMPLIANCE_SERVER_IMAGE) \
 	$(COMPLIANCE_CONTROLLER_IMAGE) \
 	$(COMPLIANCE_SNAPSHOTTER_IMAGE) \
	$(COMPLIANCE_REPORTER_IMAGE) \
	$(COMPLIANCE_BENCHMARKER_IMAGE)

MOCKERY_FILE_PATHS= \
	pkg/api/ReportEventFetcher \
	pkg/api/ListDestination \
	pkg/api/ComplianceStore \
	pkg/datastore/ClusterCtxK8sClientFactory \
	pkg/api/StoreFactory


##############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

##############################################################################
# Define some constants
##############################################################################
NON_SRC_DIRS = test

# All Compliance Server go files.
SRC_FILES:=$(shell find . $(foreach dir,$(NON_SRC_DIRS),-path $(dir) -prune -o) -type f -name '*.go') \
		$(shell find ../api/pkg -name '*.go') \
		$(shell find ../libcalico-go/lib -name '*.go') \
		$(shell find ../lma/pkg -name '*.go')

###############################################################################
# Building the binaries
###############################################################################
build: bin/benchmarker-$(ARCH) \
	bin/controller-$(ARCH) \
	bin/kube-bench-$(ARCH) \
	bin/kubectl-$(ARCH) \
	bin/report-type-gen-$(ARCH) \
	bin/reporter-$(ARCH) \
	bin/scaleloader-$(ARCH) \
	bin/server-$(ARCH) \
	bin/snapshotter-$(ARCH)

build-all: $(addprefix sub-build-,$(VALIDARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

.PHONY: bin/server-$(ARCH)
bin/server-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/server/server.go, $@)
else
	$(call build_binary, cmd/server/server.go, $@)
endif

.PHONY: bin/controller-$(ARCH)
bin/controller-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/controller/controller.go, $@)
else
	$(call build_binary, cmd/controller/controller.go, $@)
endif

.PHONY: bin/snapshotter-$(ARCH)
bin/snapshotter-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/snapshotter/snapshotter.go, $@)
else
	$(call build_binary, cmd/snapshotter/snapshotter.go, $@)
endif

.PHONY: bin/reporter-$(ARCH)
bin/reporter-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/reporter/reporter.go, $@)
else
	$(call build_binary, cmd/reporter/reporter.go, $@)
endif

.PHONY: bin/report-type-gen-$(ARCH)
bin/report-type-gen-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/report-type-gen/*.go, $@)
else
	$(call build_binary, cmd/report-type-gen/*.go, $@)
endif

.PHONY: bin/scaleloader-$(ARCH)
bin/scaleloader-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/mockdata-scaleloader/scaleloader.go, $@)
else
	$(call build_binary, cmd/mockdata-scaleloader/scaleloader.go, $@)
endif

.PHONY: bin/kube-bench-$(ARCH)
bin/kube-bench-$(ARCH): cmd/kube-bench/main.go
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/kube-bench/main.go, $@)
else
	$(call build_binary, cmd/kube-bench/main.go, $@)
endif

.PHONY: bin/benchmarker-$(ARCH)
bin/benchmarker-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/benchmarker/benchmarker.go, $@)
else
	$(call build_binary, cmd/benchmarker/benchmarker.go, $@)
endif


KUBERNETES_VERSION := $(shell grep -E 'k8s.io/kubernetes' ../go.mod | awk '{print$$2;exit}')
bin/kubectl-$(ARCH):
	$(eval LDFLAGS = -X k8s.io/component-base/version.gitVersion=$(KUBERNETES_VERSION) \
		-X k8s.io/component-base/version.gitCommit=$(KUBERNETES_VERSION) \
		-X k8s.io/component-base/version.gitTreeState=$(clean) \
		-X k8s.io/component-base/version.buildDate=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ'))
	$(call build_binary, cmd/kubectl/kubectl.go, $@)

###############################################################################
# Building the report files
###############################################################################

.PHONY: gen-files
## Force rebuild of the report generator tool and the default report manifests
gen-files: bin/report-type-gen-$(ARCH)
	rm -rf output/default
	mkdir -p output/default/manifests
	mkdir -p output/default/json
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'bin/report-type-gen-$(ARCH) generate'

###############################################################################
# Building the images
###############################################################################
COMPLIANCE_SERVER_CONTAINER_CREATED=.compliance-server.created-$(ARCH)
COMPLIANCE_CONTROLLER_CONTAINER_CREATED=.compliance-controller.created-$(ARCH)
COMPLIANCE_SNAPSHOTTER_CONTAINER_CREATED=.compliance-snapshotter.created-$(ARCH)
COMPLIANCE_REPORTER_CONTAINER_CREATED=.compliance-reporter.created-$(ARCH)
COMPLIANCE_BENCHMARKER_CONTAINER_CREATED=.compliance-benchmarker.created-$(ARCH)

# Build the images for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

# Build the tigera/compliance-server docker image, which contains only Compliance server.
$(COMPLIANCE_SERVER_IMAGE): $(COMPLIANCE_SERVER_CONTAINER_CREATED)
$(COMPLIANCE_SERVER_CONTAINER_CREATED): docker-image/server/Dockerfile bin/server-$(ARCH)
	$(DOCKER_BUILD) -t $(COMPLIANCE_SERVER_IMAGE):latest-$(ARCH) -f docker-image/server/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(COMPLIANCE_SERVER_IMAGE)
	touch $@

# Build the tigera/compliance-controller docker image, which contains only Compliance controller.
$(COMPLIANCE_CONTROLLER_IMAGE): $(COMPLIANCE_CONTROLLER_CONTAINER_CREATED)
$(COMPLIANCE_CONTROLLER_CONTAINER_CREATED): docker-image/controller/Dockerfile bin/controller-$(ARCH)
	$(DOCKER_BUILD) -t $(COMPLIANCE_CONTROLLER_IMAGE):latest-$(ARCH) -f docker-image/controller/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(COMPLIANCE_CONTROLLER_IMAGE)
	touch $@

# Build the tigera/compliance-snapshotter docker image, which contains only Compliance snapshotter.
$(COMPLIANCE_SNAPSHOTTER_IMAGE): $(COMPLIANCE_SNAPSHOTTER_CONTAINER_CREATED)
$(COMPLIANCE_SNAPSHOTTER_CONTAINER_CREATED): docker-image/snapshotter/Dockerfile bin/snapshotter-$(ARCH)
	$(DOCKER_BUILD) -t $(COMPLIANCE_SNAPSHOTTER_IMAGE):latest-$(ARCH) -f docker-image/snapshotter/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(COMPLIANCE_SNAPSHOTTER_IMAGE)
	touch $@

# Build the tigera/compliance-reporter docker image, which contains only Compliance reporter.
$(COMPLIANCE_REPORTER_IMAGE): $(COMPLIANCE_REPORTER_CONTAINER_CREATED)
$(COMPLIANCE_REPORTER_CONTAINER_CREATED): docker-image/reporter/Dockerfile bin/reporter-$(ARCH)
	$(DOCKER_BUILD) -t $(COMPLIANCE_REPORTER_IMAGE):latest-$(ARCH) -f docker-image/reporter/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(COMPLIANCE_REPORTER_IMAGE)
	touch $@

# Build the tigera/compliance-benchmarker docker image, which contains only Compliance benchmarker.
KUBE_BENCH_VERSION := $(shell grep -E 'github.com/aquasecurity/kube-bench' ../go.mod | awk '{print$$2;exit}')
$(COMPLIANCE_BENCHMARKER_IMAGE): $(COMPLIANCE_BENCHMARKER_CONTAINER_CREATED)
$(COMPLIANCE_BENCHMARKER_CONTAINER_CREATED): register docker-image/benchmarker/Dockerfile bin/benchmarker-$(ARCH) bin/kube-bench-$(ARCH) bin/kubectl-$(ARCH)
	$(DOCKER_BUILD) --build-arg KUBE_BENCH_VERSION=$(KUBE_BENCH_VERSION) -t $(COMPLIANCE_BENCHMARKER_IMAGE):latest-$(ARCH) -f docker-image/benchmarker/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(COMPLIANCE_BENCHMARKER_IMAGE)
	touch $@

.PHONY: clean
clean:
	rm -rf bin
	find . -name "*.coverprofile" -type f -delete
	find . -name "coverage.xml" -type f -delete
	find . -name ".coverage" -type f -delete
	find . -name "*.pyc" -type f -delete
	rm -f $(COMPLIANCE_SERVER_CONTAINER_CREATED)
	rm -f $(COMPLIANCE_CONTROLLER_CONTAINER_CREATED)
	rm -f $(COMPLIANCE_SNAPSHOTTER_CONTAINER_CREATED)
	rm -f $(COMPLIANCE_REPORTER_CONTAINER_CREATED)
	rm -f $(COMPLIANCE_BENCHMARKER_CONTAINER_CREATED)
	-docker image rm -f $$(docker images $(COMPLIANCE_SERVER_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(COMPLIANCE_CONTROLLER_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(COMPLIANCE_SNAPSHOTTER_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(COMPLIANCE_REPORTER_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(COMPLIANCE_BENCHMARKER_IMAGE) -a -q)

###############################################################################
# Tests
###############################################################################
.PHONY: ut
ut combined.coverprofile: run-elastic run-linseed
	@echo Running Go UTs.
	$(DOCKER_RUN) -e LINSEED_DIR=/go/src/github.com/projectcalico/calico/linseed $(CALICO_BUILD) utils/run-coverage sh -c '$(GIT_CONFIG_SSH)'

run-linseed:
	$(MAKE) -C ../linseed image gen-certs run-image

###############################################################################
# CI/CD
###############################################################################
.PHONY: cd ci

# Builds the code and runs all tests.
ci: clean static-checks image ut

# Deploys images to registry
cd: image-all cd-common

###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
.PHONY: ut-no-cover
ut-no-cover: $(SRC_FILES)
	@echo Running Go UTs without coverage.
	$(DOCKER_RUN) $(CALICO_BUILD) ginkgo -r $(GINKGO_OPTIONS)

.PHONY: ut-watch
ut-watch: $(SRC_FILES)
	@echo Watching go UTs for changes...
	$(DOCKER_RUN) $(CALICO_BUILD) ginkgo watch -r $(GINKGO_OPTIONS)

# Launch a browser with Go coverage stats for the whole project.
.PHONY: cover-browser
cover-browser: combined.coverprofile
	go tool cover -html="combined.coverprofile"

.PHONY: cover-report
cover-report: combined.coverprofile
	# Print the coverage.  We use sed to remove the verbose prefix and trim down
	# the whitespace.
	@echo
	@echo -------- All coverage ---------
	@echo
	@$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'go tool cover -func combined.coverprofile | \
	                           sed 's=$(PACKAGE_NAME)/==' | \
	                           column -t'
	@echo
	@echo -------- Missing coverage only ---------
	@echo
	@$(DOCKER_RUN) $(CALICO_BUILD) sh -c "go tool cover -func combined.coverprofile | \
	                           sed 's=$(PACKAGE_NAME)/==' | \
	                           column -t | \
	                           grep -v '100\.0%'"
