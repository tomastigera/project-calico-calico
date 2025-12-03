include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/node

# Name of the images.
# e.g., <registry>/<name>:<tag>
NODE_IMAGE            ?=node
# Name of the Enterprise windows image
# The windows image names are:
# - OS: calico/node-windows
# - EE: tigera/node-windows
WINDOWS_IMAGE         ?=$(NODE_IMAGE)-windows

# If this is a windows release build the windows image.  ARCHES will contain the values
# in WINDOWS_VERSIONS (defined in metadata.mk), prefixed with "windows-".
ifdef WINDOWS_RELEASE
BUILD_IMAGES          ?=$(WINDOWS_IMAGE)
ARCHES                ?= $(patsubst %,windows-%,$(WINDOWS_VERSIONS))
else
BUILD_IMAGES          ?=$(NODE_IMAGE)
endif

# Paths within the build container for BPF source.
LIBBPF_CONTAINER_PATH=/go/src/github.com/projectcalico/calico/felix/bpf-gpl/libbpf/src/
BPFGPL_CONTAINER_PATH=/go/src/github.com/projectcalico/calico/felix/bpf-gpl/
LIBBPF_FILE_CREATED=../felix/bpf-gpl/.libbpf-$(LIBBPF_VERSION)

LOCAL_CHECKS = LIBBPF_FILE_CREATED

# Paths within the repository for BPF source.
LIBBPF_A=../felix/bpf-gpl/libbpf/src/$(ARCH)/libbpf.a

# Complete list of files from other directories that we need to build calico/node.
REMOTE_DEPS = $(LIBBPF_A) \
	      filesystem/usr/lib/calico/bpf \
	      filesystem/etc/calico/confd/conf.d \
	      filesystem/etc/calico/confd/templates

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

FIPS ?= false

ifeq ($(FIPS),true)
NODE_CONTAINER_BIN_DIR=dist/bin/$(ARCH)-fips
NODE_CONTAINER_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-node-$(ARCH)
NODE_CONTAINER_MARKER=$(NODE_CONTAINER_FIPS_CREATED)
VALIDARCHES=amd64
else
NODE_CONTAINER_BIN_DIR=dist/bin
NODE_CONTAINER_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-node-$(ARCH)
NODE_CONTAINER_MARKER=$(NODE_CONTAINER_CREATED)
endif

# Set the platform correctly for building docker images.
ifeq ($(ARCH),arm64)
# Required for eBPF support in ARM64.
# We need to force ARM64 build image to be used in a crosscompilation run.
CALICO_BUILD:=$(CALICO_BUILD)-$(ARCH)
endif

###############################################################################

# Our (public) GCP bucket where we mirror any third party files
# that are flaky to retrieve.
THIRD_PARTY_DEPS_MIRROR=https://storage.googleapis.com/public-calico-third-party-deps

# Versions and location of dependencies used in the build.
BIRD_IMAGE ?= calico/bird:$(BIRD_VERSION)-$(ARCH)
BIRD_SOURCE=filesystem/included-source/bird-$(BIRD_VERSION).tar.gz
BIRD_DIND_IMAGE ?= calico/bird-dind:$(BIRD_VERSION)-$(ARCH)
FELIX_GPL_SOURCE=filesystem/included-source/felix-ebpf-gpl.tar.xz
INCLUDED_SOURCE=$(BIRD_SOURCE) $(FELIX_GPL_SOURCE)

# Versions and locations of dependencies used in tests.
TEST_CONTAINER_NAME_VER?=latest
TEST_CONTAINER_NAME?=calico/test:$(TEST_CONTAINER_NAME_VER)-$(ARCH)

TEST_CONTAINER_FILES=$(shell find tests/ -type f ! -name '*.created' ! -name '*.pyc' ! -name '*.tmp' )

# Variables controlling the image
NODE_CONTAINER_CREATED=.calico_node.created-$(ARCH)
NODE_CONTAINER_FIPS_CREATED=.calico_node.created-$(ARCH)-fips
WINDOWS_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-node.exe
TOOLS_MOUNTNS_BINARY = $(NODE_CONTAINER_BIN_DIR)/mountns-$(ARCH)
NONCLUSTER_HOST_INIT_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-noncluster-host-init-$(ARCH)
NODE_RELEASE_VERSION?=$(call git-release-tag-from-dev-tag)

WINDOWS_INSTALL_SCRIPT := dist/install-calico-windows.ps1

# Variables for the Windows packaging.
# Name of the Windows release ZIP archive.
WINDOWS_PACKAGING_ROOT := windows-packaging
WINDOWS_ARCHIVE_ROOT := windows-packaging/CalicoWindows
WINDOWS_ARCHIVE_BINARY := $(WINDOWS_ARCHIVE_ROOT)/calico-node.exe
WINDOWS_ARCHIVE_TAG?=$(GIT_VERSION)
WINDOWS_ARCHIVE := dist/tigera-calico-windows-$(WINDOWS_ARCHIVE_TAG).zip
# Version of NSSM to download.
# We host nssm ourselves in Calico OSS, when updating the version number the new zip needs to be added to release artifacts
WINDOWS_NSSM_VERSION=2.24-103-gdee49fc
# Original source: https://nssm.cc/ci/nssm-$(WINDOWS_NSSM_VERSION).zip
WINDOWS_NSSM_URL=$(THIRD_PARTY_DEPS_MIRROR)/nssm/nssm-$(WINDOWS_NSSM_VERSION).zip
# Explicit list of files that we copy in from the mod cache.  This is required because the copying rules we use are pattern-based
# and they only work with an explicit rule of the form "$(WINDOWS_MOD_CACHED_FILES): <file path from project root>" (otherwise,
# make has no way to know that the mod cache target produces the files we need).
WINDOWS_MOD_CACHED_FILES := \
    windows-packaging/config-bgp.ps1 \
    windows-packaging/config-bgp.psm1 \
    windows-packaging/conf.d/blocks.toml \
    windows-packaging/conf.d/peerings.toml \
    windows-packaging/templates/blocks.ps1.template \
    windows-packaging/templates/peerings.ps1.template

# Files to include in the Windows ZIP archive.  We need to list some of these explicitly
# because we need to force them to be built/copied into place. We also have
# tests in windows-packaging that we don't want to include.
WINDOWS_ARCHIVE_FILES := \
    $(WINDOWS_ARCHIVE_BINARY) \
    $(WINDOWS_ARCHIVE_ROOT)/README.txt \
    $(WINDOWS_ARCHIVE_ROOT)/*.ps1 \
    $(WINDOWS_ARCHIVE_ROOT)/node/node-service.ps1 \
    $(WINDOWS_ARCHIVE_ROOT)/felix/felix-service.ps1 \
    $(WINDOWS_ARCHIVE_ROOT)/confd/confd-service.ps1 \
    $(WINDOWS_ARCHIVE_ROOT)/confd/config-bgp.ps1 \
    $(WINDOWS_ARCHIVE_ROOT)/confd/config-bgp.psm1 \
    $(WINDOWS_ARCHIVE_ROOT)/confd/conf.d/blocks.toml \
    $(WINDOWS_ARCHIVE_ROOT)/confd/conf.d/peerings.toml \
    $(WINDOWS_ARCHIVE_ROOT)/confd/templates/blocks.ps1.template \
    $(WINDOWS_ARCHIVE_ROOT)/confd/templates/peerings.ps1.template \
    $(WINDOWS_ARCHIVE_ROOT)/cni/calico.exe \
    $(WINDOWS_ARCHIVE_ROOT)/cni/calico-ipam.exe \
    $(WINDOWS_ARCHIVE_ROOT)/libs/hns/hns.psm1 \
    $(WINDOWS_ARCHIVE_ROOT)/libs/hns/License.txt \
    $(WINDOWS_ARCHIVE_ROOT)/libs/calico/calico.psm1

MICROSOFT_SDN_VERSION := 0d7593e5c8d4c2347079a7a6dbd9eb034ae19a44
MICROSOFT_SDN_GITHUB_RAW_URL := https://raw.githubusercontent.com/microsoft/SDN/$(MICROSOFT_SDN_VERSION)

# Variables used by the tests
ST_TO_RUN?=tests/st/

# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

K8ST_REPORT_FILENAME ?= k8s-tests.xml

# Filesystem of the node container that is checked in to this repository.
NODE_CONTAINER_FILES=$(shell find ./filesystem -type f)

# Calculate a timestamp for any build artefacts.
DATE:=$(shell date -u +'%FT%T%z')

# Source golang files on which compiling the calico-node binary depends.
SRC_FILES=$(shell find ./pkg -name '*.go') \
	  $(shell find ./cmd -name '*.go') \
	  $(shell find ../felix -name '*.go') \
	  $(shell find ../typha -name '*.go') \
	  $(shell find ../felix -name '*.[ch]') \
	  $(shell find ../libcalico-go -name '*.go') \
	  $(shell find ../goldmane -name '*.go') \
	  $(shell find ../confd -name '*.go')

## Clean enough that a new release build will be clean
clean: clean-windows
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	find . -name '*.pyc' -exec rm -f {} +
	rm -f calico-node.tar.gz rhel/calico-node.spec
	rm -rf $(REMOTE_DEPS)
	rm -rf bin
	rm -rf certs *.tar $(NODE_CONTAINER_BIN_DIR)
	rm -rf dist
	rm -rf filesystem/included-source
	rm -rf package
	rm -rf tests/k8st/infra/operator
	# We build these as part of the node build, so clean them as part of the clean.
	make -C ../felix clean
	# Delete images that we built in this repo
	-docker image rm -f $$(docker images $(NODE_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(NODE_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(TEST_CONTAINER_NAME) -a -q)

clean-windows: clean-windows-builder
	rm -f $(WINDOWS_ARCHIVE) $(WINDOWS_ARCHIVE_BINARY) $(WINDOWS_BINARY)
	rm -f $(WINDOWS_ARCHIVE_ROOT)/libs/hns/hns.psm1
	rm -f $(WINDOWS_ARCHIVE_ROOT)/libs/hns/License.txt
	rm -f $(WINDOWS_ARCHIVE_ROOT)/cni/*.exe
	rm -f $(WINDOWS_ARCHIVE_ROOT)/../nssm.zip
	rm -f $(WINDOWS_ARCHIVE_ROOT)/../nssm.exe
	rm -f $(WINDOWS_INSTALL_SCRIPT)
	rm -rf "$(WINDOWS_DIST)"
	-docker image rm -f $$(docker images $(WINDOWS_IMAGE) -a -q)

###############################################################################
# Building the binary
###############################################################################
build: $(NODE_CONTAINER_MARKER) $(TOOLS_MOUNTNS_BINARY) $(NONCLUSTER_HOST_INIT_BINARY)

# Pull in config from confd.
filesystem/etc/calico/confd/conf.d: $(shell find ../confd/etc/calico/confd/conf.d -type f)
	rm -rf $@ && cp -r ../confd/etc/calico/confd/conf.d $@
	chmod +w $@

filesystem/etc/calico/confd/templates: $(shell find ../confd/etc/calico/confd/templates -type f)
	rm -rf $@ && cp -r ../confd/etc/calico/confd/templates $@
	chmod +w $@

$(LIBBPF_A): $(shell find ../felix/bpf-gpl/libbpf -type f -name '*.[ch]')
	make -C ../felix libbpf ARCH=$(ARCH)

filesystem/usr/lib/calico/bpf: $(shell find ../felix/bpf-gpl -type f) $(shell find ../felix/bpf-apache -type f)
	rm -rf filesystem/usr/lib/calico/bpf/ && mkdir -p filesystem/usr/lib/calico/bpf/
	make -C ../felix build-bpf ARCH=$(ARCH)
	cp -r ../felix/bpf-gpl/bin/* $@
	cp -r ../felix/bpf-apache/bin/* $@

# We need CGO when compiling in Felix for BPF support.
# Currently CGO can be enabled in ARM64 and AMD64 builds.
ifeq ($(ARCH),$(filter $(ARCH),amd64 arm64))
CGO_ENABLED=1
CGO_LDFLAGS="-L$(LIBBPF_CONTAINER_PATH)/$(ARCH) -lbpf -lelf -lz"
CGO_CFLAGS="-I$(LIBBPF_CONTAINER_PATH) -I$(BPFGPL_CONTAINER_PATH)"
else
CGO_ENABLED=0
CGO_LDFLAGS=""
CGO_CFLAGS=""
endif

$(NODE_CONTAINER_BINARY): filesystem/usr/lib/calico/bpf $(LIBBPF_A) $(SRC_FILES) ../go.mod
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/calico-node/main.go, $@)
else
ifeq ($(ARCH),$(filter $(ARCH),amd64 arm64))
	$(call build_cgo_binary, ./cmd/calico-node/main.go, $@)
else
	$(call build_binary, ./cmd/calico-node/main.go, $@)
endif
endif

LIBBPF_FILE_CREATED:
	make -C ../felix clone-libbpf

$(WINDOWS_BINARY): $(SRC_FILES)
	$(call build_cgo_windows_binary, ./cmd/calico-node/main.go, $@)

$(WINDOWS_ARCHIVE_ROOT)/cni/calico.exe:
	$(call build_windows_binary, ./cmd/calico, $@)

$(WINDOWS_ARCHIVE_ROOT)/cni/calico-ipam.exe:
	$(call build_windows_binary, ./cmd/calico-ipam, $@)

$(TOOLS_MOUNTNS_BINARY):
ifeq ($(CGO_ENABLED),1)
	$(call build_cgo_binary, ./cmd/mountns, $@)
else
	$(call build_binary, ./cmd/mountns, $@)
endif

$(NONCLUSTER_HOST_INIT_BINARY):
	$(call build_binary, ./cmd/calico-noncluster-host-init, $@)

###############################################################################
# Building the image
###############################################################################
## Create the images for all supported ARCHes
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image FIPS=$(FIPS) ARCH=$*

image $(NODE_IMAGE): $(NODE_CONTAINER_MARKER)
$(NODE_CONTAINER_CREATED): $(REMOTE_DEPS) ./Dockerfile.$(ARCH) $(NODE_CONTAINER_BINARY) $(INCLUDED_SOURCE) $(NODE_CONTAINER_FILES) $(TOOLS_MOUNTNS_BINARY)
	$(DOCKER_BUILD) --network=host --build-arg BIN_DIR=$(NODE_CONTAINER_BIN_DIR) --build-arg BIRD_IMAGE=$(BIRD_IMAGE) -t $(NODE_IMAGE):latest-$(ARCH) -f Dockerfile.$(ARCH) .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	docker run $(NODE_IMAGE):latest-$(ARCH) versions
	touch $@

$(NODE_CONTAINER_FIPS_CREATED): $(REMOTE_DEPS) ./Dockerfile.$(ARCH) $(NODE_CONTAINER_BINARY) $(INCLUDED_SOURCE) $(NODE_CONTAINER_FILES) $(TOOLS_MOUNTNS_BINARY)
	$(DOCKER_BUILD) --network=host --build-arg BIN_DIR=$(NODE_CONTAINER_BIN_DIR) --build-arg BIRD_IMAGE=$(BIRD_IMAGE) -t $(NODE_IMAGE):latest-fips-$(ARCH) -f Dockerfile.$(ARCH) .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

###############################################################################
# Package
###############################################################################
.PHONY: init-package
init-package: $(NODE_CONTAINER_BINARY) $(NONCLUSTER_HOST_INIT_BINARY)
	cp $(NODE_CONTAINER_BINARY) calico-node
	cp $(NONCLUSTER_HOST_INIT_BINARY) calico-noncluster-host-init
	tar zcf calico-node.tar.gz calico-node calico-noncluster-host-init calico-node.conf calico-node.env calico-node.service filesystem/usr/lib/calico/bpf
	rm -f calico-node calico-noncluster-host-init

.PHONY: package
package: calico-node.debian12 \
         calico-node.debian13 \
         calico-node.rhel8 \
         calico-node.rhel9 \
         calico-node.ubuntu22 \
         calico-node.ubuntu24

.PHONY: calico-node.debian12
calico-node.debian12: bin/yq host-native-build init-package debian/changelog.in debian/control.in
	sed -e 's/@BPFTOOL_PACKAGE@/bpftool/g' debian/control.in > debian/control
	$(call host_native_deb_build,debian12,calico-node,,bookworm,0)

.PHONY: calico-node.debian13
calico-node.debian13: bin/yq host-native-build init-package debian/changelog.in debian/control.in
	sed -e 's/@BPFTOOL_PACKAGE@/bpftool/g' debian/control.in > debian/control
	$(call host_native_deb_build,debian13,calico-node,,trixie,0)

.PHONY: calico-node.rhel8
calico-node.rhel8: bin/yq host-native-build init-package rhel/calico-node.spec.in
	$(call host_native_rpm_build,rhel8,calico-node,)

.PHONY: calico-node.rhel9
calico-node.rhel9: bin/yq host-native-build init-package rhel/calico-node.spec.in
	$(call host_native_rpm_build,rhel9,calico-node,)

.PHONY: calico-node.ubuntu22
calico-node.ubuntu22: bin/yq host-native-build init-package debian/changelog.in debian/control.in
	sed -e 's/@BPFTOOL_PACKAGE@/linux-tools-common/g' debian/control.in > debian/control
	$(call host_native_deb_build,ubuntu22,calico-node,,jammy,0)

.PHONY: calico-node.ubuntu24
calico-node.ubuntu24: bin/yq host-native-build init-package debian/changelog.in debian/control.in
	sed -e 's/@BPFTOOL_PACKAGE@/bpftool/g' debian/control.in > debian/control
	$(call host_native_deb_build,ubuntu24,calico-node,,noble,0)

##########################################################################################
# TESTING
##########################################################################################

GINKGO_ARGS += -cover -timeout 20m --trace --v
GINKGO = ginkgo

#############################################
# Run unit level tests
#############################################
# Skip packages containing FV tests.
UT_PACKAGES_TO_SKIP?=pkg/lifecycle/startup,pkg/allocateip,pkg/status
.PHONY: ut
ut:
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) ginkgo -r -skipPackage=$(UT_PACKAGES_TO_SKIP) $(GINKGO_ARGS)'

# download BIRD source to include in image.
$(BIRD_SOURCE): .bird-source.created
.bird-source.created:
	rm -rf filesystem/included-source/bird*
	mkdir -p filesystem/included-source/
	curl -sSf -L --retry 5 -o $(BIRD_SOURCE) https://github.com/projectcalico/bird/tarball/$(BIRD_VERSION)
	touch $@

# include GPL felix code in the image.
$(FELIX_GPL_SOURCE): .felix-gpl-source.created
.felix-gpl-source.created: $(shell find ../felix/bpf-gpl -type f)
	rm -rf filesystem/included-source/felix*
	mkdir -p filesystem/included-source/
	tar cf $(FELIX_GPL_SOURCE) ../felix/bpf-gpl --use-compress-program="xz -T0"
	touch $@

###############################################################################
# FV Tests
###############################################################################
K8ST_IMAGE_TARS=calico-node.tar \
	calico-typha.tar \
	calico-apiserver.tar \
	calico-cni.tar \
	pod2daemon.tar \
	csi.tar \
	node-driver-registrar.tar \
	calicoctl.tar \
	kube-controllers.tar \
	operator.tar

# Add in enterprise-only images.
ENTERPRISE_IMAGE_TARS=egress-gateway.tar calico-queryserver.tar egress-gateway.tar prometheus-operator.tar config-reloader.tar prometheus.tar prometheus-service.tar alertmanager.tar fluentd.tar policy-rec.tar eck.tar manager.tar voltron.tar ui-apis.tar kibana.tar elastic.tar es-gw.tar linseed.tar idc.tar webhooks-processor.tar dashboards-installer.tar es-metrics.tar manager.tar
K8ST_IMAGE_TARS += $(ENTERPRISE_IMAGE_TARS)

ifeq ($(SEMAPHORE_GIT_REF_TYPE), pull-request)
# Determine the tests to run using the test spider tool, which emits a list of impacted packages.
WHAT=$(shell $(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) go run ../hack/test/spider -commit-range=${SEMAPHORE_GIT_COMMIT_RANGE} -filter-dir node/')
else
# By default, run all tests.
WHAT=$(shell find . -name "*_test.go" | xargs dirname | sort -u)
endif

## Run the ginkgo tests.
ut fv: $(LIBBPF_A) run-k8s-apiserver
	$(DOCKER_RUN) \
	-v $(CERTS_PATH):/home/user/certs \
	-e KUBECONFIG=/go/src/github.com/projectcalico/calico/hack/test/certs/kubeconfig \
	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 \
	-e GINKGO_ARGS="$(GINKGO_ARGS)" \
	$(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) ./run-uts $(WHAT)'

###############################################################################
# System tests
###############################################################################
dist/calicoctl:
	mkdir -p dist
	make -C ../calicoctl build
	cp ../calicoctl/bin/calicoctl-linux-$(ARCH) $@

dist/calico dist/calico-ipam:
	mkdir -p dist
	make -C ../cni-plugin build
	cp ../cni-plugin/bin/$(ARCH)/calico dist/calico
	cp ../cni-plugin/bin/$(ARCH)/calico-ipam dist/calico-ipam

# Create images for containers used in the tests
busybox.tar:
	docker pull $(ARCH)/busybox:latest
	docker save --output busybox.tar $(ARCH)/busybox:latest

workload.tar: workload/Dockerfile
	$(DOCKER_BUILD) -t workload -f workload/Dockerfile workload
	docker save --output workload.tar workload

IPT_ALLOW_ETCD:=-A INPUT -i docker0 -p tcp --dport 2379 -m comment --comment "calico-st-allow-etcd" -j ACCEPT

# Create the calico/test image
test_image: .calico_test.created
.calico_test.created: calico_test/Dockerfile $(TEST_CONTAINER_FILES)
	$(DOCKER_BUILD) --build-arg ETCD_VERSION=$(ETCD_VERSION) --build-arg K8S_VERSION=$(K8S_VERSION) -f calico_test/Dockerfile -t $(TEST_CONTAINER_NAME) calico_test
	touch $@

chart: ../bin/tigera-operator-$(GIT_VERSION).tgz
../bin/tigera-operator-$(GIT_VERSION).tgz:
	make -C ../ bin/tigera-operator-$(GIT_VERSION).tgz

# Tag to use for images built for e2e testing. This must match the image tag used in
# tests/k8st/infra/calico_versions.yml
TEST_BUILD_TAG=test-build

# Default the branch used when pulling images, but allow it to be overridden.
RELEASE_BRANCH ?= master

operator.tar: $(K8ST_IMAGE_TARS) tests/k8st/infra/calico_versions.yml tests/k8st/infra/enterprise_versions.yml
	cd tests/k8st/infra/ && BRANCH=$(OPERATOR_BRANCH) ./build-operator.sh
	docker save --output $@ docker.io/tigera/operator:$(TEST_BUILD_TAG)

calico-node.tar: $(NODE_CONTAINER_CREATED)
	docker tag $(NODE_IMAGE):latest-$(ARCH) tigera/node:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/node:$(TEST_BUILD_TAG)

calico-typha.tar: ../go.mod $(shell find ../typha -name '*.go') $(shell find ../libcalico-go -name '*.go')
	make -C ../typha image
	docker tag tigera/typha:latest-$(ARCH) tigera/typha:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/typha:$(TEST_BUILD_TAG)

calico-apiserver.tar: ../go.mod $(shell find ../apiserver -name '*.go') $(shell find ../libcalico-go -name '*.go')
	make -C ../apiserver image
	docker tag tigera/apiserver:latest-$(ARCH) tigera/apiserver:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/apiserver:$(TEST_BUILD_TAG)

calico-cni.tar: ../go.mod $(shell find ../cni-plugin -name '*.go') $(shell find ../libcalico-go -name '*.go')
	make -C ../cni-plugin image
	docker tag tigera/cni:latest-$(ARCH) tigera/cni:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/cni:$(TEST_BUILD_TAG)

csi.tar: ../go.mod $(shell find ../pod2daemon/ -name '*.go')
	make -C ../pod2daemon image
	docker tag tigera/csi:latest-$(ARCH) tigera/csi:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/csi:$(TEST_BUILD_TAG)

node-driver-registrar.tar: ../go.mod $(shell find ../pod2daemon/ -name '*.go')
	make -C ../pod2daemon image
	docker tag tigera/node-driver-registrar:latest-$(ARCH) tigera/node-driver-registrar:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/node-driver-registrar:$(TEST_BUILD_TAG)

pod2daemon.tar: ../go.mod $(shell find ../pod2daemon/ -name '*.go')
	make -C ../pod2daemon image
	docker tag tigera/pod2daemon-flexvol:latest-$(ARCH) tigera/pod2daemon-flexvol:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/pod2daemon-flexvol:$(TEST_BUILD_TAG)

calicoctl.tar: ../go.mod $(shell find ../calicoctl -name '*.go') $(shell find ../libcalico-go -name '*.go')
	make -C ../calicoctl image
	docker tag tigera/calicoctl:latest-$(ARCH) tigera/calicoctl:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/calicoctl:$(TEST_BUILD_TAG)

kube-controllers.tar: ../go.mod $(shell find ../kube-controllers -name '*.go') $(shell find ../libcalico-go -name '*.go')
	make -C ../kube-controllers image
	docker tag tigera/kube-controllers:latest-$(ARCH) tigera/kube-controllers:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/kube-controllers:$(TEST_BUILD_TAG)

# Enterprise-only tar files below here.
calico-queryserver.tar:
	make -C ../queryserver image
	docker tag tigera/queryserver:latest-$(ARCH) tigera/queryserver:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/queryserver:$(TEST_BUILD_TAG)

egress-gateway.tar: ../go.mod $(shell find ../egress-gateway -name '*.go') ../egress-gateway/* $(shell find ../libcalico-go -name '*.go')
	make -C ../egress-gateway image
	docker tag tigera/egress-gateway:latest-$(ARCH) tigera/egress-gateway:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/egress-gateway:$(TEST_BUILD_TAG)

prometheus-operator.tar:
	make -C ../third_party/prometheus-operator image
	docker tag tigera/prometheus-operator:latest-$(ARCH) tigera/prometheus-operator:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/prometheus-operator:$(TEST_BUILD_TAG)

config-reloader.tar:
	make -C ../third_party/prometheus-operator image
	docker tag tigera/prometheus-config-reloader:latest-$(ARCH) tigera/prometheus-config-reloader:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/prometheus-config-reloader:$(TEST_BUILD_TAG)

prometheus.tar:
	# TODO: Build this. We cannot at the moment because it relies on the host OS npm / go toolchain.
	# make -C ../third_party/prometheus image
	# docker tag tigera/prometheus:latest-$(ARCH) tigera/prometheus:$(TEST_BUILD_TAG)
	docker pull gcr.io/unique-caldron-775/cnx/tigera/prometheus:$(RELEASE_BRANCH)
	docker tag gcr.io/unique-caldron-775/cnx/tigera/prometheus:$(RELEASE_BRANCH) tigera/prometheus:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/prometheus:$(TEST_BUILD_TAG)

prometheus-service.tar:
	make -C ../prometheus-service/ image
	docker tag  tigera/prometheus-service:latest-amd64 tigera/prometheus-service:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/prometheus-service:$(TEST_BUILD_TAG)

fluentd.tar:
	make -C ../fluentd image THIRD_PARTY_REGISTRY=$(THIRD_PARTY_REGISTRY_CD)
	docker tag tigera/fluentd:latest-$(ARCH) tigera/fluentd:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/fluentd:$(TEST_BUILD_TAG)

policy-rec.tar:
	make -C ../policy-recommendation/ image
	docker tag tigera/policy-recommendation:latest-$(ARCH) tigera/policy-recommendation:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/policy-recommendation:$(TEST_BUILD_TAG)

eck.tar:
	make -C ../third_party/eck-operator/ image
	docker tag tigera/eck-operator:latest-$(ARCH) tigera/eck-operator:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/eck-operator:$(TEST_BUILD_TAG)

alertmanager.tar:
	# TODO: Build this.
	docker pull gcr.io/unique-caldron-775/cnx/tigera/alertmanager:$(RELEASE_BRANCH)
	docker tag gcr.io/unique-caldron-775/cnx/tigera/alertmanager:$(RELEASE_BRANCH) tigera/alertmanager:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/alertmanager:$(TEST_BUILD_TAG)

elastic.tar:
	# TODO: Build this.
	docker pull gcr.io/unique-caldron-775/cnx/tigera/elasticsearch:$(RELEASE_BRANCH)
	docker tag gcr.io/unique-caldron-775/cnx/tigera/elasticsearch:$(RELEASE_BRANCH) tigera/elasticsearch:$(TEST_BUILD_TAG)
	# make -C ../third_party/elasticsearch/ image
	# docker tag tigera/elasticsearch:latest-$(ARCH) tigera/elasticsearch:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/elasticsearch:$(TEST_BUILD_TAG)

kibana.tar:
	# TODO: Can we run without kibana? Requires operator change.
	docker pull gcr.io/unique-caldron-775/cnx/tigera/kibana:$(RELEASE_BRANCH)
	docker tag gcr.io/unique-caldron-775/cnx/tigera/kibana:$(RELEASE_BRANCH) tigera/kibana:$(TEST_BUILD_TAG)
	# make -C ../third_party/kibana/ image
	# docker tag tigera/kibana:latest-$(ARCH) tigera/kibana:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/kibana:$(TEST_BUILD_TAG)

manager.tar:
	# TODO
	docker pull gcr.io/unique-caldron-775/cnx/tigera/manager:$(RELEASE_BRANCH)
	docker tag gcr.io/unique-caldron-775/cnx/tigera/manager:$(RELEASE_BRANCH) tigera/manager:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/manager:$(TEST_BUILD_TAG)

ui-apis.tar:
	make -C ../ui-apis image
	docker tag tigera/ui-apis:latest-$(ARCH) tigera/ui-apis:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/ui-apis:$(TEST_BUILD_TAG)

es-gw.tar:
	make -C ../es-gateway image
	docker tag tigera/es-gateway:latest-$(ARCH) tigera/es-gateway:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/es-gateway:$(TEST_BUILD_TAG)

voltron.tar:
	make -C ../voltron image
	docker tag tigera/voltron:latest-$(ARCH) tigera/voltron:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/voltron:$(TEST_BUILD_TAG)

linseed.tar:
	make -C ../linseed image
	docker tag tigera/linseed:latest-$(ARCH) tigera/linseed:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/linseed:$(TEST_BUILD_TAG)

idc.tar:
	make -C ../intrusion-detection-controller image
	docker tag tigera/intrusion-detection-controller:latest-$(ARCH) tigera/intrusion-detection-controller:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/intrusion-detection-controller:$(TEST_BUILD_TAG)

webhooks-processor.tar:
	make -C ../webhooks-processor image
	docker tag tigera/webhooks-processor:latest-$(ARCH) tigera/webhooks-processor:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/webhooks-processor:$(TEST_BUILD_TAG)

dashboards-installer.tar:
	make -C ../intrusion-detection-controller intrusion-detection-job-installer
	docker tag tigera/intrusion-detection-job-installer:latest-$(ARCH) tigera/intrusion-detection-job-installer:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/intrusion-detection-job-installer:$(TEST_BUILD_TAG)

es-metrics.tar:
	make -C ../elasticsearch-metrics image
	docker tag tigera/elasticsearch-metrics:latest-$(ARCH) tigera/elasticsearch-metrics:$(TEST_BUILD_TAG)
	docker save --output $@ tigera/elasticsearch-metrics:$(TEST_BUILD_TAG)

goldmane.tar: ../go.mod $(shell find ../goldmane -name '*.go')
	make -C ../goldmane image
	docker tag calico/goldmane:latest-$(ARCH) calico/goldmane:$(TEST_BUILD_TAG)
	docker save --output $@ calico/goldmane:$(TEST_BUILD_TAG)

whisker.tar: ../go.mod $(shell find ../whisker)
	make -C ../whisker image
	docker tag calico/whisker:latest-$(ARCH) calico/whisker:$(TEST_BUILD_TAG)
	docker save --output $@ calico/whisker:$(TEST_BUILD_TAG)

whisker-backend.tar: ../go.mod $(shell find ../whisker-backend -name '*.go')
	make -C ../whisker-backend image
	docker tag calico/whisker-backend:latest-$(ARCH) calico/whisker-backend:$(TEST_BUILD_TAG)
	docker save --output $@ calico/whisker-backend:$(TEST_BUILD_TAG)

load-container-images: $(K8ST_IMAGE_TARS) $(KUBECTL)
	# Load the latest tar files onto the currently running kind cluster.
	KUBECONFIG=$(KIND_KUBECONFIG) KIND=$(KIND) ./tests/k8st/load_images_on_kind_cluster.sh
	# Restart the Calico containers so they launch with the newly loaded code.
	KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) delete pods -n calico-system --all
	# calicoctl is deployed as a pod on the cluster and needs to be recreated.
	KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) apply -f tests/k8st/infra/calicoctl.yaml

GCR_IO_PULL_SECRET?=${HOME}/secrets/docker_cfg.json
TSEE_TEST_LICENSE?=${HOME}/secrets/license.yaml

#
# Dual ToR Tests
#
.PHONY: dual-tor-test-legacy
dual-tor-test-legacy: $(K8ST_IMAGE_TARS) .calico_test.created dual-tor-setup-legacy dual-tor-run-test dual-tor-cleanup

.PHONY: dual-tor-test
dual-tor-test: $(K8ST_IMAGE_TARS) .calico_test.created dual-tor-setup dual-tor-run-test dual-tor-cleanup

# TODO: dual-tor uses a custom kind build, and so doesn't leverage the common
# kind logic from lib.Makefile.
.PHONY: dual-tor-setup
# In the legacy testbed, dual-tor legacy flags are switched on, to test old dual-tor norms.
# In legacy mode, a node's default routes *must* use a dual-tor network.
LEGACY_ROUTING=false
# Which early-network config file in the dual-tor-test directory to copy to the custom kind-node image
NODE_ENC_FILE=cfg.yaml
DUAL_TOR_DIR=tests/k8st/dual-tor
dual-tor-setup: dual-tor-cleanup kubectl dist/calicoctl $(K8ST_IMAGE_TARS) .calico_test.created tests/k8st/reliable-nc/bin/reliable-nc
	docker build -t calico-test/busybox-with-reliable-nc tests/k8st/reliable-nc
	mkdir -p $(DUAL_TOR_DIR)/tmp
	cp -a $(K8ST_IMAGE_TARS) $(DUAL_TOR_DIR)/tmp/
	docker build \
		--build-arg KINDEST_NODE_VERSION=$(KINDEST_NODE_VERSION_DUAL_TOR) \
		--build-arg EARLY_NETWORK_CONFIG_FILE=$(NODE_ENC_FILE) \
		-t calico/dual-tor-node \
		$(DUAL_TOR_DIR)
	rm -rf $(DUAL_TOR_DIR)/tmp
	GCR_IO_PULL_SECRET=$(GCR_IO_PULL_SECRET) LEGACY_ROUTING=$(LEGACY_ROUTING) STEPS=setup \
	ROUTER_IMAGE=$(BIRD_IMAGE) CALICOCTL=`pwd`/dist/calicoctl $(DUAL_TOR_DIR)/dualtor.sh

.PHONY: dual-tor-setup-legacy
dual-tor-setup-legacy: LEGACY_ROUTING=true
dual-tor-setup-legacy: NODE_ENC_FILE=cfg-legacy.yaml
dual-tor-setup-legacy: dual-tor-setup

DUAL_TOR_ST_TO_RUN=dual-tor-tests/test_dual_tor.py -s --nocapture --nologcapture
.PHONY: dual-tor-run-test
dual-tor-run-test:
	docker run -t --rm \
	    -v $(CURDIR):/code \
	    -v /var/run/docker.sock:/var/run/docker.sock \
	    -v ${HOME}/.kube/kind-config-kind:/root/.kube/config \
	    --privileged \
	    --net host \
	${TEST_CONTAINER_NAME} \
	    sh -c 'echo "container started.." && \
			cd /code/tests/k8st && nosetests $(DUAL_TOR_ST_TO_RUN) -v --with-xunit --xunit-file="/code/report/k8s-dual-tor-tests.xml" --with-timer'

.PHONY: dual-tor-cleanup
dual-tor-cleanup:
	-STEPS=cleanup $(DUAL_TOR_DIR)/dualtor.sh

tests/k8st/reliable-nc/bin/reliable-nc: tests/k8st/reliable-nc/reliable-nc.go
	mkdir -p dist
	$(DOCKER_GO_BUILD) \
	    sh -c 'go build -buildvcs=false -v -o $@ -v $(BUILD_FLAGS) -ldflags "$(LDFLAGS) -s -w" $(PACKAGE_NAME)/tests/k8st/reliable-nc'

## k8st: STs in a real Kubernetes cluster provisioned by KIND
##
## Note: if you're developing and want to see test output as it
## happens, instead of only later and if the test fails, add "-s
## --nocapture --nologcapture" to K8ST_TO_RUN.  For example:
##
## make k8s-test K8ST_TO_RUN="tests/test_dns_policy.py -s --nocapture --nologcapture"
##
## By default, run tests tagged with "vanilla". This excludes dual tor tests from running
## on a test environment which doesn't support dual tor, and excludes egress IP tests which
## reconfigure the cluster configuration.
K8ST_TO_RUN ?= -A vanilla
K8ST_REPORT_FILENAME ?= k8s-tests.xml

.PHONY: k8s-test
k8s-test:
	$(MAKE) kind-k8st-cleanup
	$(MAKE) kind-k8st-setup
	$(MAKE) kind-k8st-run-test

TEST_LICENSE=$(SECRETS_PATH)/license.yaml

.PHONY: kind-k8st-setup
kind-k8st-setup: $(K8ST_IMAGE_TARS) kubectl $(TEST_LICENSE) ../bin/tigera-operator-$(GIT_VERSION).tgz kind-cluster-create
	TSEE_TEST_LICENSE=$(TEST_LICENSE) GCR_IO_PULL_SECRET=$(GCR_IO_PULL_SECRET) KUBECONFIG=$(KIND_KUBECONFIG) KIND=$(KIND) ARCH=$(ARCH) GIT_VERSION=$(GIT_VERSION) ./tests/k8st/deploy_resources_on_kind_cluster.sh

.PHONY: kind-k8st-run-test
kind-k8st-run-test: .calico_test.created $(KIND_KUBECONFIG)
	docker run -t --rm \
	    -v $(CURDIR):/code \
	    -v /var/run/docker.sock:/var/run/docker.sock \
	    -v $(KIND_KUBECONFIG):/root/.kube/config \
	    -e ROUTER_IMAGE=$(BIRD_IMAGE) \
	    --privileged \
	    --net host \
	${TEST_CONTAINER_NAME} \
	    sh -c 'echo "container started.." && \
	     cd /code/tests/k8st && nosetests $(K8ST_TO_RUN) -v --with-xunit --xunit-file="/code/report/$(K8ST_REPORT_FILENAME)" --with-timer'

.PHONY: kind-k8st-cleanup
kind-k8st-cleanup: kind-cluster-destroy

.PHONY: external-network-test
external-network-test:
	$(MAKE) kind-k8st-setup
	$(MAKE) external-network-setup
	$(MAKE) external-network-run-test
	$(MAKE) external-network-cleanup
	$(MAKE) kind-k8st-cleanup

.PHONY: external-network-setup
EXTERNAL_NETWORK_DIR=tests/k8st/external-network
external-network-setup: .calico_test.created external-network-cleanup kubectl dist/calicoctl $(KIND_KUBECONFIG)
	STEPS=setup \
	  ROUTER_IMAGE=$(BIRD_DIND_IMAGE) CALICOCTL=`pwd`/dist/calicoctl KUBECONFIG=$(KIND_KUBECONFIG) $(EXTERNAL_NETWORK_DIR)/external-networks.sh

EXTERNAL_NETWORK_ST_TO_RUN=external-network-tests/test_external_network.py -s --nocapture --nologcapture
.PHONY: external-network-run-test
external-network-run-test: .calico_test.created $(KIND_KUBECONFIG)
	@echo "Starting to run external network tests..."
	docker run -t --rm \
	    -v $(CURDIR):/code \
	    -v /var/run/docker.sock:/var/run/docker.sock \
	    -v $(KIND_KUBECONFIG):/root/.kube/config \
	    --privileged \
	    --net host \
	${TEST_CONTAINER_NAME} \
	    sh -c 'echo "container started..." && \
			cd /code/tests/k8st && nosetests $(EXTERNAL_NETWORK_ST_TO_RUN) -v --with-xunit --xunit-file="/code/report/k8s-enet-tests.xml" --with-timer'

.PHONY: external-network-cleanup
external-network-cleanup:
	STEPS=cleanup \
	  ROUTER_IMAGE=$(BIRD_DIND_IMAGE) CALICOCTL=`pwd`/dist/calicoctl KUBECONFIG=$(KIND_KUBECONFIG)  $(EXTERNAL_NETWORK_DIR)/external-networks.sh

.PHONY: st
## Run the system tests
st: $(REMOTE_DEPS) image dist/calicoctl busybox.tar calico-node.tar workload.tar run-etcd .calico_test.created dist/calico dist/calico-ipam
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# HOST_CHECKOUT_DIR is used for volume mounts on containers started by this one.
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	docker run --uts=host \
		   --pid=host \
		   --net=host \
		   --privileged \
		   -v $(CURDIR):/code \
		   -v $(TSEE_TEST_LICENSE):/license.yaml \
		   -e HOST_CHECKOUT_DIR=$(CURDIR) \
		   -e DEBUG_FAILURES=$(DEBUG_FAILURES) \
		   -e MY_IP=$(LOCAL_IP_ENV) \
		   -e NODE_CONTAINER_NAME=tigera/node:$(TEST_BUILD_TAG) \
		   --rm -t \
		   -v /var/run/docker.sock:/var/run/docker.sock \
		   $(TEST_CONTAINER_NAME) \
		   sh -c 'nosetests $(ST_TO_RUN) -v --with-xunit --xunit-file="/code/report/nosetests.xml" --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: static-checks ut image image-windows

## Deploys images to registry
cd: image-all cd-common

.PHONY: node-test-at
# Run docker-image acceptance tests
node-test-at: release-prereqs
	docker run -v $(CURDIR)/tests/at/calico_node_goss.yaml:/tmp/goss.yaml \
	  $(NODE_IMAGE):$(VERSION) /bin/sh -c ' \
	   apk --no-cache add wget ca-certificates && \
	   wget -q -O /tmp/goss https://github.com/aelsabbahy/goss/releases/download/v0.3.4/goss-linux-amd64 && \
	   chmod +rx /tmp/goss && \
	   /tmp/goss --gossfile /tmp/goss.yaml validate'

ensure-calico-version-release-defined:
ifndef CALICO_VERSION_RELEASE
	$(error CALICO_VERSION_RELEASE is undefined - run using make release CALICO_VERSION_RELEASE=vX.Y.Z)
endif

###############################################################################
# Windows packaging
###############################################################################
# Pull the BGP configuration scripts and templates from the confd repo.
$(WINDOWS_MOD_CACHED_FILES):

$(WINDOWS_ARCHIVE_ROOT)/confd/config-bgp%: windows-packaging/config-bgp%
	cp -r ../confd/$< $@
	chmod +w $@

$(WINDOWS_ARCHIVE_ROOT)/confd/conf.d/%: windows-packaging/conf.d/%
	cp -r ../confd/$< $@
	chmod +w $@

$(WINDOWS_ARCHIVE_ROOT)/confd/templates/%: windows-packaging/templates/%
	cp -r ../confd/$< $@
	chmod +w $@

$(WINDOWS_ARCHIVE_ROOT)/libs/hns/hns.psm1:
	curl -sSf -L --retry 5 -o $@ $(MICROSOFT_SDN_GITHUB_RAW_URL)/Kubernetes/windows/hns.psm1

$(WINDOWS_ARCHIVE_ROOT)/libs/hns/License.txt:
	curl -sSf -L --retry 5 -o $@  $(MICROSOFT_SDN_GITHUB_RAW_URL)/License.txt

## Download NSSM.
windows-packaging/nssm.zip:
	curl -sSf -L --retry 5 -o $@ $(WINDOWS_NSSM_URL)

windows-packaging/nssm.exe: windows-packaging/nssm.zip
	cd windows-packaging && \
	sha256sum --check nssm.sha256sum && \
	unzip -o nssm.zip 'nssm-$(WINDOWS_NSSM_VERSION)/win64/nssm.exe' && \
	mv nssm-$(WINDOWS_NSSM_VERSION)/win64/nssm.exe nssm.exe && \
	rm -rf nssm-$(WINDOWS_NSSM_VERSION)/

$(WINDOWS_ARCHIVE): build-windows-archive

.PHONY: build-windows-archive
build-windows-archive: $(WINDOWS_ARCHIVE_FILES) windows-packaging/nssm.zip
	# To be as atomic as possible, we re-do work like unpacking NSSM here.
	-rm -f "$(WINDOWS_ARCHIVE)"
	-rm -rf $(WINDOWS_ARCHIVE_ROOT)/nssm
	mkdir -p dist
	cd windows-packaging && \
	cp -r CalicoWindows TigeraCalico && \
	sha256sum --check nssm.sha256sum && \
	cd TigeraCalico && \
	unzip  ../nssm.zip \
	       -x 'nssm-$(WINDOWS_NSSM_VERSION)/src/*' && \
	mv nssm-$(WINDOWS_NSSM_VERSION) nssm && \
	cd .. && \
	zip -r "../$(WINDOWS_ARCHIVE)" TigeraCalico -x '*.git*'
	@echo
	@echo "Windows archive built at $(WINDOWS_ARCHIVE)"
	rm -rf windows-packaging/TigeraCalico

RELEASE_TAG_REGEX := ^v([0-9]{1,}\.){2}[0-9]{1,}$$
WINDOWS_GCS_BUCKET := gs://tigera-windows/dev/

# This target is just for Calico Enterprise. OS has a different release process.
# When merging, keep the 'release-windows-archive' target in private.
#
# This target builds the Windows installation zip file and uploads it to GCS.
push-windows-archive-gcs: build-windows-archive
	gcloud auth activate-service-account --key-file ~/secrets/gcp-registry-pusher-service-account.json
	gsutil cp dist/tigera-calico-windows-$(GIT_VERSION).zip $(WINDOWS_GCS_BUCKET)
	gcloud auth revoke registry-pusher@unique-caldron-775.iam.gserviceaccount.com

release-verify-version: var-require-all-VERSION
ifdef CONFIRM
	$(if $(filter $(VERSION),$(GIT_VERSION)),,\
		echo Current version $(CURRENT_RELEASE_VERSION) does not match given version $(VERSION) && exit 1)
endif

# Create and publish the windows archive for the release.
release-publish-windows-archive-gcs: var-require-one-of-CONFIRM-DRYRUN var-require-all-VERSION release-verify-version build-windows-archive
ifdef CONFIRM
	gcloud auth activate-service-account --key-file ~/secrets/gcp-registry-pusher-service-account.json
	gsutil cp dist/tigera-calico-windows-$(GIT_VERSION).zip gs://tigera-windows/
	gcloud auth revoke registry-pusher@unique-caldron-775.iam.gserviceaccount.com
else
	@echo [DRYRUN] gcloud auth activate-service-account --key-file ~/secrets/gcp-registry-pusher-service-account.json
	@echo [DRYRUN] gsutil cp dist/tigera-calico-windows-$(GIT_VERSION).zip gs://tigera-windows/
	@echo [DRYRUN] gcloud auth revoke registry-pusher@unique-caldron-775.iam.gserviceaccount.com
endif

$(WINDOWS_ARCHIVE_BINARY): $(WINDOWS_BINARY)
	cp $< $@

## Produces the Windows ZIP archive for the release.
## NOTE: this is needed to make the hash release, don't remove until that's changed.
release-windows-archive $(WINDOWS_ARCHIVE): var-require-all-VERSION
	$(MAKE) build-windows-archive WINDOWS_ARCHIVE_TAG=$(VERSION)

# Build the docs site and copy over the install-calico-windows.ps1 script.
$(WINDOWS_INSTALL_SCRIPT):
	-mkdir -p dist
	cp $(CURDIR)/windows-packaging/install-calico-windows.ps1 $@
	sed -i s/VERSION/$(GIT_VERSION)/g $@

# NOTE: WINDOWS_IMAGE_REQS must be defined with the requirements to build the windows
# image. These must be added as reqs to 'image-windows' (originally defined in
# lib.Makefile) on the specific package Makefile otherwise they are not correctly
# recognized.
WINDOWS_IMAGE_REQS := \
	Dockerfile-windows \
	$(WINDOWS_BINARY) \
	$(WINDOWS_ARCHIVE_ROOT)/libs/hns/hns.psm1 \
	$(WINDOWS_ARCHIVE_ROOT)/libs/calico/calico.psm1 \
	$(WINDOWS_ARCHIVE_ROOT)/config-hpc.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/felix/felix-service.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/node/node-service.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/uninstall-calico-hpc.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/confd/confd-service.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/confd/config-bgp.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/confd/config-bgp.psm1 \
	$(WINDOWS_ARCHIVE_ROOT)/confd/conf.d/blocks.toml \
	$(WINDOWS_ARCHIVE_ROOT)/confd/conf.d/peerings.toml \
	$(WINDOWS_ARCHIVE_ROOT)/confd/templates/blocks.ps1.template \
	$(WINDOWS_ARCHIVE_ROOT)/confd/templates/peerings.ps1.template \
	windows-packaging/nssm.exe
image-windows: $(WINDOWS_IMAGE_REQS)
