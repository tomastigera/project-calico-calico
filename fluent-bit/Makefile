include ../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/fluent-bit

FLUENT_BIT_VERSION = 4.2.2

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

###############################################################################
# Build
###############################################################################
MOCKERY_FILE_PATHS= \
	plugins/out_linseed/pkg/http/TokenProvider

SRC_FILES = $(shell find plugins -name '*.go')

build: out_linseed.so

out_linseed.so: $(SRC_FILES)
	$(DOCKER_RUN) \
		-e CGO_ENABLED=1 \
		-e CGO_CFLAGS=$(CGO_CFLAGS) \
		-e CGO_LDFLAGS=$(CGO_LDFLAGS) \
		$(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go build -buildmode=c-shared -o $@ -v -buildvcs=false -ldflags "$(LDFLAGS) -s -w" plugins/out_linseed/*.go'

###############################################################################
# Package
###############################################################################
FLUENT_BIT_DOWNLOADED=.fluent-bit.downloaded

.PHONY: init-source
# This target downloads fluent-bit source archive, extract it and rename
# fluent-bit folder name to calico-fluent-bit for better packaging.
init-source: $(FLUENT_BIT_DOWNLOADED)
$(FLUENT_BIT_DOWNLOADED):
	mkdir -p calico-fluent-bit
	curl -sfL https://github.com/fluent/fluent-bit/archive/refs/tags/v${FLUENT_BIT_VERSION}.tar.gz | tar xz --strip-components 1 -C calico-fluent-bit
	tar czf calico-fluent-bit.tar.gz calico-fluent-bit
	rm -fr calico-fluent-bit
	touch $@

.PHONY: package
package: calico-fluent-bit.debian12 \
         calico-fluent-bit.debian13 \
         calico-fluent-bit.rhel8 \
         calico-fluent-bit.rhel9 \
         calico-fluent-bit.ubuntu22 \
         calico-fluent-bit.ubuntu24

.PHONY: calico-fluent-bit.debian12
calico-fluent-bit.debian12:  bin/yq $(FLUENT_BIT_DOWNLOADED) host-native-build debian/changelog.in out_linseed.so
	mkdir -p package/debian12/calico-fluent-bit/debian
	cp out_linseed.so plugins.conf.debian record_transformer.lua package/debian12/calico-fluent-bit/debian
	$(call host_native_deb_build,debian12,calico-fluent-bit,$(FLUENT_BIT_VERSION),bookworm,1)

.PHONY: calico-fluent-bit.debian13
calico-fluent-bit.debian13: bin/yq $(FLUENT_BIT_DOWNLOADED) host-native-build debian/changelog.in out_linseed.so
	mkdir -p package/debian13/calico-fluent-bit/debian
	cp out_linseed.so plugins.conf.debian record_transformer.lua package/debian13/calico-fluent-bit/debian
	$(call host_native_deb_build,debian13,calico-fluent-bit,$(FLUENT_BIT_VERSION),trixie,1)

.PHONY: calico-fluent-bit.rhel8
calico-fluent-bit.rhel8:  bin/yq $(FLUENT_BIT_DOWNLOADED) host-native-build rhel/calico-fluent-bit.spec.in out_linseed.so
	$(call host_native_rpm_build,rhel8,calico-fluent-bit,$(FLUENT_BIT_VERSION))

.PHONY: calico-fluent-bit.rhel9
calico-fluent-bit.rhel9: bin/yq $(FLUENT_BIT_DOWNLOADED) host-native-build rhel/calico-fluent-bit.spec.in out_linseed.so
	$(call host_native_rpm_build,rhel9,calico-fluent-bit,$(FLUENT_BIT_VERSION))

.PHONY: calico-fluent-bit.ubuntu22
calico-fluent-bit.ubuntu22: bin/yq $(FLUENT_BIT_DOWNLOADED) host-native-build debian/changelog.in out_linseed.so
	mkdir -p package/ubuntu22/calico-fluent-bit/debian
	cp out_linseed.so plugins.conf.debian record_transformer.lua package/ubuntu22/calico-fluent-bit/debian
	$(call host_native_deb_build,ubuntu22,calico-fluent-bit,$(FLUENT_BIT_VERSION),jammy,1)

.PHONY: calico-fluent-bit.ubuntu24
calico-fluent-bit.ubuntu24: bin/yq $(FLUENT_BIT_DOWNLOADED) host-native-build debian/changelog.in out_linseed.so
	mkdir -p package/ubuntu24/calico-fluent-bit/debian
	cp out_linseed.so plugins.conf.debian record_transformer.lua package/ubuntu24/calico-fluent-bit/debian
	$(call host_native_deb_build,ubuntu24,calico-fluent-bit,$(FLUENT_BIT_VERSION),noble,1)

###############################################################################
# Clean
###############################################################################
clean:
	rm -f $(FLUENT_BIT_DOWNLOADED)
	rm -f *.h *.so *.tar.gz
	rm -f rhel/calico-fluent-bit.spec
	rm -fr bin/ package/

###############################################################################
# Tests
###############################################################################
GINKGO_ARGS += -cover -timeout 20m
GINKGO = ginkgo $(GINKGO_ARGS)

.PHONY: ut
ut:
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) $(GINKGO) -r plugins/'

.PHONY: fv
fv: package
	$(eval rpm_version := $(shell $(REPO_ROOT)/hack/generate-package-version.sh $(REPO_ROOT) rpm "" $(FLUENT_BIT_VERSION)))
	$(eval deb_version := $(shell $(REPO_ROOT)/hack/generate-package-version.sh $(REPO_ROOT) deb trixie $(FLUENT_BIT_VERSION)))
	$(eval ubuntu_version := $(shell $(REPO_ROOT)/hack/generate-package-version.sh $(REPO_ROOT) deb noble $(FLUENT_BIT_VERSION)))

	docker run --rm \
		-v ./package/rhel9/RPMS/x86_64/calico-fluent-bit-$(rpm_version)-1.el9.x86_64.rpm:/package/calico-fluent-bit.rpm \
		-v ./fv:/fv \
		almalinux:9 \
		/fv/run-tests.sh

	docker run --rm \
		-v ./package/debian13/calico-fluent-bit_$(deb_version)_amd64.deb:/package/calico-fluent-bit.deb \
		-v ./fv:/fv \
		debian:13 \
		/fv/run-tests.sh

	docker run --rm \
		-v ./package/ubuntu24/calico-fluent-bit_$(ubuntu_version)_amd64.deb:/package/calico-fluent-bit.deb \
		-v ./fv:/fv \
		ubuntu:noble \
		/fv/run-tests.sh

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean static-checks ut fv
