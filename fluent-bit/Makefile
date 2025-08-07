include ../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/fluent-bit

FLUENT_BIT_VERSION = 4.0.7

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

###############################################################################
# Build
###############################################################################
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
package: calico-fluent-bit.rhel8 calico-fluent-bit.rhel9

.PHONY: calico-fluent-bit.rhel8
calico-fluent-bit.rhel8:  bin/yq $(FLUENT_BIT_DOWNLOADED) host-native-build rhel/calico-fluent-bit.spec.in out_linseed.so
	$(call host_native_rpm_build,rhel8,calico-fluent-bit,$(FLUENT_BIT_VERSION))

.PHONY: calico-fluent-bit.rhel9
calico-fluent-bit.rhel9: bin/yq $(FLUENT_BIT_DOWNLOADED) host-native-build rhel/calico-fluent-bit.spec.in out_linseed.so
	$(call host_native_rpm_build,rhel9,calico-fluent-bit,$(FLUENT_BIT_VERSION))

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

ZONE ?= us-central1-a
VM_PREFIX ?= $(USER)-fluent-bit

.PHONY: fv
fv: package
	fv/create-vm-and-install.sh $(ZONE) $(VM_PREFIX) $(FLUENT_BIT_VERSION)
	fv/run-tests.sh $(ZONE) $(VM_PREFIX)

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean ut static-checks fv
