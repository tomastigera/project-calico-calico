include metadata.mk

AWS_PROFILE := helm

TOPLEVEL_DIR:=$(shell git rev-parse --show-toplevel)
OPERATOR_CHART_VALUES_FILE := $(TOPLEVEL_DIR)/charts/tigera-operator/values.yaml

YQ:= bin/yq
HTML_CMD:=$(shell which pandoc || echo docker run --rm --volume "`pwd`:/data" pandoc/core:2.9.2)

##############################################################################
# Version information used for cutting a release.

CALICO_VER := $(shell $(YQ) '.calicoctl.tag' $(OPERATOR_CHART_VALUES_FILE))
OPERATOR_VER := $(shell $(YQ) '.tigeraOperator.version' $(OPERATOR_CHART_VALUES_FILE))

ifdef VERSIONS_FILE
CALICO_VER := $(shell $(YQ) '.[0].title' $(VERSIONS_FILE))
OPERATOR_VER := $(shell $(YQ) '.[0].tigera-operator.version' $(VERSIONS_FILE))
CHART_RELEASE := $(shell $(YQ) '.[0].helmRelease' $(VERSIONS_FILE))
endif

# Get the release stream from the version string without the "v" prefix.
CALICO_RELEASE_STREAM := $(shell echo $(CALICO_VER) | grep --only-matching --extended-regexp '(v[0-9]+\.[0-9]+)|master' | sed -e 's/^v//')
###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include lib.Makefile

## START builds the release archives for the version
## Creates archive of all the manifests
OUTPUT_DIR?=_release_archive
RELEASE_DIR_NAME?=release-$(CALICO_VER)-$(OPERATOR_VER)
RELEASE_DIR?=$(OUTPUT_DIR)/$(RELEASE_DIR_NAME)
RELEASE_DIR_K8S_MANIFESTS?=$(RELEASE_DIR)/manifests
IGNORED_MANIFESTS= 02-tigera-operator-no-resource-loading.yaml 00-namespace-calico-system.yaml


# The default registry we're pushing to
REGISTRY := quay.io

# Default manifest location
MANIFEST_SRC:=$(TOPLEVEL_DIR)/manifests

publish-release-archive: release-archive
	@aws --profile $(AWS_PROFILE) s3 cp $(RELEASE_DIR).tgz s3://tigera-public/ee/archives/ --acl public-read
	@aws --profile $(AWS_PROFILE) s3 cp manifests/ s3://tigera-public/ee/$(CALICO_VER)/manifests/ --acl public-read --recursive

release-archive: $(RELEASE_DIR) $(RELEASE_DIR).tgz

$(RELEASE_DIR)/private-registry.md:
	$(info *** Generating private-registry.md with Calico Enterprise $(CALICO_VER), Operator $(OPERATOR_VER))
	@sed \
		-e 's/__OP_VERSION__/$(OPERATOR_VER)/g' \
		-e 's/__CE_VERSION__/$(CALICO_VER)/g' \
		private-registry.md.tpl > $(RELEASE_DIR)/private-registry.md

bin/ocp.tgz:
	@$(MAKE) -f Makefile $@

$(RELEASE_DIR).tgz: $(RELEASE_DIR) $(RELEASE_DIR_K8S_MANIFESTS) $(RELEASE_DIR)/private-registry.md $(RELEASE_DIR)/README.md bin/ocp.tgz
	$(info *** Building release archive for Calico Enterprise $(CALICO_VER), Operator $(OPERATOR_VER), chart release $(CHART_RELEASE))
	$(foreach var,$(IGNORED_MANIFESTS), $(shell find $(RELEASE_DIR) -name $(var) -delete))
	@tar -czf $(RELEASE_DIR).tgz -C $(OUTPUT_DIR) $(RELEASE_DIR_NAME)

$(RELEASE_DIR)/README.md:
	@echo "This directory contains an archive of all the manifests for release of Calico Enterprise $(CALICO_VER)" >> $@
	@echo "Documentation for this release can be found at https://docs.tigera.io/calico-enterprise/$(CALICO_RELEASE_STREAM)" >> $@
	@echo "" >> $@
	@echo "To install Calico Enterprise from this archive, please follow the docs at https://docs.tigera.io/calico-enterprise/$(CALICO_RELEASE_STREAM)/getting-started/manifest-archive" >> $@
	@echo "and use the appropriate manifest from the archive where ever you are prompted to download a manifest" >> $@
	@echo "" >> $@
	@echo "Example:" >> $@
	@echo "" >> $@
	@echo "From the docs for OpenShift installation, we have the following command" >> $@
	@echo "" >> $@
	@echo "curl -L https://docs.tigera.io/manifests/ocp/01-cr-installation.yaml -o manifests/01-cr-installation.yaml" >> $@
	@echo "" >> $@
	@echo "For this example, instead of download the manifest using curl, you need to navigate the archive (after extracting) " >> $@
	@echo "and copy the relevant file at manifests/ocp/01-cr-installation.yaml and paste it into your local manifests folder " >> $@
	@echo "" >> $@

$(RELEASE_DIR):
	@mkdir -p $(RELEASE_DIR)

$(RELEASE_DIR_K8S_MANIFESTS):
	# Find all the hosted manifests and copy them into the release dir. Use xargs to mkdir the destination directory structure before copying them.
	# -printf "%P\n" prints the file name and directory structure with the search dir stripped off
	@find $(MANIFEST_SRC) -name  '*.yaml' -printf "%P\n" | \
	  xargs -I FILE sh -c \
	    'mkdir -p $(RELEASE_DIR_K8S_MANIFESTS)/`dirname FILE`;\
	    cp $(MANIFEST_SRC)/FILE $(RELEASE_DIR_K8S_MANIFESTS)/`dirname FILE`;'

