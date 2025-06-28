include metadata.mk

AWS_PROFILE := helm

TOPLEVEL_DIR:=$(shell git rev-parse --show-toplevel)
CALICO_DIR=$(TOPLEVEL_DIR)/calico
VERSIONS_FILE?=$(CALICO_DIR)/_data/versions.yml

# Determine whether there's a local yaml installed or use dockerized version.
# Note in order to install local (faster) yaml: "go get github.com/mikefarah/yq.v2"
YAML_CMD:=$(shell which yq.v2 || echo docker run --rm -i mikefarah/yq:2.4.2 yq)
HTML_CMD:=$(shell which pandoc || echo docker run --rm --volume "`pwd`:/data" pandoc/core:2.9.2)

##############################################################################
# Version information used for cutting a release.
# Use := so that these V_ variables are computed only once per make run.

RELEASE_STREAM := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '[0].title' | grep --only-matching --extended-regexp '(v[0-9]+\.[0-9]+)|master')
CALICO_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '[0].title')
CHART_RELEASE := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '[0].helmRelease')

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include lib.Makefile

## START builds the release archives for the version
## Creates archive of all the manifests
OUTPUT_DIR?=_release_archive
OPERATOR_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '[0].tigera-operator.version')
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
	@echo "Documentation for this release can be found at https://docs.tigera.io/$(RELEASE_STREAM)" >> $@
	@echo "" >> $@
	@echo "To install Calico Enterprise from this archive, please follow the docs at https://docs.tigera.io/$(RELEASE_STREAM)/maintenance/manifest-archive" >> $@
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

