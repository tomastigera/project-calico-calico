###############################################################################
# Istio Vendor Makefile
# This Makefile builds all Istio components vendored in this directory.
###############################################################################

# List of all Istio components to build
COMPONENTS = ztunnel proxy

.PHONY: all
all: $(COMPONENTS)

# Build all components
.PHONY: $(COMPONENTS)
$(COMPONENTS):
	$(MAKE) -C $@ build

# Build images for all components
.PHONY: image-all
image-all:
	@for component in $(COMPONENTS); do \
		echo "Building image for $$component..."; \
		$(MAKE) -C $$component image || exit 1; \
	done

# Build images for all components and all architectures
.PHONY: images
images:
	@for component in $(COMPONENTS); do \
		echo "Building images for all architectures for $$component..."; \
		$(MAKE) -C $$component image-all || exit 1; \
	done

# CI target - runs CI for all components
.PHONY: ci
ci:
	@for component in $(COMPONENTS); do \
		echo "Running CI for $$component..."; \
		$(MAKE) -C $$component ci || exit 1; \
	done

# CD target - runs CD for all components
.PHONY: cd
cd:
	@for component in $(COMPONENTS); do \
		echo "Running CD for $$component..."; \
		$(MAKE) -C $$component cd || exit 1; \
	done

# Initialize source for all components (download and patch)
.PHONY: init-source-all
init-source-all:
	@for component in $(COMPONENTS); do \
		echo "Initializing source for $$component..."; \
		$(MAKE) -C $$component init-source || exit 1; \
	done

# Clean all components
.PHONY: clean
clean:
	@for component in $(COMPONENTS); do \
		echo "Cleaning $$component..."; \
		$(MAKE) -C $$component clean || exit 1; \
	done

# Release build for all components
.PHONY: release-build
release-build:
	@for component in $(COMPONENTS); do \
		echo "Building release for $$component..."; \
		$(MAKE) -C $$component release-build || exit 1; \
	done

# Release publish for all components
.PHONY: release-publish
release-publish:
	@for component in $(COMPONENTS); do \
		echo "Publishing release for $$component..."; \
		$(MAKE) -C $$component release-publish || exit 1; \
	done

# Help target
.PHONY: help
help:
	@echo "Istio Vendor Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build all components (default)"
	@echo "  <component>      - Build a specific component (e.g., make ztunnel)"
	@echo "  image-all        - Build images for all components (current architecture)"
	@echo "  images           - Build images for all components (all architectures)"
	@echo "  ci               - Run CI for all components"
	@echo "  cd               - Run CD for all components"
	@echo "  init-source-all  - Download and patch source for all components"
	@echo "  clean            - Clean all components"
	@echo "  release-build    - Build releases for all components"
	@echo "  release-publish  - Publish releases for all components"
	@echo ""
	@echo "Available components: $(COMPONENTS)"
