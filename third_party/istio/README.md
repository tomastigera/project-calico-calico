# Istio Components

This directory contains vendored Istio components that are customized for Calico Enterprise.

## Overview

Istio provides a service mesh platform with features like traffic management, security, and observability. We vendor specific Istio components to integrate them with Calico's networking and security capabilities.

## Directory Structure

```
third_party/istio/
├── Makefile                    # Vendor-level Makefile (builds all components)
├── README.md                   # This file
└── <component>/                # Individual component directories
    ├── Makefile                # Component-specific Makefile
    ├── Dockerfile              # Container image definition
    ├── .gitignore              # Ignore build artifacts
    ├── patches/                # Patches to apply to upstream
    │   ├── 0001-*.patch
    │   ├── 0002-*.patch
    │   └── ...
    ├── <component>/            # Downloaded source (git-ignored)
    └── bin/                    # Built binaries (git-ignored)
```

## Current Components

### ztunnel
- **Version**: 1.27.3
- **Language**: Rust
- **Description**: Zero-trust tunnel for ambient mesh
- **Upstream**: https://github.com/istio/ztunnel

## Building Components

### Build All Components
```bash
cd third_party/istio
make all              # Build all components
make image-all        # Build container images (current arch)
make images           # Build container images (all architectures)
```

### Build Individual Component
```bash
cd third_party/istio/ztunnel
make build            # Build binary
make image            # Build container image
make ci               # Run CI tasks
```

## Adding a New Component

To add a new Istio component, follow these steps:

### 1. Create Component Directory Structure

```bash
cd third_party/istio
mkdir -p <component>/patches
```

### 2. Create Component Makefile

Create `<component>/Makefile` with the following structure:

```makefile
include ../../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/istio/<component>

<COMPONENT>_IMAGE ?= <component>
BUILD_IMAGES ?= $(<COMPONENT>_IMAGE)

<COMPONENT>_VERSION = <version>

include ../../../lib.Makefile

###############################################################################
# Source Download and Patching
###############################################################################
<COMPONENT>_DOWNLOADED = .<component>.downloaded

.PHONY: init-source
init-source: $(<COMPONENT>_DOWNLOADED)

$(<COMPONENT>_DOWNLOADED):
	mkdir -p <component>
	curl -sfL https://github.com/istio/<component>/archive/refs/tags/$(<COMPONENT>_VERSION).tar.gz | tar xz --strip-components 1 -C <component>
	@for patch in patches/*.patch; do \
		if [ -f "$$patch" ]; then \
			patch -d <component> -p1 < "$$patch" || exit 1; \
		fi; \
	done
	touch $@

###############################################################################
# Build
###############################################################################
.PHONY: build
build: bin/<component>-$(ARCH)

# Add language-specific build commands here
# For Go: Use $(DOCKER_GO_BUILD)
# For Rust: Use docker run with calico/rust-build
# For Node.js: Use node container
# etc.

###############################################################################
# Image
###############################################################################
<COMPONENT>_IMAGE_CREATED = .<component>.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(<COMPONENT>_IMAGE): $(<COMPONENT>_IMAGE_CREATED)
$(<COMPONENT>_IMAGE_CREATED): register Dockerfile build
	$(DOCKER_BUILD) -t $(<COMPONENT>_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: image

.PHONY: cd
cd: image-all cd-common

###############################################################################
# Clean
###############################################################################
.PHONY: clean
clean:
	rm -f $(<COMPONENT>_DOWNLOADED)
	rm -f $(<COMPONENT>_IMAGE_CREATED)
	rm -fr bin/ <component>/
	rm -f .release-*
	-docker image rm -f $$(docker images $(<COMPONENT>_IMAGE) -a -q)
```

### 3. Create Dockerfile

Create `<component>/Dockerfile` following the multi-stage pattern:

```dockerfile
ARG CALICO_BASE
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS ubi
RUN microdnf upgrade -y
# Install any runtime dependencies

FROM scratch AS source
ARG TARGETARCH

# Copy runtime libraries and binary
COPY --from=ubi /lib64/libc.so.6 /lib64/libc.so.6
# ... other libraries

COPY bin/<component>-${TARGETARCH} /usr/local/bin/<component>
COPY <component>/LICENSE /LICENSE

FROM ${CALICO_BASE}
COPY --from=source / /

USER 10001:10001
EXPOSE <ports>
ENTRYPOINT ["/usr/local/bin/<component>"]
```

### 4. Create .gitignore

Create `<component>/.gitignore`:

```
.<component>.created-*
.<component>.downloaded
.release-*
<component>/
bin/
```

### 5. Add Patches

If you need to customize the upstream code:

1. Download and extract the source
2. Make your changes
3. Generate patches:
   ```bash
   cd <component>
   git diff > ../patches/0001-description-of-change.patch
   ```

Patches are applied in alphabetical order, so name them sequentially:
- `0001-first-patch.patch`
- `0002-second-patch.patch`
- etc.

### 6. Update Vendor Makefile

Add the new component to the `COMPONENTS` list in `third_party/istio/Makefile`:

```makefile
COMPONENTS = ztunnel <new-component>
```

### 7. Test the Build

```bash
cd third_party/istio/<component>
make clean
make init-source    # Download and patch
make build          # Build binary
make image          # Build container image
```

## Language-Specific Build Patterns

### Rust (like ztunnel)

```makefile
CALICO_RUST_BUILD_IMAGE = docker.io/calico/rust-build:calico-rust-build

bin/<component>-$(ARCH): $(<COMPONENT>_DOWNLOADED)
	mkdir -p bin
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR)/<component>:/work \
		-v $(CURDIR)/bin:/output \
		-e CARGO_TARGET_DIR=/work/target \
		$(CALICO_RUST_BUILD_IMAGE) \
		sh -c 'cd /work && \
			cargo build --release && \
			cp target/release/<component> /output/<component>-$(ARCH)'
```

**Important:** Always include `-e LOCAL_USER_ID=$(LOCAL_USER_ID)` when using the rust-build container. The container's entrypoint script uses this environment variable to create a user with the correct UID, preventing permission errors when writing to mounted volumes.

### Go

```makefile
bin/<component>-$(ARCH): $(<COMPONENT>_DOWNLOADED)
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			CGO_ENABLED=0 go build -C <component> -o ../$@ -v -ldflags="$(LD_FLAGS) -s -w" ./cmd/<component>'
```

### Node.js

```makefile
bin/<component>-$(ARCH): $(<COMPONENT>_DOWNLOADED)
	cd <component> && \
	npm install && \
	npm run build
```

## CI/CD Integration

### Semaphore CI (Current)

Most components build on Semaphore. The CI process:
1. Runs `make ci` which builds the image
2. On successful merge to master: runs `make cd` which builds multi-arch images
3. On tags: runs `make release-build` and `make release-publish`

### ArgoCI (Future)

Some components (like dashboards) use ArgoCI. To integrate with ArgoCI:

1. Create `.argoci/ciworkflow.yaml` in the component directory:
   ```yaml
   apiVersion: argoproj.io/v1alpha1
   kind: Workflow
   metadata:
     generateName: istio-<component>-ci-
   spec:
     entrypoint: main
     # ... (see dashboards/.argoci/ciworkflow.yaml for full example)
   ```

2. Register the workflow in root `.argoci/config.yaml`:
   ```yaml
   workflows:
     - name: istio-<component>-ci
       workflowFile: third_party/istio/<component>/.argoci/ciworkflow.yaml
       runWhen:
         runOnTag: true
         changes:
           in:
             - third_party\/istio\/<component>\/.*
   ```

3. Update the component Makefile to support ArgoCI-specific targets if needed

## Release Process

### Release Build
```bash
make release-build VERSION=v1.2.3
```

This will:
- Clean previous builds
- Build images for all architectures
- Tag images with the specified version

### Release Publish
```bash
make release-publish VERSION=v1.2.3 RELEASE=true
```

This will:
- Push images to registries
- Create multi-arch manifests

## Troubleshooting

### Build Fails After Applying Patches
- Check that patches apply cleanly: `make init-source`
- Verify patch format (must be unified diff format)
- Ensure patches are numbered correctly

### Binary Not Found in Container
- Check that the binary is copied to the correct location in Dockerfile
- Verify the binary name matches between Makefile and Dockerfile
- Ensure `TARGETARCH` is used correctly

### Image Build Fails
- Verify all required libraries are copied from UBI image
- Check that paths in Dockerfile match actual locations
- Test binary locally: `./bin/<component>-$(ARCH)`

## References

- [Istio Documentation](https://istio.io/latest/docs/)
- [Calico Third-Party Component Patterns](../../README.md)
- [Calico Rust Build Image](https://github.com/projectcalico/calico/tree/master/calico-rust-build)
