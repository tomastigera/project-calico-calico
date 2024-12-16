REPO_ROOT := $(shell git rev-parse --show-toplevel)
REPO_BASENAME := $(shell basename $(REPO_ROOT))

PACKAGE_NAME ?= github.com/tigera/$(REPO_BASENAME)/$(PROJECT_NAME)

LOCAL_USER_ID:=$(shell id -u)
LOCAL_GROUP_ID:=$(shell id -g)

# Allow the ssh auth sock to be mapped into the build container.
ifdef SSH_AUTH_SOCK
	EXTRA_DOCKER_ARGS += -v $(SSH_AUTH_SOCK):/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent
endif

# Volume-mount gopath into the build container to cache go module's packages. If the environment is using multiple
# comma-separated directories for gopath, use the first one, as that is the default one used by go modules.
ifneq ($(GOPATH),)
	# If the environment is using multiple comma-separated directories for gopath, use the first one, as that
	# is the default one used by go modules.
	GOMOD_CACHE = $(shell echo $(GOPATH) | cut -d':' -f1)/pkg/mod
else
	# If gopath is empty, default to $(HOME)/go.
	GOMOD_CACHE = $(HOME)/go/pkg/mod
endif

EXTRA_DOCKER_ARGS += -v $(GOMOD_CACHE):/tmp/go/pkg/mod:rw

# DOCKER_BUILD is the base build command used for building all images.
DOCKER_BUILD=docker buildx build --load --platform=linux/$(ARCH) \
				--pull \
				--ssh default

GO_BUILD_IMAGE ?= calico/go-build
CALICO_BUILD    = $(GO_BUILD_IMAGE):$(GO_BUILD_VER)

CONTAINERIZED=docker run --rm \
				--net=host \
				$(EXTRA_DOCKER_ARGS) \
				-e GOCACHE=/tmp/go-cache \
				-e GOPROXY=$(GOPROXY) \
				-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
				-v $(REPO_ROOT):/go/src/github.com/tigera/$(REPO_BASENAME):rw \
				-v $(REPO_ROOT)/.go-pkg-cache:/go-cache:rw \
				-w /go/src/$(PACKAGE_NAME) \

CONTAINERIZED_BUILD= mkdir -p $(REPO_ROOT)/.go-pkg-cache bin/ $(GOMOD_CACHE) && \
	$(CONTAINERIZED) $(CALICO_BUILD)
