include ../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e
include ../lib.Makefile

SRC_FILES=$(shell find . -name '*.go')
build: bin/k8s/e2e.test bin/clusternetworkpolicy/e2e.test $(SRC_FILES)
bin/k8s/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./cmd/k8s -c -o $@'

bin/clusternetworkpolicy/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./cmd/clusternetworkpolicy -c -o $@'

clean:
	rm -rf bin/
