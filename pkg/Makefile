include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/pkg

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# CI
###############################################################################

GINKGO_ARGS += -cover -timeout 20m
GINKGO = ginkgo $(GINKGO_ARGS)

ut:
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) $(GINKGO) -r .'

ci: static-checks ut
