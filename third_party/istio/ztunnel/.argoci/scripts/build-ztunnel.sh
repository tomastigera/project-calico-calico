#!/bin/bash

set -e

arg="$1"

function main() {
    echo "---- MAIN EXECUTION BEGIN ----"
    echo $DOCKERHUB_PASSWORD | docker login --username "$DOCKERHUB_USERNAME" --password-stdin
    echo $QUAY_TOKEN | docker login --username "$QUAY_USERNAME" --password-stdin quay.io

    case "$arg" in
        build)
            export BUILD_ARCH="$2"
            build
            ;;
        publish)
            publish
            ;;
        *)
            echo "ERROR: Usage: $0 {build|publish} [amd64|arm64]"
            exit 1
            ;;
    esac
    echo "---- MAIN EXECUTION END ----"
}

function build() {
    cd third_party/istio/ztunnel

    MAX_RETRIES=3  # Rust builds are more reliable than C++, fewer retries needed
    for i in $(seq 1 $MAX_RETRIES); do
        echo "---- Build Attempt $i for ${BUILD_ARCH} ----"

        # Run the build and push to dev registry
        make cd ARCHES=${BUILD_ARCH} CONFIRM=true && break

        echo "Build attempt $i failed, retrying in 10 seconds..."
        sleep 10

        if [[ "${i}" == "${MAX_RETRIES}" ]]; then
            echo "Failed to build after ${MAX_RETRIES} attempts... Check logs above for more information"
            exit 1
        fi
    done
}

function publish() {
    cd third_party/istio/ztunnel
    make push-manifest CONFIRM=true
}

function epilogue() {
    echo "---- EPILOGUE BEGIN ----"
    echo "---- EPILOGUE END ----"
}

##########################################
# Do not modify anything below this line #
##########################################

function globalPrologue() {
    echo "---- GLOBAL PROLOGUE BEGIN ----"
    if [ -f "${CI_HOME}/${CI_GIT_DIR}/.argoci/scripts/global_gcp_prologue.sh" ]; then
        echo "Running global prologue script"
        source ${CI_HOME}/${CI_GIT_DIR}/.argoci/scripts/global_gcp_prologue.sh
    else
        echo "No global prologue script to be run"
    fi
    echo "---- GLOBAL PROLOGUE END ----"
}

function globalEpilogue() {
    echo "---- GLOBAL EPILOGUE BEGIN ----"
    if [ -f "${CI_HOME}/${CI_GIT_DIR}/.argoci/scripts/global_gcp_epilogue.sh" ]; then
        echo "Running global epilogue script"
        source ${CI_HOME}/${CI_GIT_DIR}/.argoci/scripts/global_gcp_epilogue.sh
    else
        echo "No global epilogue script to be run"
    fi
    echo "---- GLOBAL EPILOGUE END ----"
}

function exitHandler() {
    epilogue
    globalEpilogue
}

trap exitHandler EXIT
globalPrologue
main "$@"
