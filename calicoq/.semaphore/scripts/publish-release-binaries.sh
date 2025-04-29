#!/usr/bin/env bash

DEV_TAG_SUFFIX=${DEV_TAG_SUFFIX:-calient-0.dev}

if [ -n "$CONFIRM" ]
then
  RELEASE_VERSION=$(git describe --tags --exact-match --exclude "*dev*")
else
  RELEASE_VERSION=$(git describe --tags --long --always --abbrev=12 --match "*dev*" | grep -P -o "^v\d*.\d*.\d*(-.*)?(?=-${DEV_TAG_SUFFIX})")
fi

if [ -z "$RELEASE_VERSION" ]
then
    echo "Current commit has no release version tagged"
    exit 1
fi

make release-publish-binaries VERSION="$RELEASE_VERSION"
