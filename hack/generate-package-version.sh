#!/bin/bash

# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

# This function normalizes versions to be compatible with rpm build system
#
# For Calico components, the version parameter is empty.
# * Official release: v3.20.1 -> 3.20.1
# * Early preview: v3.20.0-1.1
#     RHEL: -> 3.20.0~pre1.1^20240823gc210c473
#     Debian/Ubuntu: -> 3.20.0~pre1.1+20240823gc210c473-1~bookworm
# * Main branch or values.yaml tag starts with "release-calient-": 0.0.0~20240823gc210c473-1~bookworm
#
# For third-party components built by us, the vendor version is passed in as the fourth parameter.
# * Official release:
#     RHEL: v3.1.6 -> 3.1.6
#     Debian/Ubuntu: v3.1.6 -> 3.1.6-1~bookworm
# * Early preview: v3.1.6
#     RHEL: -> 3.1.6~pre1.1^20240823gc210c473
#     Debian/Ubuntu: -> 3.1.6~pre1.1+20240823gc210c473-1~bookworm
# * Main branch: 3.1.6~20240823gc210c473-1~bookworm
#
# The packaging type is passed in as the second parameter:
# * rpm -> RHEL
# * deb -> Debian and derivatives

repo_root=$1

if [[ -z "$repo_root" ]]; then
    echo "Empty repository root" >&2
    exit 1
fi

os_type=$2

if [[ "$os_type" = "rpm" ]]; then
    separator="^"
    codename=""
elif [[ "$os_type" = "deb" ]]; then
    separator="+"
    codename=-1~$3
else
    echo "Invalid OS type. Should be rpm or deb" >&2
    exit 1
fi

version=${4#v}
tag=$(bin/yq .calicoctl.tag <"$repo_root/charts/tigera-operator/values.yaml")

is_dev=false
is_early_preview=false
is_release=false

if [[ "$tag" == "master" || "$tag" == release-calient-* ]]; then
    is_dev=true
elif [[ "$tag" =~ ^v[0-9]\.[0-9]+\.[0-9]+-[0-9]\.[0-9]$ ]]; then
    is_early_preview=true
elif [[ "$tag" =~ ^v[0-9]\.[0-9]+\.[0-9]+$ ]]; then
    is_release=true
else
    echo "Unexpected tag: $tag" >&2
    exit 1
fi

date_hash=$(date -u +'%Y%m%d')g$(git rev-parse --short=7 HEAD)

if [[ "$is_dev" = true ]]; then
    if [[ -z "$version" ]]; then
        echo "0.0.0~$date_hash$codename"
    else
        echo "$version~$date_hash$codename"
    fi
elif [[ "$is_early_preview" = true ]]; then
    if [[ -z "$version" ]]; then
        tag=${tag#v}
        echo "${tag//-/"~pre"}$separator$date_hash$codename"
    else
        echo "$version~$date_hash$codename"
    fi
elif [[ "$is_release" = true ]]; then
    if [[ -z "$version" ]]; then
        echo "${tag#v}$codename"
    else
        echo "$version$codename"
    fi
else
    echo "None of the dev, early preview, or release flag is set" >&2
    exit 1
fi
