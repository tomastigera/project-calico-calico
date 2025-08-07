#!/bin/bash

# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

# This function normalizes versions to be compatible with rpm build system
#
# For Calico components, the second version parameter is empty.
# * Official release: v3.20.1 -> 3.20.1
# * Early preview: v3.20.0-1.1 -> 3.20.0~pre1.1^20240823gitc210c473
# * Main branch or versions.yml title starts with "release-calient-": 0.0.0^20240823gitc210c473
#
# For third-party components built by us, the vendor version is passed in as the second parameter.
# * Official release: v3.1.6 -> 3.1.6
# * Early preview: v3.1.6 -> 3.1.6~pre1.1^20240823gitc210c473
# * Main branch: 3.1.6^20240823gitc210c473

repo_root=$1

if [[ -z "$repo_root" ]]; then
    echo "Empty repository root" >&2
    exit 1
fi

version=${2#v}
title=$(bin/yq .calicoctl.tag <$repo_root/charts/tigera-operator/values.yaml)

is_dev=false
is_early_preview=false
is_release=false

if [[ "$title" == "master" || "$title" == release-calient-* ]]; then
    is_dev=true
elif [[ "$title" =~ ^v[0-9]\.[0-9]+\.[0-9]+-[0-9]\.[0-9]$ ]]; then
    is_early_preview=true
elif [[ "$title" =~ ^v[0-9]\.[0-9]+\.[0-9]+$ ]]; then
    is_release=true
else
    echo "Unexpected version: $version" >&2
    exit 1
fi

# For master and release-calient-vx.yz, we always use 0.0.0 as the version string.
# For early preview, we convert x.y.z-n.m to x.y.z~pren.m.
# For release, we use the version string as-is.
if [[ -z "$version" ]]; then
    if [[ "$is_dev" = true ]]; then
        version="0.0.0"
    elif [[ "$is_early_preview" = true ]]; then
        title=${title#v}
        version="${title//-/"~pre"}"
    elif [[ "$is_release" = true ]]; then
        version=${title#v}
    else
        echo "None of the dev, early preview, or release flag is set" >&2
        exit 1
    fi
fi

if [[ "$is_dev" = true ]] || [[ "$is_early_preview" = true ]]; then
    echo "$version^$(date -u +'%Y%m%d')git$(git rev-parse --short=7 HEAD)"
else
    echo "$version"
fi
