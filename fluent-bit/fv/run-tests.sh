#!/bin/bash
# Copyright (c) 2024 Tigera, Inc. All rights reserved.

set -ex

zone=$1
vm_name=$2-rocky8

assert_file_exists() {
    if ! gcloud compute ssh --zone="$zone" "user@$vm_name" -- test -f "$1"; then
        echo "file $1 doesn't exist"
        exit 1
    fi
}

assert_folder_exists() {
    if ! gcloud compute ssh --zone="$zone" "user@$vm_name" -- test -d "$1"; then
        echo "folder $1 doesn't exist"
        exit 1
    fi
}

assert_folder_user_group() {
    if ! gcloud compute ssh --zone="$zone" "user@$vm_name" -- ls -dl "$1" | grep "$2"; then
        echo "entry $1 doesn't have expected user and group $2"
        exit 1
    fi
}

assert_user_exists() {
    if ! gcloud compute ssh --zone="$zone" "user@$vm_name" -- getent passwd "$1"; then
        echo "user $1 doesn't exist"
        exit 1
    fi
}

assert_group_exists() {
    if ! gcloud compute ssh --zone="$zone" "user@$vm_name" -- getent group "$1"; then
        echo "group $1 doesn't exist"
        exit 1
    fi
}

echo "running Fluent Bit FV tests ..."

# check user and group
assert_user_exists calico
assert_group_exists calico

# check folders
assert_folder_exists /etc/calico/
assert_folder_exists /etc/calico/calico-fluent-bit/
assert_folder_exists /run/calico/

# check folder user and groups
assert_folder_user_group /etc/calico/ "root root"
assert_folder_user_group /etc/calico/calico-fluent-bit/ "root root"
assert_folder_user_group /run/calico/ "root calico"
assert_folder_user_group /var/log/calico/calico-fluent-bit/ "calico calico"

# check files
assert_file_exists /etc/calico/calico-fluent-bit/calico-fluent-bit.conf
assert_file_exists /etc/calico/calico-fluent-bit/calico-fluent-bit.env
assert_file_exists /etc/calico/calico-fluent-bit/parsers.conf
assert_file_exists /etc/calico/calico-fluent-bit/plugins.conf
assert_file_exists /etc/calico/calico-fluent-bit/record_transformer.lua
assert_file_exists /usr/bin/calico-fluent-bit
assert_file_exists /usr/lib/systemd/system/calico-fluent-bit.service
assert_file_exists /usr/lib64/calico-fluent-bit/out_linseed.so

echo "Fluent Bit FV tests completed successfully."
