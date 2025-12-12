#!/bin/bash
# Copyright (c) 2024 Tigera, Inc. All rights reserved.

set -ex

install_package() {
    shopt -s nullglob
    files=(/package/*)
    [[ ${#files[@]} -eq 0 ]] && { echo "Error: No files found in /package/" >&2; exit 1; }

    package_file="${files[0]}"
    case "$package_file" in
        *.deb)
            echo "Installing DEB package: $(basename "$package_file")"
            apt update
            apt install -y "$package_file"
            ;;
        *.rpm)
            echo "Installing RPM package: $(basename "$package_file")"
            dnf install --disablerepo='*' -y "$package_file"
            ;;
    esac
}

assert_file_exists() {
    if [ ! -f "$1" ]; then
        echo "file $1 doesn't exist"
        exit 1
    fi
}

assert_either_file_exists() {
    if [ ! -f "$1" ] && [ ! -f "$2" ]; then
        echo "neither file $1 nor $2 exists"
        exit 1
    fi
}

assert_folder_exists() {
    if [ ! -d "$1" ]; then
        echo "folder $1 doesn't exist"
        exit 1
    fi
}

assert_folder_user_group() {
    if ! ls -dl "$1" | grep "$2"; then
        echo "entry $1 doesn't have expected user and group $2"
        exit 1
    fi
}

assert_user_exists() {
    if ! getent passwd "$1"; then
        echo "user $1 doesn't exist"
        exit 1
    fi
}

assert_group_exists() {
    if ! getent group "$1"; then
        echo "group $1 doesn't exist"
        exit 1
    fi
}

echo "running Fluent Bit FV tests ..."

install_package

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
assert_either_file_exists /usr/lib64/calico-fluent-bit/out_linseed.so "/usr/lib/$(uname -m)-linux-gnu/calico-fluent-bit/out_linseed.so"

echo "Fluent Bit FV tests completed successfully."
