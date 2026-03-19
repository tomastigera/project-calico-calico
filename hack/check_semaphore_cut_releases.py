#!/usr/bin/env python3

import sys
import pathlib
import textwrap

import yaml

def get_configured_promotions():
    data = yaml.safe_load(open(".semaphore/cut-release.yml"))
    promotion_files = [pathlib.Path(promotion['pipeline_file']).relative_to("..") for promotion in data['promotions']]
    return promotion_files

SKIP_SUBDIRS = [
    "api",
    "confd",
    "crypto",
    "dashboards",
    "e2e",
    "felix",
    "fluent-bit",
    "goldmane",
    "guardian",
    "hack",
    "lib",
    "libcalico-go",
    "licensing",
    "lma",
    "networking-calico",
    "oiler",
    "pkg",
    "release",
    "selinux",
    "test",
    "whisker",
    "whisker-backend",
]

if sys.stdout.isatty():
    class color:
        PURPLE = '\033[95m'
        CYAN = '\033[96m'
        DARKCYAN = '\033[36m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
        END = '\033[0m'
else:
    class color:
        PURPLE = ''
        CYAN = ''
        DARKCYAN = ''
        BLUE = ''
        GREEN = ''
        YELLOW = ''
        RED = ''
        BOLD = ''
        UNDERLINE = ''
        END = ''


BASEDIR = pathlib.Path("..").relative_to("..")
THISFILE_PATH = pathlib.Path(__file__).relative_to(BASEDIR.absolute())

wrapper = textwrap.TextWrapper(width=80, initial_indent="  ", subsequent_indent="  ")

RELEASE_CUT_NOT_REFERENCED_ERROR = wrapper.fill("The following release cut promotions exist, but are not "
                                    "referenced from the top-level .semaphore/release-cut.yml file. Please "
                                    "add them to that file or remove the promotion:")

PROJECT_MISSING_RELEASE_CUT_ERROR = wrapper.fill("The following subdirectories appear to be sub-projects (they "
                                     "contain a Makefile) but do not have a `cut-release.yml` file:")

MISSING_RELEASE_CUT_NOTE = wrapper.fill("If these directories are not sub-projects with images which need "
                                        f"to be cut during release, please add them to `SKIP_SUBDIRS` in `{THISFILE_PATH}`")


subdirs = sorted([dirent for dirent in BASEDIR.glob("*") if dirent.is_dir()])

subdirs_with_semaphore = []
subdirs_missing_semaphore = []
promotions_missing_reference = []

for subdir in subdirs:
    if subdir.as_posix() in SKIP_SUBDIRS:
        continue
    if not subdir.joinpath("Makefile").is_file():
        continue
    if subdir.joinpath(".semaphore/cut-release.yml").is_file():
        subdirs_with_semaphore.append(subdir)
    else:
        subdirs_missing_semaphore.append(subdir)

if subdirs_with_semaphore:
    current_promotions = get_configured_promotions()
    for promotion_subdir in subdirs_with_semaphore:
        promotions_file = promotion_subdir.joinpath(".semaphore/cut-release.yml")
        if promotions_file not in current_promotions:
            promotions_missing_reference.append(promotions_file)

if subdirs_missing_semaphore or promotions_missing_reference:
    print()
    print(f"{color.RED}*** WARNING ***{color.END}")
    print()
    if subdirs_missing_semaphore:
        print(f"{color.RED}MISSING SEMAPHORE RELEASE CUT PROMOTION{color.END}")
        print(PROJECT_MISSING_RELEASE_CUT_ERROR)
        for subdir in subdirs_missing_semaphore:
            print(f"    * {subdir}")
        print()
        print(MISSING_RELEASE_CUT_NOTE)
        print()
    if promotions_missing_reference:
        print(f"{color.RED}SEMAPHORE RELEASE CUT PROMOTION NOT REFERENCED{color.END}")
        print(RELEASE_CUT_NOT_REFERENCED_ERROR)
        for promotion in promotions_missing_reference:
            print(f"    * {promotion}")
        print()
    sys.exit(1)
