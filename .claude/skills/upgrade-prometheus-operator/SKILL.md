---
name: upgrade-prometheus-operator
description: Upgrades the prometheus-operator third-party dependency to a new upstream version, including CRD regeneration, pinned version updates, CVE patch analysis, and change documentation.
---

## Overview

prometheus-operator is vendored as a third-party dependency built from source.
The build downloads the upstream tarball, optionally applies patches from
`third_party/prometheus-operator/patches/`, and compiles the binaries into
container images (`tigera/prometheus-operator` and `tigera/prometheus-config-reloader`).

## Workflow

### 1. Determine target version

If the user provides a version, use it. Otherwise, query the latest release:

```bash
curl -s "https://api.github.com/repos/prometheus-operator/prometheus-operator/releases/latest" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])"
```

Read the current version from `third_party/prometheus-operator/Makefile`
(the `PROMETHEUS_OPERATOR_VERSION` variable).

### 2. Review upstream release notes

Fetch and summarise the release notes between the current and target versions.
Flag any breaking changes, removed features, or new CRDs.

### 3. Update version references

Update these files, replacing the old version with the new one:

| File | What to change |
|------|---------------|
| `third_party/prometheus-operator/Makefile` | `PROMETHEUS_OPERATOR_VERSION` variable |
| `release/internal/pinnedversion/enterprise.go` | `coreosConfigReloaderComponentName` version |
| `release/internal/pinnedversion/enterprise.go` | `coreosPrometheusOperatorComponentName` version |
| `release/internal/pinnedversion/*.approved.txt` | All snapshot files referencing the old version (use `sed` to replace across all `*.approved.txt` files) |

**Important:** The `coreosConfigReloaderComponentName` version tracks the
prometheus-operator version (they are released together from the same repo).

### 4. CVE and dependency patch analysis

Follow the **`check-cve-dependencies`** skill with these parameters:

| Parameter | Value |
|-----------|-------|
| `GITHUB_REPO` | `prometheus-operator/prometheus-operator` |
| `VERSION` | The target version tag (e.g. `v0.89.0`) |
| `COMPONENT_DIR` | `third_party/prometheus-operator` |
| `DOWNLOAD_TARGET` | `$(PROMETHEUS_OPERATOR_DOWNLOADED)` |
| `EXTRA_DEPS` | *(none — the core set is sufficient for prometheus-operator)* |

The skill will check all security-sensitive Go dependencies, query the
vulnerability database, determine whether patches are needed, create or remove
patch files, and produce the dependency/CVE table for the change analysis.

### 5. Regenerate CRDs and manifests

```bash
make gen-prometheus-crds   # Downloads source, copies CRDs to charts/, strips descriptions
make gen-manifests         # Regenerates manifests/ from helm charts
```

This will update:
- `charts/tigera-prometheus-operator/crds/01-crd-*.yaml` (10 CRD files)
- `manifests/prometheus-operator-crds.yaml`
- `manifests/tigera-prometheus-operator.yaml`

### 6. Run formatting

```bash
make fix-changed
```

### 7. Verify (optional but recommended)

```bash
# Build the images to verify compilation
make -C third_party/prometheus-operator build

# Run pinned version tests
go test ./release/internal/pinnedversion/...

# YAML validation
make yaml-lint
```

### 8. Print change analysis

After completing all steps, print a structured analysis for documentation:

```
## Prometheus Operator Upgrade Analysis

### Version Change
- Previous: <old version>
- New: <new version>

### Files Modified
- <list of all files changed, grouped by category>

### CRD Changes
- <summary of any new, removed, or modified CRDs>

<insert check-cve-dependencies output table here>
```

### 9. Commit

Create a commit with the message format:
```
[<TICKET>] Upgrade prometheus-operator to <VERSION>

Update prometheus-operator from <OLD> to <NEW>, regenerate CRDs and
manifests from the new upstream source, and update pinned version files
and test snapshots.
<if patched: \nCreate patches/0001-Update-libraries.patch to fix CVE-XXXX.>
```

## Expected file changes

A typical upgrade touches these files:

- `third_party/prometheus-operator/Makefile`
- `third_party/prometheus-operator/patches/*` (if patches are needed)
- `release/internal/pinnedversion/enterprise.go`
- `release/internal/pinnedversion/*.approved.txt` (7-8 snapshot files)
- `charts/tigera-prometheus-operator/crds/01-crd-*.yaml` (10 CRD files)
- `manifests/prometheus-operator-crds.yaml`
- `manifests/tigera-prometheus-operator.yaml`

## Historical context

Previous upgrades and their patch status:

| Version | Date | Patches? | Notes |
|---------|------|----------|-------|
| v0.89.0 | 2026-02 | No | Deps already current, no CVEs |
| v0.88.0 | 2026-01 | Removed old patches | Jiawei's upgrade absorbed all previous fixes |
| v0.84.0 | 2025-07 | Modified existing | Updated `0001-Update-libraries.patch` |
| v0.78.2 | 2025-02 | Added new | EV-5623 x/crypto and x/net patch |
| v0.76.0 | 2024-09 | Removed old | Upstream absorbed crypto fix |
| v0.73.2 | 2024-04 | Modified existing | Updated crypto patch |

The pattern: patches accumulate between major upgrades for CVE fixes, then get
deleted when a new upstream version incorporates the fixes.
