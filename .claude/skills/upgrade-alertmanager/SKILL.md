---
name: upgrade-alertmanager
description: Upgrades the alertmanager third-party dependency to a new upstream version, including pinned version updates, CVE patch analysis, and change documentation.
---

## Overview

Alertmanager is vendored as a third-party dependency built from source.
The build downloads the upstream tarball, optionally applies patches from
`third_party/alertmanager/patches/`, builds frontend assets, and compiles
the binaries into a container image (`tigera/alertmanager`).

Unlike prometheus-operator, alertmanager does not have CRDs — so there is no
CRD regeneration step.

## Workflow

### 1. Determine target version

If the user provides a version, use it. Otherwise, query the latest release:

```bash
curl -s "https://api.github.com/repos/prometheus/alertmanager/releases/latest" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])"
```

Read the current version from `third_party/alertmanager/Makefile`
(the `ALERTMANAGER_VERSION` variable).

### 2. Review upstream release notes

Fetch and summarise the release notes between the current and target versions.
Flag any breaking changes, removed features, or API changes.

### 3. Update version references

Update these files, replacing the old version with the new one:

| File | What to change |
|------|---------------|
| `third_party/alertmanager/Makefile` | `ALERTMANAGER_VERSION` variable |
| `release/internal/pinnedversion/enterprise.go` | `coreosAlertmanagerComponentName` version |
| `release/internal/pinnedversion/*.approved.txt` | All snapshot files referencing the old version (use `sed` to replace across all `*.approved.txt` files) |

### 4. CVE and dependency patch analysis

Follow the **`check-cve-dependencies`** skill with these parameters:

| Parameter | Value |
|-----------|-------|
| `GITHUB_REPO` | `prometheus/alertmanager` |
| `VERSION` | The target version tag (e.g. `v0.31.1`) |
| `COMPONENT_DIR` | `third_party/alertmanager` |
| `DOWNLOAD_TARGET` | `$(ALERTMANAGER_DOWNLOADED)` |
| `EXTRA_DEPS` | `github.com/hashicorp/memberlist`, `github.com/gogo/protobuf` |

**Alertmanager-specific note:** Alertmanager uses `google.golang.org/grpc` as a
direct dependency (not just indirect) and `github.com/hashicorp/memberlist` for
HA clustering — both are included via `EXTRA_DEPS` above.

The skill will check all security-sensitive Go dependencies, query the
vulnerability database, determine whether patches are needed, create or remove
patch files, and produce the dependency/CVE table for the change analysis.

### 5. Regenerate manifests (if needed)

Alertmanager itself does not have CRDs, but if pinned versions or manifests
reference the alertmanager version, regenerate:

```bash
make gen-manifests
```

Note: In most cases, the alertmanager version is only tracked in the pinned
version files and does not appear in the generated manifests, so this step
may produce no changes. Run it anyway to be safe.

### 6. Run formatting

```bash
make fix-changed
```

### 7. Verify (optional but recommended)

```bash
# Build the image to verify compilation
make -C third_party/alertmanager build

# Run pinned version tests
go test ./release/internal/pinnedversion/...

# YAML validation (if manifests changed)
make yaml-lint
```

### 8. Print change analysis

After completing all steps, print a structured analysis for documentation:

```
## Alertmanager Upgrade Analysis

### Version Change
- Previous: <old version>
- New: <new version>

### Files Modified
- <list of all files changed, grouped by category>

<insert check-cve-dependencies output table here>
```

### 9. Commit

Create a commit with the message format:
```
[<TICKET>] Upgrade alertmanager to <VERSION>

Update alertmanager from <OLD> to <NEW> and update pinned version files
and test snapshots.
<if patched: \nCreate patches/0001-Update-libraries.patch to fix CVE-XXXX.>
```

## Expected file changes

A typical upgrade touches these files:

- `third_party/alertmanager/Makefile`
- `third_party/alertmanager/patches/*` (if patches are needed)
- `release/internal/pinnedversion/enterprise.go`
- `release/internal/pinnedversion/*.approved.txt` (7-8 snapshot files)

Note: Alertmanager upgrades touch fewer files than prometheus-operator upgrades
because there are no CRDs to regenerate.

## Historical context

Previous upgrades and their patch status:

| Version | Date | Patches? | Notes |
|---------|------|----------|-------|
| v0.31.1 | 2026-02 | No | Deps already current, no CVEs |
| v0.30.1 | 2026-01 | Removed old patches | Jiawei's upgrade absorbed all previous fixes |
| v0.28.0 | 2024-09 | Removed old | Upstream absorbed x/libs fix |
| v0.27.0 | 2024-09 | Removed old | Upstream absorbed lib updates |

The pattern: patches accumulate between major upgrades for CVE fixes, then get
deleted when a new upstream version incorporates the fixes.

## Alertmanager-specific considerations

- Alertmanager has a **frontend asset build step** (`make assets apiv2`) that
  runs before compilation. If the upstream build process changes, this may need
  updating in the Makefile.
- The `amtool` binary is also built from the same source — both binaries must
  compile successfully.
