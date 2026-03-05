---
name: upgrade-elasticsearch-kibana
description: Upgrades Elasticsearch and Kibana third-party dependencies to a new upstream patch version, including patch rebasing, pinned version updates, and change documentation.
---

## Overview

Elasticsearch and Kibana are vendored as third-party dependencies built from
source. The builds download the upstream tarballs, apply patches from
`third_party/elasticsearch/patches/` and `third_party/kibana/patches/`,
and produce container images.

Unlike Go-based third-party upgrades (prometheus-operator, alertmanager), ES and
Kibana are Java/Node.js projects — the `check-cve-dependencies` Go CVE skill
does **not** apply. Instead, the main concern is whether existing patches still
apply cleanly to the new version.

**ES and Kibana always bump together** — they share the same version number.

## Workflow

### 1. Determine target version

If the user provides a version, use it. Otherwise, query the latest patch
release in the current minor series:

```bash
# List recent ES tags in the 8.19.x series
curl -s "https://api.github.com/repos/elastic/elasticsearch/tags?per_page=20" \
  | python3 -c "import sys,json; [print(t['name']) for t in json.load(sys.stdin) if t['name'].startswith('v8.19.')]"
```

Read the current versions from:
- `third_party/elasticsearch/Makefile` — `ELASTIC_VERSION` variable
- `third_party/kibana/Makefile` — `KIBANA_VERSION` variable

### 2. Review upstream release notes

Fetch and summarise the Elasticsearch and Kibana release notes between the
current and target versions. Flag any breaking changes or security fixes.

- ES release notes: `https://www.elastic.co/docs/release-notes/elasticsearch`
- Kibana release notes: `https://www.elastic.co/docs/release-notes/kibana`

### 3. Update version references

Update these files, replacing the old version with the new one:

| File | What to change |
|------|---------------|
| `third_party/elasticsearch/Makefile` | `ELASTIC_VERSION` variable |
| `third_party/kibana/Makefile` | `KIBANA_VERSION` variable |
| `release/internal/pinnedversion/enterprise.go` | Version for `eckElasticsearchComponentName` and `eckKibanaComponentName` in `thirdPartyEnterpriseComponents` |
| `release/internal/pinnedversion/*.approved.txt` | All snapshot files referencing the old version (use `sed` to replace across all `*.approved.txt` files) |
| `elasticsearch/Dockerfile` | `FROM` base image tag (e.g. `elasticsearch:v8.19.10-` → `elasticsearch:v8.19.12-`) |
| `kibana/docker-image/Dockerfile` | `FROM` base image tag (e.g. `kibana-ubi:v8.19.10-` → `kibana-ubi:v8.19.12-`) |
| `node/tests/k8st/infra/enterprise_versions.yml` | `eck-elasticsearch` and `eck-kibana` version fields |

**Important notes:**
- The root-level Dockerfiles have hardcoded versions in the `FROM` line — they
  are NOT derived from the third_party Makefile variables.
- The `enterprise_versions.yml` test infra file is easy to miss — always update it.
- The approved.txt snapshots typically contain 7-8 files that all need updating.

### 4. Verify and rebase patches

For each third-party component (elasticsearch, kibana), verify whether existing
patches are still needed and still apply cleanly. The process is:

1. **Temporarily disable all patches** — Comment out or remove the `patch` lines
   in the component's Makefile init target (`init-elastic` / `init-source`).
2. **Clean and re-init without patches** — Remove old build artifacts and
   download/clone the clean upstream source at the new version:
   ```bash
   # For ES
   make -C third_party/elasticsearch clean
   make -C third_party/elasticsearch init-elastic
   # For Kibana
   make -C third_party/kibana clean
   make -C third_party/kibana init-source
   ```
3. **Git-init the downloaded source** — Turn the extracted source into a git
   repo so you can apply patches as commits and regenerate them cleanly:
   ```bash
   # For ES
   cd third_party/elasticsearch/build/elasticsearch-<VERSION>
   git init && git add -A && git commit -m "upstream <VERSION>"
   # For Kibana
   cd third_party/kibana/kibana
   git init && git add -A && git commit -m "upstream <VERSION>"
   ```
4. **Apply each patch and evaluate** — Apply patches one at a time. For each:
   ```bash
   git apply ../patches/<patch-file>  # adjust relative path as needed
   ```
   - **Applies cleanly and produces changes** → Keep the original patch file
     as-is. Commit the changes: `git add -A && git commit -m "<patch description>"`
     (the commit is only needed as a base for subsequent patches, NOT for
     regenerating this patch — do NOT regenerate patches that applied cleanly).
   - **Applies cleanly but `git status` shows no changes** → The patch content
     is already in upstream. Remove the patch file.
   - **Reports "Reversed or previously applied"** → Same as above — the fix
     was absorbed upstream. Remove the patch file.
   - **Fails to apply** → Manually make the equivalent changes in the source,
     commit, then regenerate ONLY this patch via `git format-patch -1 HEAD`.
     Copy the regenerated patch back to the `patches/` directory.

   Upstream cherry-pick patches (numbered like `141390.patch`, `248651.patch`)
   are most likely to be absorbed. Tigera customization patches (0001-0005
   series) are long-lived and should almost always still produce changes.

5. **Regenerate patches** — Only regenerate patches that **failed to apply**
   and were manually rebased. Patches that applied cleanly must be kept as-is
   — regenerating them via `git format-patch` introduces unnecessary metadata
   changes (commit hash, date) with no content difference.
6. **Restore the Makefile** — Re-enable the patch lines for all patches that
   are being kept. Remove lines for deleted patches.
7. **Clean and rebuild** — Remove the downloaded source and marker files, then
   do a full init+build to confirm everything works end-to-end.

**Elasticsearch patches** (`third_party/elasticsearch/patches/`):
- Typically CVE fix patches (dependency bumps) and upstream cherry-picks
- Example: `0001-Bump-packages-for-CVE-fixes.patch`, `141390.patch`

**Kibana patches** (`third_party/kibana/patches/`):
- Tigera customizations, platform support, CVE fixes
- Example patches: Tigera UI customization, reduce platforms to linux-only,
  UBI arm64 support, UBI10 build support, CVE library updates,
  upstream cherry-picks
- **Kibana has more patches (~6) than ES (~2)** — these are critical and
  must all rebase cleanly

### 5. Build and verify

Build the third-party images first, then the root-level images:

```bash
# Build third-party images (applies patches + compiles)
make -C third_party/elasticsearch image
make -C third_party/kibana image

# Build root-level images (uses third-party as base)
make -C elasticsearch image
make -C kibana image
```

**Note:** Local builds may fail due to environment differences. If third-party
builds succeed but root-level builds fail, recommend CI for full verification.

### 6. Run pinned version tests

```bash
go test ./release/internal/pinnedversion/...
```

This regenerates the `*.approved.txt` snapshot files. If tests fail because
snapshots are stale, update them with:

```bash
go test ./release/internal/pinnedversion/... -update
```

Then verify the updated snapshots look correct.

### 7. Run formatting

```bash
make fix-changed
```

### 8. Print change analysis

After completing all steps, print a structured analysis:

```
## Elasticsearch/Kibana Upgrade Analysis

### Version Change
- Previous: <old version>
- New: <new version>

### Upstream Changes
- <summary of notable changes from release notes>

### Files Modified
- **Version references:** <list of files with version bumps>
- **Patches:** <status — applied cleanly / rebased / removed>
- **Snapshots:** <number of approved.txt files updated>

### Patch Status

#### Elasticsearch patches
| Patch | Status | Notes |
|-------|--------|-------|
| <patch name> | Applied cleanly / Rebased / Removed | <details> |

#### Kibana patches
| Patch | Status | Notes |
|-------|--------|-------|
| <patch name> | Applied cleanly / Rebased / Removed | <details> |

### Build Verification
- third_party/elasticsearch: <PASS/FAIL>
- third_party/kibana: <PASS/FAIL>
- elasticsearch: <PASS/FAIL/SKIPPED>
- kibana: <PASS/FAIL/SKIPPED>
```

### 9. Commit

Create a commit with the message format:
```
[<TICKET>] Bump Elasticsearch and Kibana to <VERSION>

Update Elasticsearch and Kibana from <OLD> to <NEW>.
Update pinned version files, Dockerfiles, test infrastructure,
and snapshot files.
<if patches rebased: \nRebase patches against new upstream source.>
<if patches removed: \nRemove patches absorbed by upstream.>
```

## Expected file changes

A typical patch bump touches these files:

- `third_party/elasticsearch/Makefile`
- `third_party/kibana/Makefile`
- `third_party/elasticsearch/patches/*` (if patches need rebasing)
- `third_party/kibana/patches/*` (if patches need rebasing)
- `release/internal/pinnedversion/enterprise.go`
- `release/internal/pinnedversion/*.approved.txt` (7-8 snapshot files)
- `elasticsearch/Dockerfile`
- `kibana/docker-image/Dockerfile`
- `node/tests/k8st/infra/enterprise_versions.yml`

## Key differences from Go-based upgrade skills

- **No `check-cve-dependencies` step** — ES/Kibana are Java/Node.js, not Go
- **ES and Kibana always bump together** — same version number
- **Patch rebasing is the main risk** — Kibana has ~6 patches that must apply cleanly
- **Root-level Dockerfiles have hardcoded versions** — not derived from Makefile variables
- **`enterprise_versions.yml`** test infra file also needs updating
- **No CRD regeneration** — ES/Kibana don't have Kubernetes CRDs

## Historical context

Previous upgrades and their patch status:

| Version | Date | Patches? | Notes |
|---------|------|----------|-------|
| 8.19.12 | 2026-03 | Rebased | ES: removed 141390.patch (absorbed); Kibana: removed 0005+248651 (absorbed), rebased 0001 (template.tsx conflict) |
| 8.19.10 | 2026-02 | Existing | 2 ES patches, 6 Kibana patches |

The pattern: patches accumulate for Tigera customizations and CVE fixes.
Upstream cherry-pick patches (numbered like `141390.patch`, `248651.patch`)
may be removable when the fix lands in a new release. Tigera customization
patches (0001-0005 series) are long-lived and must be maintained.
