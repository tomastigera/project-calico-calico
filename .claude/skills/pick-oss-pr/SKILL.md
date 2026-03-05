---
name: pick-oss-pr
description: >
  Cherry-pick a merged PR from the OSS projectcalico/calico repo into the
  tigera/calico-private enterprise fork. Use this skill whenever the user asks
  to pick, cherry-pick, or sync an OSS PR into calico-private, or references
  the hack/pick-oss-pr script. Also trigger when the user says things like
  "bring over PR #NNNNN from OSS", "sync this OSS change", or "pick this into
  private". Works for single or multiple PRs, targeting master or release branches.
---

# Pick OSS PR

Cherry-pick merged PRs from `projectcalico/calico` into `tigera/calico-private`,
replicating what `hack/pick-oss-pr` does but with you resolving conflicts
instead of prompting the user interactively.

## Prerequisites

You must be in a `tigera/calico-private` clone. Run `git remote -v` and
identify:
- **OSS remote**: points at `projectcalico/calico` (often `open-source`,
  `calico`, or `oss`)
- **Private remote**: points at `tigera/calico-private` (often `origin` or
  `upstream`)

If the OSS remote doesn't exist, tell the user and stop.

Verify the working copy is clean (`git status --porcelain`). If there are
uncommitted changes, tell the user and stop — don't start a pick on a dirty repo.

Also note the current branch (`git branch --show-current`) so you can return
to it at the end.

## Workflow

### 1. Gather PR metadata

For each PR number, fetch from the OSS repo:

```bash
gh pr view <PR> --repo projectcalico/calico \
  --json title,body,labels,mergeCommit,headRefOid,state
```

Verify the PR is **MERGED**. If not, stop — cherry-pick needs a merge commit.

Extract:
- `title` — strip any existing `[...]` prefix (from prior cherry-picks)
- `body` — the full PR description
- `labels[].name` — all label names
- `mergeCommit.oid` — the merge commit SHA (fall back to `headRefOid`)

### 2. Fetch the OSS remote and create the branch

```bash
git fetch <oss-remote>
git checkout -b auto-pick-of-#<PR>-<private-remote>-<target-branch>-<timestamp> \
  <private-remote>/<target-branch>
```

Use a timestamp suffix (e.g., `$(date +%s)`) on the **local** branch name to
avoid collisions with leftover branches from previous picks. When pushing,
push to the canonical name without the timestamp:

```bash
git push <remote> <local-branch-with-timestamp>:auto-pick-of-#<PR>-<private-remote>-<target-branch>
```

Branch naming (the canonical push target, without timestamp):
- Single PR: `auto-pick-of-#11993-origin-master`
- Multiple: `auto-pick-of-#11959-#11960-origin-master`
- Release: `auto-pick-of-#11993-origin-release-v3.31`

Default target is `master`. The user may specify a release branch.

### 3. Cherry-pick

```bash
git cherry-pick -x --mainline=1 <merge-commit-sha>
```

`--mainline=1` is required because these are merge commits. `-x` annotates the
commit with the original SHA.

**Resolving conflicts:**

If `git cherry-pick` exits non-zero, check `git diff --name-only --diff-filter=U`
for conflicted files. Read the conflict markers, resolve them, then:

```bash
git add <resolved-files>
git cherry-pick --continue --no-edit
```

Common conflicts:
- **Copyright year**: take the newer year (should be 2026)
- **Enterprise-only code nearby**: the private repo has extra code that OSS
  doesn't; keep both the enterprise additions and the OSS changes
- **Import ordering**: resolve, then let `make fix-changed` clean up later

For multiple PRs, cherry-pick each merge commit in sequence.

**Empty cherry-pick (changes already present):**

If after resolving conflicts `git cherry-pick --continue` reports the commit is
empty, the enterprise repo already contains all the changes from that OSS PR.
Skip it with `git cherry-pick --skip` and label that specific PR:

```bash
gh pr edit <PR> --repo projectcalico/calico --add-label "skip-bot-cherry-pick"
```

**For multi-PR picks**, track which PRs were skipped vs successfully picked.
Continue cherry-picking the remaining PRs in sequence. At the end:

- **All PRs empty**: clean up the branch, do not create a calico-private PR,
  and report which PRs were skipped and why.
- **Some PRs empty, some picked**: proceed with the normal workflow (steps 4–6)
  for the successfully picked PRs. Exclude the skipped PRs from the branch
  name, PR title, and PR body. Mention the skipped PRs in the PR body as a
  note (e.g., "Skipped projectcalico/calico#NNNN — already present in
  enterprise"). Label only the skipped OSS PRs with `skip-bot-cherry-pick`.
- **Single PR empty**: clean up the branch, do not create a calico-private PR.

In all cases, tell the user which PRs were skipped and why.

### 4. Fix up module references and generated files

The enterprise fork uses `tigera/api` instead of `projectcalico/api`. After
the cherry-pick, check whether any files reference `projectcalico/api` that
should be `tigera/api`:

```bash
git diff HEAD~1 --name-only | xargs grep -l 'projectcalico/api' 2>/dev/null
```

If hits are found in Go files, replace `github.com/projectcalico/api` with
`github.com/tigera/api` in those files. This commonly shows up in import
paths and `go.mod`/`go.sum`.

If the cherry-picked changes touch anything that feeds into code generation
(API types, protobuf, helm charts, CI templates), run the relevant `make`
target to regenerate:

| Changed files | Regenerate with |
|---|---|
| `api/` types or CRDs | `make -C api gen-files` |
| `.proto` files | `make protobuf` |
| `charts/` | `make gen-manifests` |
| `.semaphore/semaphore.yml.d/` | `make gen-semaphore-yaml` |

Commit any fixups (module path replacements, regenerated files) as separate
commits on top of the cherry-pick.

### 5. Push and create the PR

```bash
git push <remote> <local-branch-with-timestamp>:<canonical-branch-name>
```

Then create the PR with the exact format below.

#### Title

`[<branch-short>] <original-title>`

| Target branch | Prefix |
|---|---|
| `master` | `[master]` |
| `release-v3.31` | `[v3.31]` |
| `release-calient-v3.22` | `[v3.22]` |
| `release-calient-v3.22-1` | `[v3.22-1]` |

The prefix is derived by stripping `release-` and then `calient-` from the
branch name.

Multiple PRs: join stripped titles with `; `.

#### Body

Three sections, in this order:

**Section 1 — Cherry-pick history:**

```
**Cherry-pick history**
- Pick onto **master**: projectcalico/calico#<PR>
```

(For multiple PRs, use indented sub-bullets under the "Pick onto" line.)

**Section 2 — Original PR body:**

Separated from section 1 by a blank line. Use the original body verbatim with
these adjustments:
- If it starts with a cherry-pick history header, strip that first line (keep
  any old pick bullets — they stack)
- Remove `## Todos` and `## Reminder for the reviewer` sections
- Bare `#NNN` references in the body should ideally be prefixed with
  `projectcalico/calico` so they link correctly, but don't break the body
  trying to do this — it's a nice-to-have

For multiple PRs, separate each with `---` and `**Title** (projectcalico/calico#PR)`.

**Section 3 — Metadata (in a details expander):**

```html
<details>
<summary><b>Cherry-Pick PR details</b></summary>

- **Original PR ID**: <PR-number(s)>
- **Original Commit SHA**: <first-10-chars>
- **Source Repo**: `projectcalico/calico`
- **Target Repo**: `tigera/calico-private`
- **Target Branch**: `master`
</details>
```

#### Labels

All original labels, minus `cherry-pick-candidate`, plus `merge-oss-cherry-pick`.
Comma-separated, deduplicated.

#### Command

```bash
gh pr create \
  --repo tigera/calico-private \
  -H "<branch-name>" \
  -B "<target-branch>" \
  -t "<title>" \
  -l "<labels>" \
  -b "$(cat <<'EOF'
<body>
EOF
)"
```

### 6. Clean up

Return to the original branch and report the PR URL.

## Notes

- The PR body comes from the original OSS PR — don't rewrite it, just adjust
  formatting as described above.
- Never force-push without asking.
- If the user asks to target a release branch, adjust branch name, title prefix,
  and `-B` flag accordingly.
