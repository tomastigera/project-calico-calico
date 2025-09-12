#!/bin/bash

set -eu
set -o pipefail

write_disclaimer() {
  echo "# !! WARNING, DO NOT EDIT !! This file is generated from semaphore.yml.d." >"$1"
  echo "# To update, modify the template and then run 'make gen-semaphore-yaml'." >>"$1"
}

detect_branch() {
  branch=$(grep -P --only-matching "(?<=default_branch: ')[^']+(?=')" semaphore.yml | uniq)
  branch_counts=$(echo "${branch}" | wc -l)
  if [[ ${branch_counts} != 1 ]]; then
    echo "Detected more than one branch in the current semaphore.yml, bailing out:"
    echo "$branch"
    exit 1
  else
    echo "$branch"
  fi
}

# To ease up on CI runs, we want to compare against the last commit
# on our current branch and not against master. Thus, we need to add
# a 'default_branch' parameter to each `change_in` option.

# If we've been provided a DEFAULT_BRANCH_OVERRIDE, we use that. This
# is in case we need to regenerate the yaml while on a different
# branch (e.g. in a PR)
if [[ -v DEFAULT_BRANCH_OVERRIDE ]]; then
  current_branch=$DEFAULT_BRANCH_OVERRIDE
else
  # We haven't been provided an override, so we need to detect the
  # branch we're on. Semaphore provides a variable that references
  # the base branch for PRs, so we can use that (instead of using
  # the PR branch's name, which would be wrong).
  #
  # If we don't have that variable, then we try using the name of
  # the branch we're currently on, which is hopefully correct.
  if [[ -v SEMAPHORE_GIT_BRANCH ]]; then
    # We're in Sem CI and we should use the base branch
    current_branch=$SEMAPHORE_GIT_BRANCH
  else
    # We're not in Sem CI, so use the current branch name
    current_branch=$(git branch --show-current)
  fi
fi

# If our branch name is actually `release-calient-v*` then we should
# add in the default_branch stanza. If, for some reason, we're not on
# a matching branch and are generating the yaml, then we leave it blank
# because we don't really know what's happening.
if [[ $current_branch == release-calient-v* ]]; then
  branch_stanza=", default_branch: '${current_branch}'"
else
  if [[ $current_branch == master ]]; then
    branch_stanza=""
  else
    detected_head_branch=$(detect_branch)
    if [[ ${detected_head_branch} ]]; then
      branch_stanza=", default_branch: '${detected_head_branch}'"
      echo "WARNING: Currently on a non-master, non-release branch. This branch appears to"
      echo "         be a branch of ${detected_head_branch}, so we're using that as the"
      echo "         default branch in semaphore.yml. If this is not correct, please set"
      echo "         DEFAULT_BRANCH_OVERRIDE in the environment before running this script."
    else
      branch_stanza=""
      echo "WARNING: Currently on a non-master, non-release branch. This branch appears to"
      echo "         be a branch of master, so we're not specifying a default branch in"
      echo "         semaphore.yml. If this is not correct, please set DEFAULT_BRANCH_OVERRIDE"
      echo "         in the environment before running this script."
    fi
  fi
fi

# Check that all change_in clauses ignore the pipeline file.  We now regenerate the
# pipeline file often, so any jobs that need this should depend on it explicitly.
if find semaphore.yml.d/ -name '*.yml' -print0 | xargs -0 grep change_in | grep -v pipeline_file; then
  echo
  echo "ERROR: All change_in clauses must include the \"pipeline_file: 'ignore'\""
  echo "option to prevent unnecessary job runs when the pipeline file is updated."
  echo "Or, if you really want a job to run when the pipeline file changes, add"
  echo "\"pipeline_file: 'track'\"."
  echo
  exit 1
fi

# generate semaphore yaml file for PR and nightly builds
for out_file in semaphore.yml semaphore-scheduled-builds.yml; do
  write_disclaimer $out_file

  cat semaphore.yml.d/01-preamble.yml >>$out_file
  cat semaphore.yml.d/02-global_job_config.yml >>$out_file
  cat semaphore.yml.d/03-promotions.yml >>$out_file

  # use sed to properly indent blocks
  echo "blocks:" >>$out_file

  ls semaphore.yml.d/blocks/*.yml | sort | xargs cat | sed -e 's/^./  &/' >>$out_file

  cat semaphore.yml.d/99-after_pipeline.yml >>$out_file
done

# FIXME default_branch support

grep -o --perl '\$\{CHANGE_IN\(\K[^)]+' --no-filename semaphore.yml | \
  sort --reverse -u | \
  while read -r dep; do
    sed -i "s&\${CHANGE_IN($dep)}&true&g" semaphore-scheduled-builds.yml
  done

pushd ..
go run ./hack/cmd/deps replace-sem-change-in ./.semaphore/semaphore.yml
popd

sed -i "s/\${FORCE_RUN}/false/g" semaphore.yml
sed -i "s/\${WEEKLY_RUN}/false/g" semaphore.yml
sed -i "s/\${FORCE_RUN}/true/g" semaphore-scheduled-builds.yml
sed -i "s/\${WEEKLY_RUN}/false/g" semaphore-scheduled-builds.yml

# generate semaphore yaml file for third-party builds
out_file=semaphore-third-party-builds.yml

write_disclaimer $out_file

cat semaphore.yml.d/01-preamble.yml >>$out_file
cat semaphore.yml.d/02-global_job_config.yml >>$out_file

echo "blocks:" >>$out_file
cat semaphore.yml.d/blocks/10-prerequisites.yml | sed -e 's/^./  &/' >>$out_file
cat semaphore.yml.d/blocks/30-deep-packet-inspection.yml | sed -e 's/^./  &/' >>$out_file
cat semaphore.yml.d/blocks/30-elasticsearch.yml | sed -e 's/^./  &/' >>$out_file
cat semaphore.yml.d/blocks/30-fluentd.yml | sed -e 's/^./  &/' >>$out_file

sed -i "s/\${FORCE_RUN}/true/g" semaphore-third-party-builds.yml
sed -i "s/\${WEEKLY_RUN}/true/g" semaphore-third-party-builds.yml

# Add the `default_branch` parameter to `change_in` clauses
sed -i "s/\${DEFAULT_BRANCH}/${branch_stanza}/" \
          semaphore.yml \
          semaphore-scheduled-builds.yml \
          semaphore-third-party-builds.yml
