#!/bin/bash

write_disclaimer() {
  echo "# !! WARNING, DO NOT EDIT !! This file is generated from semaphore.yml.d." >"$1"
  echo "# To update, modify the template and then run 'make gen-semaphore-yaml'." >>"$1"
}

# To ease up on CI runs, we want to compare against the last commit
# on our current branch and not against master. Thus, we need to add
# a 'default_branch' parameter to each `change_in` option.

# If we've been provided a DEFAULT_BRANCH_OVERRIDE, we use that. This
# is in case we need to regenerate the yaml while on a different
# branch (e.g. in a PR)
if [[ -n $DEFAULT_BRANCH_OVERRIDE ]]; then
  current_branch=$DEFAULT_BRANCH_OVERRIDE
else
  # We haven't been provided an override, so we need to detect the
  # branch we're on. Semaphore provides a variable that references
  # the base branch for PRs, so we can use that (instead of using
  # the PR branch's name, which would be wrong).
  #
  # If we don't have that variable, then we try using the name of
  # the branch we're currently on, which is hopefully correct.
  if [[ -n $SEMAPHORE_GIT_BRANCH ]]; then
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
    echo "ERROR: Unable to determine the current 'default_branch', which should be"
    echo "       of the format \`release-calient-v*\`. You can provide a branch name"
    echo "       by setting the DEFAULT_BRANCH_OVERRIDE variable to the base branch"
    echo "       that this branch will be merged into."
    exit 1
  fi
fi

# generate semaphore yaml file for PR and nightly builds
for out_file in semaphore.yml semaphore-scheduled-builds.yml; do
  write_disclaimer $out_file

  cat semaphore.yml.d/01-preamble.yml >>$out_file
  cat semaphore.yml.d/02-global_job_config.yml >>$out_file
  cat semaphore.yml.d/03-promotions.yml >>$out_file

  # use sed to properly indent blocks
  echo "blocks:" >>$out_file
  cat semaphore.yml.d/blocks/*.yml | sed -e 's/^./  &/' >>$out_file

  cat semaphore.yml.d/99-after_pipeline.yml >>$out_file
done

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
