# How to release Calico Enterprise

- [How to release Calico Enterprise](#how-to-release-calico-enterprise)
  - [Creating a release branch](#creating-a-release-branch)
    - [Prerequisite](#prerequisite)
    - [Code freeze](#code-freeze)
    - [Create branch](#create-branch)
    - [Code thaw](#code-thaw)
    - [Setup hashrelease](#setup-hashrelease)
  - [Performing a release](#performing-a-release)

## Creating a release branch

When preparing for a release, one of the earlier steps is to have a release branch created.

> [!CAUTION]
> This does not apply to patch releases and should be skipped.

### Prerequisite

1. Push access to protected branches for the following repos
   - `tigera/calico-private`
   - `tigera/manager`
   - `tigera/operator`

### Code freeze

Announce code freeze in [#eng-eng](https://tigera.slack.com/archives/GKTBUHGN4) slack channel. See sample below

```md
:rotating_light:  CODE FREEZE ALERT :cold_face: :rotating_light:

Consider the following branches are frozen for Enterprise <RELEASE_STREAM> branch cut:

- tigera/calico-private: master
- tigera/manager: master
- tigera/operator: master

unless... :index_pointing_at_the_viewer:
```

### Create branch

Follow these instructions for cutting new branch in both `tigera/calico-private` and `tigera/manager`.
For `tigera/operator` follow ["Preparing a new release branch"](https://github.com/tigera/operator/blob/master/RELEASING.md#preparing-a-new-release-branch) steps outlined in Tigera Operator `RELEASING.md`.

```sh
make create-release-branch
```

This will create a new branch named `release-calico-vX.Y` in `tigera/calico-private` and `tigera/manager`
where `X.Y` is the release stream for the release branch.

> [!NOTE]
> While `vX.Y` is used as the release stream above, for EP1 branch cut, the branch will be named `release-calico-vX.Y-1`.


### Code thaw

Add a message to the thread for the code freeze message from [earlier](#code-freeze) that the codes are unfrozen.

  > [!IMPORTANT]
  >
  > - Ensure the checkbox for "Also send to #eng-eng" is selected
  > - Update the message to `vX.Y-1` for EP1 branch cut.

```md
code freeze over! :melting_face:

All changes for Enterprise vX.Y should be committed to master branch and cherry-picked to release-calient-vX.Y branch
All Operator changes for Enterprise vX.Y should be committed to master branch and cherry-picked to release-vA.B branch
```

### Setup hashrelease

  > [!CAUTION]
  > Wait for `tigera/calico-private` and `tigera/manager` to have published images from the release branch before completing step 2.

1. Add a new task in [calico-private Semaphore project](https://tigera.semaphoreci.com/projects/calico-private/schedulers)

    > [!TIP]
    >
    > - Use any of the "hashrelease: RELEASE_STREAM" task as a template.
    > - Adjust the schedule for this and other hashrelease tasks as needed.

2. Hit "Run Now" and ensure the pipeline passes.

## Performing a release

Follow the instructions from [Calico Enterprise Release Cut Process](https://docs.google.com/document/d/1Oyg4avouWlLXLQf4wpDNsHzdmLyBfGuF_sFTs4t30ho/edit?tab=t.ioffkn5wp5i8)
