package branch

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/version"
)

func (b *BranchManager) CreateNextDevelopmentTag(releaseVersion string) error {
	// Tag the current commit with the release version
	if releaseVersion == "" {
		logrus.Error("Release version is not specified")
		return fmt.Errorf("release version must be specified")
	}
	if _, err := b.git("tag", releaseVersion); err != nil {
		return err
	}
	gitVersion, err := command.GitVersion(b.repoRoot, true)
	if err != nil {
		logrus.WithError(err).Error("Failed to get git version")
		return fmt.Errorf("failed to get git version: %w", err)
	}
	ver := version.New(gitVersion)
	// Get Next release version
	nextVersion, err := ver.NextReleaseVersion()
	if err != nil {
		logrus.WithError(err).Error("Failed to determine next release version")
	}
	devTagIdentifier := b.devTagIdentifier
	nextVersionTag := fmt.Sprintf("%s-%s", nextVersion.FormattedString(), devTagIdentifier)
	// Check if the tag already exists
	out, err := b.git("ls-remote", "--tags", b.remote, nextVersionTag)
	if err != nil {
		logrus.WithError(err).Error("Failed to check if tag already exists")
		return fmt.Errorf("failed to check if tag already exists: %w", err)
	}
	if out != "" {
		// tag already exists,increment the number in the dev tag.
		// i.e. if vX.Y.Z-calient-0.dev already exists use calient-1.dev
		// for the dev tag identifier to give tag vX.Y.Z-calient-1.dev tag
		sansDevParts := strings.Split(devTagIdentifier, ".")
		parts := strings.Split(sansDevParts[0], "-")
		num := parts[len(parts)-1]
		numInt, err := strconv.Atoi(num)
		if err != nil {
			logrus.WithField("devTagIdentifier", devTagIdentifier).WithError(err).Error("Failed to extract number from dev tag identifier")
			return fmt.Errorf("failed to extract number from dev tag identifier %s: %w", devTagIdentifier, err)
		}

		numInt = numInt + 1
		// update the dev tag identifier
		devTagIdentifier = fmt.Sprintf("%s-%d", strings.Join(parts[:len(parts)-1], "-"), numInt)
		logrus.WithField("newDevTagIdentifier", devTagIdentifier).Info("New development tag identifier created")
	}
	nextVersionTag = fmt.Sprintf("%s-%s", nextVersion.FormattedString(), devTagIdentifier)

	if _, err := b.git("commit", "--allow-empty", "-m", fmt.Sprintf("Begin development for %s", nextVersion.FormattedString())); err != nil {
		logrus.WithError(err).Error("Failed to create empty commit for new dev tag")
		return fmt.Errorf("failed to create empty commit for new dev tag: %w", err)
	}
	if _, err := b.git("tag", nextVersionTag); err != nil {
		logrus.WithError(err).Error("Failed to create new dev tag")
		return fmt.Errorf("failed to create new dev tag: %w", err)
	}
	if b.publish {
		if _, err := b.git("push", b.remote, nextVersionTag); err != nil {
			logrus.WithError(err).Error("Failed to push new dev tag")
			return fmt.Errorf("failed to push new dev tag: %w", err)
		}
		if _, err := b.git("push", b.remote, b.mainBranch); err != nil {
			logrus.WithError(err).Error("Failed to push branch with new dev tag")
			return fmt.Errorf("failed to push branch with new dev tag: %w", err)
		}
		if _, err := b.git("push", b.remote, nextVersionTag); err != nil {
			logrus.WithError(err).Error("Failed to push new dev tag")
			return fmt.Errorf("failed to push new dev tag: %w", err)
		}
	}
	return nil
}

func (b *BranchManager) retagThirdPartyBaseImages(branch string) error {
	logrus.WithField("branch", branch).Info("retagging third-party base images")

	args := []string{"release-retag-third-party-base-images"}
	envs := append(os.Environ(),
		fmt.Sprintf("RELEASE_BRANCH=%s", branch),
	)
	if b.publish {
		envs = append(envs, "CONFIRM=true")
	} else {
		envs = append(envs, "DRYRUN=true")
	}

	if _, err := command.MakeInDir(b.repoRoot, args, envs); err != nil {
		return err
	}
	return nil
}
