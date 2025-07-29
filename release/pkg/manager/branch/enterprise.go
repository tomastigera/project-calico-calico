package branch

import (
	"fmt"
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
		logrus.WithError(err).Fatal("Failed to get git version")
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
		logrus.WithError(err).Fatal("Failed to check if tag already exists")
	}
	if out != "" {
		// increment the number in the dev tag.
		sansDevParts := strings.Split(devTagIdentifier, ".")
		parts := strings.Split(sansDevParts[0], "-")
		num := parts[len(parts)-1]
		numInt, err := strconv.Atoi(num)
		if err != nil {
			logrus.WithField("devTagIdentifier", devTagIdentifier).WithError(err).Fatal("Failed to extract number from dev tag identifier")
		}

		numInt = numInt + 1
		// update the dev tag identifier
		devTagIdentifier = fmt.Sprintf("%s-%d", strings.Join(parts[:len(parts)-1], "-"), numInt)
		logrus.WithField("newDevTagIdentifier", devTagIdentifier).Info("New development tag identifier created")
	}
	nextVersionTag = fmt.Sprintf("%s-%s", nextVersion.FormattedString(), devTagIdentifier)

	if _, err := b.git("commit", "--allow-empty", "-m", fmt.Sprintf("Begin development for %s", nextVersion.FormattedString())); err != nil {
		logrus.WithError(err).Fatal("Failed to create empty commit for new dev tag")
		return err
	}
	if _, err := b.git("tag", nextVersionTag); err != nil {
		logrus.WithError(err).Fatal("Failed to create new dev tag")
		return err
	}
	if b.publish {
		if _, err := b.git("push", b.remote, nextVersionTag); err != nil {
			logrus.WithError(err).Fatal("Failed to push new dev tag")
			return err
		}
		if _, err := b.git("push", b.remote, b.mainBranch); err != nil {
			logrus.WithError(err).Fatal("Failed to push branch with new dev tag")
			return err
		}
		if _, err := b.git("push", b.remote, nextVersionTag); err != nil {
			logrus.WithError(err).Fatal("Failed to push new dev tag")
			return err
		}
	}
	return nil
}
