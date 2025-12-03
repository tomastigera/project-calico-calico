package manager

import (
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/branch"
)

const (
	ReleaseDir          = "manager"
	ComponentName       = "manager"
	DefaultImage        = "manager"
	DefaultOrg          = utils.TigeraOrg
	DefaultRepoName     = "manager"
	DefaultBranchName   = utils.DefaultBranch
	DefaultRemote       = utils.DefaultRemote
	DefaultDevTagSuffix = "calient-0.dev"
)

type Manager struct {
	dir       string
	calicoDir string
	version   string

	runner command.CommandRunner

	remote              string
	githubOrg           string
	repoName            string
	branch              string
	devTagIdentifier    string
	releaseBranchPrefix string

	isHashrelease       bool
	hashreleaseVersion  string
	hashreleaseRegistry string
	registry            string

	validate bool

	publishImages bool
	publishTag    bool
	dryRun        bool
}

func NewManager(opts ...Option) (*Manager, error) {
	m := &Manager{
		runner:              &command.RealCommandRunner{},
		validate:            true,
		publishImages:       true,
		isHashrelease:       false,
		hashreleaseRegistry: registry.DefaultEnterpriseHashreleaseRegistry,
		registry:            registry.DefaultEnterpriseRegistry,
	}
	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	if m.dir == "" {
		return nil, errors.New("no repository root dir specified")
	}
	return m, nil
}

func (m *Manager) publishReleaseImages() error {
	if !m.publishImages {
		logrus.Info("Skipping publishing release images")
		return nil
	}

	logrus.Info("Start publishing release images")
	env := append(os.Environ(),
		"RELEASE=true",
		"IMAGE_ONLY=true",
		fmt.Sprintf("DEV_TAG=%s", m.hashreleaseVersion),
		fmt.Sprintf("DEV_REGISTRIES=%s", m.hashreleaseRegistry),
		fmt.Sprintf("RELEASE_REGISTRIES=%s", m.registry),
		fmt.Sprintf("RELEASE_TAG=%s", m.version),
	)
	if m.dryRun {
		env = append(env, "DRYRUN=true")
	} else {
		env = append(env, "CONFIRM=true")
	}
	if !m.publishTag {
		env = append(env, "SKIP_DEV_IMAGE_RETAG=true")
	}

	// We allow for a certain number of retries when publishing each directory, since
	// network flakes can occasionally result in images failing to push.
	maxRetries := 1
	attempt := 0
	for {
		out, err := m.make("cut-release-image", env)
		if err != nil {
			if attempt < maxRetries {
				logrus.WithField("attempt", attempt).WithError(err).Warn("Publish failed, retrying")
				attempt++
				continue
			}
			logrus.Error(out)
			return fmt.Errorf("failed to publish %s: %s", DefaultImage, err)
		}
		// Success - move on to the next directory.
		logrus.Info(out)
		break
	}

	attempt = 0
	for {
		out, err := m.make("cut-release-image", append(env, "TESLA=true"))
		if err != nil {
			if attempt < maxRetries {
				logrus.WithField("attempt", attempt).WithError(err).Warn("Publish failed, retrying")
				attempt++
				continue
			}
			logrus.Error(out)
			return fmt.Errorf("failed to publish %s for Cloud: %s", DefaultImage, err)
		}
		// Success - move on to the next directory.
		logrus.Info(out)
		break
	}
	logrus.Info("Finished publishing release images")
	return nil
}

func (m *Manager) Publish() error {
	if m.validate {
		if err := m.PrePublishValidation(); err != nil {
			return err
		}
	}

	if err := m.publishReleaseImages(); err != nil {
		return fmt.Errorf("failed to publish images: %w", err)
	}

	branchManager := branch.NewManager(branch.WithRepoRoot(m.dir),
		branch.WithRepoRemote(m.remote),
		branch.WithMainBranch(m.branch),
		branch.WithDevTagIdentifier(m.devTagIdentifier),
		branch.WithReleaseBranchPrefix(m.releaseBranchPrefix),
		branch.WithValidate(m.validate),
		branch.WithPublish(m.publishTag && !m.dryRun))

	return branchManager.CreateNextDevelopmentTag(m.version)
}

func (m *Manager) PrePublishValidation() error {
	if m.isHashrelease {
		return fmt.Errorf("manager is only supported for release")
	}
	if m.hashreleaseVersion == "" {
		return fmt.Errorf("hashrelease version is not specified")
	}
	if m.version == "" {
		return fmt.Errorf("version is not specified")
	}

	gitVersion := version.GitVersion()
	if !version.HasDevTag(gitVersion, m.devTagIdentifier) {
		err := fmt.Errorf("git version %s does not contain dev tag suffix %s", gitVersion, m.devTagIdentifier)
		logrus.Error(err)
		return err
	}
	return nil
}

func (m *Manager) releaseBranchPrereqs(branch string) error {
	if !m.validate {
		logrus.Info("Skipping release branch setup validation")
		return nil
	}

	var errStack error
	if dirty, err := utils.GitIsDirty(m.dir); err != nil {
		errStack = errors.Join(errStack, fmt.Errorf("failed to check if git is dirty: %s", err))
	} else if dirty {
		errStack = errors.Join(errStack, fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before cutting a release branch"))
	}
	if branch == "" {
		errStack = errors.Join(errStack, fmt.Errorf("release branch not specified"))
	}

	return errStack
}

// SetupReleaseBranch prepares the repository for a new release branch by updating:
//   - Makefile: point MONOREPO_BRANCH to the new branch equivalent in calico-private
//
// Finally, it commits the changes to the new release branch.
func (m *Manager) SetupReleaseBranch(branch string) error {
	if err := m.releaseBranchPrereqs(branch); err != nil {
		return err
	}

	// Modify values in Makefile
	logrus.WithField("MONOREPO_BRANCH", branch).Debug("Updating variables in Makefile")
	makefileRelPath := "Makefile"
	if _, err := m.runner.RunInDir(m.dir, "sed", []string{"-i", fmt.Sprintf(`s/^MONOREPO_BRANCH.*/MONOREPO_BRANCH ?= %s/g`, branch), makefileRelPath}, nil); err != nil {
		logrus.WithError(err).Errorf("Failed to update manager branch in %s", makefileRelPath)
		return fmt.Errorf("failed to update manager branch in %s: %w", makefileRelPath, err)
	}

	// Commit the changes.
	if _, err := m.git("add", makefileRelPath); err != nil {
		return fmt.Errorf("failed to add files to git: %s", err)
	}
	if _, err := m.git("commit", "-m", fmt.Sprintf("Updates for %s release branch", branch)); err != nil {
		return fmt.Errorf("failed to commit changes: %s", err)
	}
	return nil
}

// UpdateMainBranch updates the main branch after a release branch has been cut.
// This is a no-op for the manager repository.
func (m *Manager) UpdateMainBranch(releaseBranchStream string) error {
	return nil
}

func (m *Manager) make(target string, env []string) (string, error) {
	return m.runner.Run("make", []string{"-C", m.dir, target}, env)
}

func (m *Manager) git(args ...string) (string, error) {
	return m.runner.RunInDir(m.dir, "git", args, nil)
}

func Clone(org, repo, branch, dir string) error {
	if org == "" {
		org = DefaultOrg
	}
	if repo == "" {
		repo = DefaultRepoName
	}
	if branch == "" {
		branch = DefaultBranchName
	}
	if dir == "" {
		return fmt.Errorf("directory cannot be empty")
	}
	return utils.Clone(fmt.Sprintf("git@github.com:%s/%s.git", org, repo), branch, dir)
}
