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

func (m *Manager) make(target string, env []string) (string, error) {
	return m.runner.Run("make", []string{"-C", m.dir, target}, env)
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
