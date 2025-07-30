package manager

import (
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

	remote           string
	githubOrg        string
	repoName         string
	branch           string
	devTagIdentifier string

	isHashrelease       bool
	hashreleaseVersion  string
	hashreleaseRegistry string

	validate bool

	publish bool
}

func NewManager(opts ...Option) (*Manager, error) {
	m := &Manager{
		runner:              &command.RealCommandRunner{},
		validate:            true,
		publish:             true,
		isHashrelease:       false,
		hashreleaseRegistry: registry.DefaultEnterpriseHashreleaseRegistry,
	}
	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	if m.dir == "" {
		return nil, fmt.Errorf("No repository root dir specified")
	}
	return m, nil
}

func (m *Manager) Publish() error {
	if m.validate {
		if err := m.PrePublishValidation(); err != nil {
			return err
		}
	}

	env := append(os.Environ(),
		"IMAGE_ONLY=true",
		fmt.Sprintf("DEV_TAG=%s", m.hashreleaseVersion),
		fmt.Sprintf("DEV_REGISTRIES=%s", m.hashreleaseRegistry),
		fmt.Sprintf("RELEASE_TAG=%s", m.version),
	)
	if m.publish {
		env = append(env, "DRYRUN=true")
	} else {
		env = append(env, "CONFIRM=true")
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
			return fmt.Errorf("Failed to publish %s: %s", DefaultImage, err)
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
			return fmt.Errorf("Failed to publish %s for Cloud: %s", DefaultImage, err)
		}
		// Success - move on to the next directory.
		logrus.Info(out)
		break
	}

	branchManager := branch.NewManager(branch.WithRepoRoot(m.dir),
		branch.WithRepoRemote(m.remote),
		branch.WithMainBranch(m.branch),
		branch.WithDevTagIdentifier(m.devTagIdentifier),
		branch.WithValidate(m.validate),
		branch.WithPublish(m.publish))

	return branchManager.CreateNextDevelopmentTag()
}

func (m *Manager) PrePublishValidation() error {
	if m.isHashrelease {
		return fmt.Errorf("manager is only supported for release")
	}
	if m.hashreleaseVersion != "" {
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

	if !m.publish {
		logrus.Warn("Skipping publish is set, will treat as dry-run")
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
