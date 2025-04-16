package manager

type Option func(*Manager) error

func WithDirectory(dir string) Option {
	return func(m *Manager) error {
		m.dir = dir
		return nil
	}
}

func WithCalicoDirectory(dir string) Option {
	return func(m *Manager) error {
		m.calicoDir = dir
		return nil
	}
}

func WithRepoRemote(remote string) Option {
	return func(m *Manager) error {
		m.remote = remote
		return nil
	}
}

func WithGithubOrg(org string) Option {
	return func(m *Manager) error {
		m.githubOrg = org
		return nil
	}
}

func WithRepoName(name string) Option {
	return func(m *Manager) error {
		m.repoName = name
		return nil
	}
}

func WithBranch(branch string) Option {
	return func(m *Manager) error {
		m.branch = branch
		return nil
	}
}

func WithDevTagIdentifier(tag string) Option {
	return func(m *Manager) error {
		m.devTagIdentifier = tag
		return nil
	}
}

func WithValidate(validate bool) Option {
	return func(m *Manager) error {
		m.validate = validate
		return nil
	}
}

func WithPublish(publish bool) Option {
	return func(m *Manager) error {
		m.publish = publish
		return nil
	}
}

func WithVersion(version string) Option {
	return func(m *Manager) error {
		m.version = version
		return nil
	}
}

func WithHashreleaseVersion(version string) Option {
	return func(m *Manager) error {
		m.hashreleaseVersion = version
		return nil
	}
}
