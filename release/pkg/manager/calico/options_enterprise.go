package calico

import "github.com/projectcalico/calico/release/internal/hashreleaseserver"

type EnterpriseOption func(*EnterpriseManager) error

func WithDevTagIdentifier(devTagSuffix string) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.devTagSuffix = devTagSuffix
		return nil
	}
}

func WithChartVersion(version string) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.chartVersion = version
		return nil
	}
}

func WithEnterpriseHashrelease(hashrelease hashreleaseserver.EnterpriseHashrelease, cfg hashreleaseserver.Config) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.enterpriseHashrelease = hashrelease
		r.hashrelease = hashrelease.Hashrelease
		r.hashreleaseConfig = cfg
		return nil
	}
}

func WithPublishWindowsArchive(publish bool) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.publishWindowsArchive = publish
		return nil
	}
}

func WithPublishCharts(publish bool) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.publishCharts = publish
		return nil
	}
}

func WithPublishToS3(publish bool) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.publishCharts = publish
		r.publishToS3 = publish
		return nil
	}
}

func WithPublishGitChanges(publish bool) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.publishGitChanges = publish
		return nil
	}
}

func WithHelmRegistry(registry string) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.helmRegistry = registry
		return nil
	}
}

func WithRPMs(rpm bool) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.rpm = rpm
		return nil
	}
}

func WithAWSProfile(profile string) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.awsProfile = profile
		return nil
	}
}

func WithDryRun(dryRun bool) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.dryRun = dryRun
		return nil
	}
}
