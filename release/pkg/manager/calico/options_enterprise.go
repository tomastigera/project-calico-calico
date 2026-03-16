package calico

import (
	"fmt"
	"strings"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
)

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

func WithEnterpriseHashreleaseRegistry(registry string) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.enterpriseHashreleaseRegistry = registry
		return nil
	}
}

func WithWindowsArchiveBucket(bucket string) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.windowsArchiveBucket = bucket
		return nil
	}
}

func WithPublishWindowsArchive(publish bool) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.publishWindowsArchive = publish
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

func WithNonClusterHostPackages(nchPackages bool) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.nchPackages = nchPackages
		return nil
	}
}

func WithGPGKeyID(gpgKeyID string) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.gpgKeyID = gpgKeyID
		return nil
	}
}

func WithDryRun(dryRun bool) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.dryRun = dryRun
		return nil
	}
}

func WithBaseArtifactsURL(url string) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.baseArtifactsURL = url
		return nil
	}
}

func WithImageReleaseDirs(dirs []string) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		// ensure that the dirs specified are part of the expected enterprise dirs
		parentReleaseDirs := make(map[string]struct{})
		for _, dir := range enterpriseImageReleaseDirs {
			parentReleaseDirs[dir] = struct{}{}
		}
		diff := []string{}
		for _, dir := range dirs {
			if _, ok := parentReleaseDirs[dir]; !ok {
				diff = append(diff, dir)
			}
		}
		if len(diff) > 0 {
			return fmt.Errorf("invalid image release dirs specified: %v", strings.Join(diff, ", "))
		}
		r.imageReleaseDirs = dirs
		return nil
	}
}

func WithManager(include bool) EnterpriseOption {
	return func(r *EnterpriseManager) error {
		r.includeManager = include
		return nil
	}
}
