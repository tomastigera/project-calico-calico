package pinnedversion

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/manager"
)

const unknownHash = "<unknown>"

var (
	relVersionsDirPath  = filepath.Join("calico", "_data")
	versionsFileName    = "versions.yml"
	relVersionsFilePath = filepath.Join(relVersionsDirPath, versionsFileName)
)

// EnterpriseReleaseVersions holds the configuration for creating (and updating)
// `calico/_data/versions.yml` for the enterprise release.
type EnterpriseReleaseVersions struct {
	// HashreleaseName is the name of the hashrelease to get its pinned versions file
	Hashrelease string

	// RepoRootDir is the root directory of the repository.
	RepoRootDir string

	// TmpDir is the temporary directory to store the pinned versions file.
	TmpDir string

	// ProductVersion is the version of the product.
	ProductVersion string

	// OperatorVersion is the version of the operator.
	OperatorVersion string

	// OperatorCfg is the configuration for the operator.
	OperatorCfg OperatorConfig

	// HelmReleaseVersion is the version of the Helm release.
	HelmReleaseVersion string

	// ReleaseDirs is the list of images release directories in the release.
	ReleaseDirs []string

	// versions is the pinned versions for the enterprise release.
	versions EnterprisePinnedVersion

	// outDir is the output directory for the versions file.
	// Typically calico/_data relative to the repository root directory.
	// For testing, this can be overridden to a temporary directory.
	outDir string
}

// getHashreleasePinnedVersions downloads the pinned versions file from the hashrelease server
// and stores it in the temporary directory.
func (e *EnterpriseReleaseVersions) getHashreleasePinnedVersions() error {
	if err := os.MkdirAll(e.TmpDir, utils.DirPerms); err != nil {
		return fmt.Errorf("failed to create %s: %w", e.TmpDir, err)
	}
	hashreleaseURL := fmt.Sprintf("https://%s.%s/%s", e.Hashrelease, hashreleaseserver.BaseDomain, pinnedVersionFileName)
	pinnedVersionPath := PinnedVersionFilePath(e.TmpDir)
	file, err := os.Create(pinnedVersionPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", pinnedVersionPath, err)
	}
	defer func() { _ = file.Close() }()
	resp, err := http.Get(hashreleaseURL)
	if err != nil {
		return fmt.Errorf("failed to get %s pinned_versions.yml from %s: %w", e.Hashrelease, hashreleaseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get %s pinned_versions.yml: %s", e.Hashrelease, resp.Status)
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		return fmt.Errorf("failed to write %s pinned_versions.yml: %w", e.Hashrelease, err)
	}
	return nil
}

// generateVersions generates the versions for the enterprise release based on the versions from the hashrelease server.
func (e *EnterpriseReleaseVersions) generateVersions() error {
	// load the hashrelease pinned versions file.
	hr, err := retrieveEnterprisePinnedVersion(e.TmpDir)
	if err != nil {
		return fmt.Errorf("failed to retrieve downloaded pinned versions for %s from %s: %w", e.TmpDir, e.Hashrelease, err)
	}

	// get the git hashes from the hashrelease.
	sep := "-g"
	hashVerParts := strings.Split(hr.Title, sep)
	hash := hashVerParts[len(hashVerParts)-1]
	if len(hashVerParts) < 2 {
		logrus.Errorf("Unable to determine git hash of %s from the hashrelease", utils.CalicoPrivateRepo)
		hash = unknownHash
	}
	mHashVerParts := strings.Split(hr.Components[managerComponentName].Version, sep)
	mHash := mHashVerParts[len(mHashVerParts)-1]
	if len(mHashVerParts) < 2 {
		logrus.Errorf("Unable to determine git hash of %s from the hashrelease", managerComponentName)
		mHash = unknownHash
	}
	// Update the pinned versions file with the new values.
	e.versions = hr
	e.versions.Title = e.ProductVersion
	e.versions.ManifestURL = "" // this field is not used for enterprise releases
	e.versions.HelmRelease = e.HelmReleaseVersion
	e.versions.Note = fmt.Sprintf("%s - generated from git hash %s and %s git hash %s", e.Hashrelease, hash, managerComponentName, mHash)
	e.versions.Hash = hash // record the git hash of the hashrelease
	e.versions.TigeraOperator.Version = e.OperatorVersion
	e.versions.TigeraOperator.Image = e.OperatorCfg.Image
	e.versions.TigeraOperator.Registry = e.OperatorCfg.Registry
	for n, c := range e.versions.Components {
		if c.Version == hr.Title {
			c.Version = e.ProductVersion
		} else if strings.HasPrefix(n, managerComponentName) {
			c.Version = e.ProductVersion
		}
		e.versions.Components[n] = c
	}
	if len(e.ReleaseDirs) == 0 {
		return nil
	}
	// Ensure there are no duplicate release dirs to avoid making duplicate calls to the same dir to build its image list.
	compactedReleaseDirs := slices.CompactFunc(slices.Clone(e.ReleaseDirs), strings.EqualFold)
	if len(compactedReleaseDirs) < len(e.ReleaseDirs) {
		return fmt.Errorf("release dirs contain duplicates: %v", e.ReleaseDirs)
	}
	// Build the list of components to include in the enterprise release.
	// If the ReleaseDirs includes the manager dir, it is handled specially.
	monoRepoReleaseDirs := compactedReleaseDirs
	managerIndex := slices.Index(e.ReleaseDirs, manager.ReleaseDir)
	includesManager := managerIndex != -1
	if includesManager {
		monoRepoReleaseDirs = append(monoRepoReleaseDirs[:managerIndex], monoRepoReleaseDirs[managerIndex+1:]...)
	} else {
		// If manager is not included, there is no need to specify the hash for the manager repo.
		e.versions.Note = fmt.Sprintf("%s - generated from git hash %s", e.Hashrelease, hash)
	}
	images, err := utils.BuildReleaseImageList(e.RepoRootDir, monoRepoReleaseDirs...)
	if err != nil {
		return fmt.Errorf("failed to build release image list: %w", err)
	}
	releaseComponents := make([]string, 0, len(images))
	for _, img := range images {
		name, _ := mapEnterpriseImageToComponent(img, e.ProductVersion)
		releaseComponents = append(releaseComponents, name)
	}
	// Filter the components to only include those being released as well as the base components.
	thirdPartyComponentNames := slices.Collect(maps.Keys(thirdPartyEnterpriseComponents))
	for name := range e.versions.Components {
		switch {
		case name == calicoPrivateComponentName:
			// always include calico-private
		case slices.Contains(thirdPartyComponentNames, name):
			// always include third-party components
		case slices.Contains(releaseComponents, name):
			// include components for the monorepo release dirs in ReleaseDirs
		case strings.HasPrefix(name, managerComponentName):
			if !includesManager {
				// exclude manager components if manager is not included in ReleaseDirs
				delete(e.versions.Components, name)
			}
		default:
			// otherwise, remove the component
			delete(e.versions.Components, name)
		}
	}
	return nil
}

// updateVersionsFile updates the calico/_data/versions.yml file with the versions for the enterprise release.
//
// It creates the file if it does not exist. If it does exist, it appends the new versions to the top of the stack.
// It also ensures that there is a warning comment added to the file to indicate that it is generated and should not be edited manually.
func (e *EnterpriseReleaseVersions) updateVersionsFile() error {
	if e.outDir == "" {
		e.outDir = filepath.Join(e.RepoRootDir, relVersionsDirPath)
	}
	versionsFilePath := filepath.Join(e.outDir, versionsFileName)
	var dataVersionsFile []EnterprisePinnedVersion
	data, err := os.ReadFile(versionsFilePath)
	if errors.Is(err, os.ErrNotExist) {
		// Create dir and file if it does not exist.
		if err := os.MkdirAll(filepath.Dir(versionsFilePath), utils.DirPerms); err != nil {
			return fmt.Errorf("failed to create directory for %s: %w", versionsFilePath, err)
		}
		if _, err := os.Create(versionsFilePath); err != nil {
			return fmt.Errorf("failed to create %s: %w", versionsFilePath, err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to read %s: %w", versionsFilePath, err)
	}
	if err := yaml.Unmarshal([]byte(data), &dataVersionsFile); err != nil {
		return fmt.Errorf("failed to unmarshal %s: %w", versionsFilePath, err)
	}
	upd := append([]EnterprisePinnedVersion{e.versions}, dataVersionsFile...)
	// Write the updated versions file.
	f, err := os.OpenFile(versionsFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", versionsFilePath, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("# !! WARNING, DO NOT EDIT !! This file is generated and updated during a release.\n"); err != nil {
		return fmt.Errorf("failed to add warning to %s: %w", versionsFilePath, err)
	}
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()
	if err := enc.Encode(upd); err != nil {
		return fmt.Errorf("failed to encode %s: %w", versionsFilePath, err)
	}
	return nil
}

// AddToEnterprisePinnedVersionFile adds the enterprise pinned version to the calico/_data/versions.yml file.
//
// It downloads the pinned versions file from the hashrelease server, loads the pinned versions file,
// and updates the calico/_data/versions.yml file with the versions for the enterprise release.
func (e *EnterpriseReleaseVersions) AddToEnterprisePinnedVersionFile() error {
	// download the pinned versions of the hashrelease.
	if err := e.getHashreleasePinnedVersions(); err != nil {
		return fmt.Errorf("failed to get %s hashrelease pinned versions: %w", e.Hashrelease, err)
	}

	// Load the pinned versions file.
	if err := e.generateVersions(); err != nil {
		return fmt.Errorf("failed to load pinned versions for %s: %w", e.Hashrelease, err)
	}

	// Load the calico version from the repo root directory.
	if err := e.updateVersionsFile(); err != nil {
		return fmt.Errorf("failed to update versions file: %w", err)
	}
	return nil
}

// LoadEnterpriseVersionsFromDataFile loads the enterprise pinned version for the given version
// from the versions file calico/_data/versions.yaml relative to the repository root directory.
func LoadEnterpriseVersionsFromDataFile(repoRootDir, version string) (*EnterprisePinnedVersion, error) {
	versionsFilePath := filepath.Join(repoRootDir, relVersionsFilePath)
	data, err := os.ReadFile(versionsFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", versionsFilePath, err)
	}
	var versions []EnterprisePinnedVersion
	if err := yaml.Unmarshal(data, &versions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", versionsFilePath, err)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("no versions found in %s", versionsFilePath)
	}
	for _, v := range versions {
		if v.Title == version {
			return &v, nil
		}
	}
	return nil, fmt.Errorf("version %s not found in %s", version, versionsFilePath)
}
