package operator

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
)

//go:embed templates/enterprise-images.go.gotmpl
var enterpriseComponentImagesFileTemplate string

type EnterpriseOperatorManager struct {
	OperatorManager
}

func NewEnterpriseManager(opts ...Option) *EnterpriseOperatorManager {
	defaultOpts := []Option{
		WithProductRegistry(registry.DefaultEnterpriseRegistry),
	}
	return &EnterpriseOperatorManager{
		OperatorManager: *NewManager(append(defaultOpts, opts...)...),
	}
}

func (o *EnterpriseOperatorManager) PreBuildValidation() error {
	if err := o.OperatorManager.PreBuildValidation(); err != nil {
		return err
	}
	return nil
}

func (o *EnterpriseOperatorManager) Build() error {
	if o.validate {
		if err := o.PreBuildValidation(); err != nil {
			return err
		}
	}
	component, componentsVersionPath, err := pinnedversion.GenerateEnterpriseOperatorComponents(o.tmpDir, o.outputDir)
	if err != nil {
		return err
	}
	if component.Image != o.image {
		return fmt.Errorf("operator image mismatch: expected %s, got %s", o.image, component.Image)
	}
	defer func() {
		if _, err := o.runner.RunInDir(o.dir, "git", []string{"reset", "--hard"}, nil); err != nil {
			logrus.WithError(err).Error("Failed to reset repository")
		}
	}()
	if err := o.modifyComponentsImagesFile(); err != nil {
		return err
	}
	env := os.Environ()
	env = append(env, fmt.Sprintf("EE_VERSIONS=%s", componentsVersionPath))
	env = append(env, fmt.Sprintf("ENTERPRISE_CRDS_DIR=%s", o.calicoDir))
	if _, err := o.make("gen-versions", env); err != nil {
		return fmt.Errorf("failed to generate versions: %w", err)
	}
	env = os.Environ()
	env = append(env, fmt.Sprintf("ARCHES=%s", strings.Join(o.architectures, " ")))
	env = append(env, fmt.Sprintf("GIT_VERSION=%s", component.Version))
	env = append(env, fmt.Sprintf("BUILD_IMAGE=%s", component.Image))
	if _, err := o.make("image-all", env); err != nil {
		return fmt.Errorf("failed to build images: %w", err)
	}
	for _, arch := range o.architectures {
		currentTag := fmt.Sprintf("%s:latest-%s", component.Image, arch)
		newTag := fmt.Sprintf("%s-%s", component.String(), arch)
		if err := o.docker.TagImage(currentTag, newTag); err != nil {
			return fmt.Errorf("failed to tag image %q to %q: %w", currentTag, newTag, err)
		}
	}
	env = os.Environ()
	env = append(env, fmt.Sprintf("GIT_VERSION=%s", component.Version))
	env = append(env, fmt.Sprintf("BUILD_IMAGE=%s", component.Image))
	env = append(env, fmt.Sprintf("BUILD_INIT_IMAGE=%s", component.InitImage().Image))
	if _, err := o.make("image-init", env); err != nil {
		return fmt.Errorf("failed to build init image: %w", err)
	}
	currentTag := fmt.Sprintf("%s:latest", component.InitImage().Image)
	newTag := component.InitImage().String()
	if err := o.docker.TagImage(currentTag, newTag); err != nil {
		return fmt.Errorf("failed to tag image %q to %q: %w", currentTag, newTag, err)
	}
	return nil
}

// modifyComponentsImagesFile overwrites the pkg/components/images.go file
// with the contents of the embedded file to ensure that operator has the right registries.
// This is ONLY used by hashreleases because the operator uses the images.go file to determine the registry.
func (o *EnterpriseOperatorManager) modifyComponentsImagesFile() error {
	destFilePath := filepath.Join(o.dir, componentImagesFilePath)
	dest, err := os.OpenFile(destFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to open file %s", destFilePath)
		return fmt.Errorf("failed to open file %s: %w", destFilePath, err)
	}
	defer func() { _ = dest.Close() }()
	tmpl, err := template.New("pkg/components/images.go").Parse(enterpriseComponentImagesFileTemplate)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to parse template to overwrite %s file", destFilePath)
		return fmt.Errorf("failed to parse template to overwrite %s file: %w", destFilePath, err)
	}

	imagePath, _, err := o.imageParts()
	if err != nil {
		return err
	}
	productRegistry, productImagePath, err := o.productRegistryParts()
	if err != nil {
		return err
	}

	if err := tmpl.Execute(dest, map[string]string{
		"ImagePath":        imagePath,
		"Registry":         o.registry,
		"ProductImagePath": productImagePath,
		"ProductRegistry":  productRegistry,
		"Year":             time.Now().Format("2006"),
	}); err != nil {
		logrus.WithError(err).Errorf("Failed to write to file %s", destFilePath)
		return fmt.Errorf("failed to write to file %s: %w", destFilePath, err)
	}
	return nil
}
