package ruleset

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

var _ = Describe("WAF middleware tests", func() {
	var mockClientSet *lmak8s.MockClientSet

	owaspCRS, err := fs.Sub(coreruleset.FS, "@owasp_crs")
	Expect(err).To(BeNil())

	crsMap, err := asMap(owaspCRS)
	Expect(err).To(BeNil())

	var configmap = corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultRuleset,
			Namespace: "calico-system",
		},
		Data: crsMap,
	}

	BeforeEach(func() {
		mockClientSet = &lmak8s.MockClientSet{}
		fakeClientSet := fake.NewClientset().CoreV1()
		cf, err := fakeClientSet.ConfigMaps("calico-system").Create(context.Background(), &configmap, metav1.CreateOptions{})
		Expect(err).To(BeNil())
		Expect(cf).NotTo(BeNil())

		mockClientSet.On("CoreV1").Return(fakeClientSet)
	})

	Context("WAF API", func() {
		It("Test Get WAF Rulesets", func() {
			rs := Ruleset{
				Client: mockClientSet,
			}
			ctx := context.Background()
			result, err := rs.GetRulesets(ctx)
			Expect(err).To(BeNil())

			Expect(result).To(HaveLen(1))

			ruleset := result[0]
			Expect(ruleset.ID).To(Equal("coreruleset-default"))
			Expect(ruleset.Name).To(Equal("OWASP Top 10"))
			Expect(ruleset.Files).NotTo(BeEmpty())
		})

		It("Test Get WAF Ruleset", func() {
			rs := Ruleset{
				Client: mockClientSet,
			}
			ctx := context.Background()
			ruleset, err := rs.GetRuleset(ctx, defaultRuleset)
			Expect(err).To(BeNil())

			Expect(ruleset.ID).To(Equal("coreruleset-default"))
			Expect(ruleset.Name).To(Equal("OWASP Top 10"))
			Expect(ruleset.Files).NotTo(BeEmpty())

			for _, file := range ruleset.Files {
				if !strings.HasSuffix(file.Name, ".conf") {
					Expect(file.Name).To(BeNil())
				}
			}
		})

		It("Test Filtering WAF Ruleset", func() {
			rs := Ruleset{
				Client: mockClientSet,
			}
			ctx := context.Background()
			ruleset, err := rs.GetRuleset(ctx, defaultRuleset)
			Expect(err).To(BeNil())

			Expect(ruleset.ID).To(Equal("coreruleset-default"))
			Expect(ruleset.Name).To(Equal("OWASP Top 10"))
			Expect(ruleset.Files).NotTo(BeEmpty())

			for _, file := range ruleset.Files {
				// check we don't send files with rules that don't contain a 'msg' field
				// this file has no rules with a message field so it should not be present
				Expect(file.Name).ToNot(Equal("REQUEST-905-COMMON-EXCEPTIONS.conf"))

				// https://github.com/corazawaf/coraza-coreruleset/blob/main/rules/%40owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf
				// should only have 1 rule we are interested in
				if file.Name == "REQUEST-911-METHOD-ENFORCEMENT.conf" {
					Expect(len(file.Rules)).To(Equal(1))
				}

			}
		})

		It("Test Ordering WAF Ruleset", func() {
			rs := Ruleset{
				Client: mockClientSet,
			}
			ctx := context.Background()
			ruleset, err := rs.GetRuleset(ctx, defaultRuleset)
			Expect(err).To(BeNil())

			Expect(ruleset.ID).To(Equal("coreruleset-default"))
			Expect(ruleset.Name).To(Equal("OWASP Top 10"))
			Expect(ruleset.Files).NotTo(BeEmpty())

			for i := 0; i < (len(ruleset.Files) - 2); i++ {
				Expect(strings.Compare(ruleset.Files[i].Name, ruleset.Files[i+1].Name)).To(Equal(-1))
			}
		})

		It("Test no empty rule ID", func() {
			rs := Ruleset{
				Client: mockClientSet,
			}
			ctx := context.Background()
			ruleset, err := rs.GetRuleset(ctx, defaultRuleset)
			Expect(err).To(BeNil())

			Expect(ruleset.ID).To(Equal("coreruleset-default"))
			Expect(ruleset.Name).To(Equal("OWASP Top 10"))
			Expect(ruleset.Files).NotTo(BeEmpty())

			for _, file := range ruleset.Files {
				for _, rule := range file.Rules {
					Expect(rule.ID).NotTo(BeEmpty(), fmt.Sprintf(`Rule "%s" from %s has an empty ID`, rule.Name, file.Name))
				}
			}
		})

		It("Test Get WAF rule", func() {
			rs := Ruleset{
				Client: mockClientSet,
			}
			ctx := context.Background()
			result, err := rs.GetRule(ctx, defaultRuleset, "921180")
			Expect(err).To(BeNil())

			Expect(result).NotTo(BeNil())
			Expect(result.ID).To(Equal("921180"))
			Expect(result.Name).To(Equal("HTTP Parameter Pollution (%{MATCHED_VAR_NAME})"))
			Expect(result.Data).To(ContainSubstring("id:921180"))
			Expect(result.Data).To(ContainSubstring("msg:'HTTP Parameter Pollution (%{MATCHED_VAR_NAME})'"))
			Expect(result.Data).To(ContainSubstring("severity:'CRITICAL'"))
		})

	})
})

func asMap(fileSystem fs.FS) (map[string]string, error) {
	res := make(map[string]string)
	var walkFn fs.WalkDirFunc = func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return err
		}

		if b, err := fs.ReadFile(fileSystem, path); err != nil {
			return err
		} else {
			res[d.Name()] = string(b)
		}
		return nil
	}

	if err := fs.WalkDir(fileSystem, ".", walkFn); err != nil {
		return nil, fmt.Errorf("failed to walk core ruleset files (%w)", err)
	}

	return res, nil
}
