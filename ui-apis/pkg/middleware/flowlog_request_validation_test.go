package middleware

import (
	"net/http"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	networkingv1 "k8s.io/api/networking/v1"
)

const (
	invalidPreview = `{
   verb":"create",
   "networkPolicy:{
      "spec":{
         "Tier":test
      }
   }
}`
)

var (
	validSelectors = []string{
		`{
      "key":"key1",
      "operator":"=",
      "values":[
         "hi",
         "hello"
      ]
    }`,
		`{
	  "key":"key2",
	  "operator":"!=",
      "values":[
         "hi",
         "hello"
      ]
	}`,
	}
	validSelectorsBadOperators = []string{
		`{
      "key":"key1",
      "operator":"+",
      "values":[
         "hi",
         "hello"
      ]
   }`,
		`{
      "key":"key2",
      "operator":"-"
   }`,
	}
	invalidSelectors = []string{
		`{
      key":"key1",
      "operator:"=",
      "values":[
         "hi"
         "hello"
      ]
   }`,
		`{
      "key":"key2",
      "operator":"!="
   }`,
	}
)

var _ = Describe("Test flowlog request validation functions", func() {
	Context("Test that the extractLimitParam function behaves as expected", func() {
		It("should return a limit of 1000 when no limit param is included in url", func() {
			req, err := http.NewRequest(http.MethodGet, "", nil)
			Expect(err).NotTo(HaveOccurred())
			limit, _ := extractLimitParam(req.URL.Query())
			Expect(limit).To(BeNumerically("==", 1000))
		})

		It("should return a limit of 1000 when a limit param of 0 is included in url", func() {
			req, err := newTestRequestWithParam(http.MethodGet, "limit", "0")
			Expect(err).NotTo(HaveOccurred())
			limit, err := extractLimitParam(req.URL.Query())
			Expect(err).NotTo(HaveOccurred())
			Expect(limit).To(BeNumerically("==", 1000))
		})

		It("should return a limit of 3500 when a limit param of 3500 is included in url", func() {
			req, err := newTestRequestWithParam(http.MethodGet, "limit", "3500")
			Expect(err).NotTo(HaveOccurred())
			limit, err := extractLimitParam(req.URL.Query())
			Expect(err).NotTo(HaveOccurred())
			Expect(limit).To(BeNumerically("==", 3500))
		})

		It("should return an ErrParseRequest when a limit param of -1 is included in url", func() {
			req, err := newTestRequestWithParam(http.MethodGet, "limit", "-1")
			Expect(err).NotTo(HaveOccurred())
			limit, err := extractLimitParam(req.URL.Query())
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(limit).To(BeZero())
		})

		It("should return an ErrParseRequest when a limit param of max int32 + 1 is included in url", func() {
			req, err := newTestRequestWithParam(http.MethodGet, "limit", "2147483648")
			Expect(err).NotTo(HaveOccurred())
			limit, err := extractLimitParam(req.URL.Query())
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(limit).To(BeZero())
		})

		It("should return an ErrParseRequest when a limit param of min int32 - 1 is included in url", func() {
			req, err := newTestRequestWithParam(http.MethodGet, "limit", "-2147483648")
			Expect(err).NotTo(HaveOccurred())
			limit, err := extractLimitParam(req.URL.Query())
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(limit).To(BeZero())
		})
	})

	Context("Test that the lowerCaseParams function behaves as expected", func() {
		It("should return an array of lower cased strings", func() {
			params := []string{"aLLow", "DENY", "UNKNown"}
			lowerCasedParams := lowerCaseParams(params)
			Expect(lowerCasedParams[0]).To(BeEquivalentTo("allow"))
			Expect(lowerCasedParams[1]).To(BeEquivalentTo("deny"))
			Expect(lowerCasedParams[2]).To(BeEquivalentTo("unknown"))
		})
	})

	Context("Test that the validateActions function behaves as expected", func() {
		It("should return true, indicating that actions are valid", func() {
			actions := []string{"allow", "deny", "unknown"}
			valid := validateActions(actions)
			Expect(valid).To(BeTrue())
		})

		It("should return true when passed an empty slice", func() {
			actions := []string{}
			valid := validateActions(actions)
			Expect(valid).To(BeTrue())
		})

		It("should return false when passed a slice with one incorrect action", func() {
			actions := []string{"allow", "deny", "unknownnn"}
			valid := validateActions(actions)
			Expect(valid).To(BeFalse())
		})
	})

	Context("Test that the getLabelSelectors and validateLabelSelector functionality behaves as expected", func() {
		It("should return an array of LabelSelectors when passed a valid json and pass the validation", func() {
			labelSelectors, err := getLabelSelectors(validSelectors)
			Expect(err).NotTo(HaveOccurred())
			Expect(labelSelectors[0].Key).To(BeEquivalentTo("key1"))
			Expect(labelSelectors[1].Key).To(BeEquivalentTo("key2"))
			Expect(labelSelectors[0].Operator).To(BeEquivalentTo("="))
			Expect(labelSelectors[1].Operator).To(BeEquivalentTo("!="))
			Expect(labelSelectors[0].Values[0]).To(BeEquivalentTo("hi"))
			Expect(labelSelectors[0].Values[1]).To(BeEquivalentTo("hello"))
			Expect(labelSelectors[1].Values[0]).To(BeEquivalentTo("hi"))
			Expect(labelSelectors[1].Values[1]).To(BeEquivalentTo("hello"))

			valid := validateLabelSelector(labelSelectors)
			Expect(valid).To(BeTrue())
		})

		It("should return an array of LabelSelectors when passed a valid json but fail validation due to a bad operator", func() {
			labelSelectors, err := getLabelSelectors(validSelectorsBadOperators)
			Expect(err).NotTo(HaveOccurred())
			Expect(labelSelectors[0].Key).To(BeEquivalentTo("key1"))
			Expect(labelSelectors[1].Key).To(BeEquivalentTo("key2"))
			Expect(labelSelectors[0].Operator).To(BeEquivalentTo("+"))
			Expect(labelSelectors[1].Operator).To(BeEquivalentTo("-"))
			Expect(labelSelectors[0].Values[0]).To(BeEquivalentTo("hi"))
			Expect(labelSelectors[0].Values[1]).To(BeEquivalentTo("hello"))
			Expect(labelSelectors[1].Values).To(BeNil())

			valid := validateLabelSelector(labelSelectors)
			Expect(valid).To(BeFalse())
		})

		It("should fail to return LabelSelectors due to bad json", func() {
			labelSelectors, err := getLabelSelectors(invalidSelectors)
			Expect(err).To(HaveOccurred())
			Expect(labelSelectors).To(BeNil())
		})
	})

	Context("Test that the validateFlowTypes function behaves as expected", func() {
		It("should return true, indicating that types are valid", func() {
			types := []string{"net", "ns", "wep", "hep"}
			valid := validateFlowTypes(types)
			Expect(valid).To(BeTrue())
		})

		It("should return true when passed an empty slice", func() {
			types := []string{}
			valid := validateFlowTypes(types)
			Expect(valid).To(BeTrue())
		})

		It("should return false when passed a slice with incorrect types", func() {
			types := []string{"net", "ns", "weps", "heppp"}
			valid := validateFlowTypes(types)
			Expect(valid).To(BeFalse())
		})
	})
	Context("Test that the validatePolicyPreviews function behaves as expected", func() {
		It("should return true when passed a PolicyPreviews with the verb create", func() {
			policyPreview := PolicyPreview{Verb: "create", NetworkPolicy: &v3.NetworkPolicy{}}
			valid := validatePolicyPreviews([]PolicyPreview{policyPreview})
			Expect(valid).To(BeTrue())
		})

		It("should return true when passed a PolicyPreviews with the verb update", func() {
			policyPreview := PolicyPreview{Verb: "update", NetworkPolicy: &v3.NetworkPolicy{}}
			valid := validatePolicyPreviews([]PolicyPreview{policyPreview})
			Expect(valid).To(BeTrue())
		})

		It("should return true when passed a PolicyPreviews with the verb delete", func() {
			policyPreview := PolicyPreview{Verb: "delete", NetworkPolicy: &v3.NetworkPolicy{}}
			valid := validatePolicyPreviews([]PolicyPreview{policyPreview})
			Expect(valid).To(BeTrue())
		})

		It("should return false when passed a PolicyPreviews with the verb read", func() {
			policyPreview := PolicyPreview{Verb: "read", NetworkPolicy: &v3.NetworkPolicy{}}
			valid := validatePolicyPreviews([]PolicyPreview{policyPreview})
			Expect(valid).To(BeFalse())
		})

		It("should return false when passed a PolicyPreviews with the verb create and no network policy", func() {
			policyPreview := PolicyPreview{Verb: "read"}
			valid := validatePolicyPreviews([]PolicyPreview{policyPreview})
			Expect(valid).To(BeFalse())
		})
	})

	Context("Test that the getPolicyPreviews function behaves as expected", func() {
		It("should return a PolicyPreviews object when passed a valid preview string containing a Calico NetworkPolicy", func() {
			validPreview, err := os.ReadFile("testdata/flow_logs_valid_preview.json")
			Expect(err).To(Not(HaveOccurred()))
			policyPreviews, err := getPolicyPreviews([]string{string(validPreview)})
			Expect(err).To(Not(HaveOccurred()))
			Expect(policyPreviews).To(HaveLen(1))
			policyPreview := policyPreviews[0]
			Expect(policyPreview.Verb).To(BeEquivalentTo("delete"))
			Expect(policyPreview.NetworkPolicy).To(BeAssignableToTypeOf(&v3.NetworkPolicy{}))
			Expect(policyPreview.NetworkPolicy.(*v3.NetworkPolicy).Name).To(Equal("default.calico-node-alertmanager-mesh"))
			Expect(policyPreview.NetworkPolicy.(*v3.NetworkPolicy).Namespace).To(Equal("tigera-prometheus"))
		})

		It("should return a PolicyPreviews object when passed a valid preview string containing a Calico GlobalNetworkPolicy", func() {
			validPreview, err := os.ReadFile("testdata/flow_logs_valid_preview_2.json")
			Expect(err).To(Not(HaveOccurred()))
			policyPreviews, err := getPolicyPreviews([]string{string(validPreview)})
			Expect(err).To(Not(HaveOccurred()))
			Expect(policyPreviews).To(HaveLen(1))
			policyPreview := policyPreviews[0]
			Expect(policyPreview.Verb).To(BeEquivalentTo("delete"))
			Expect(policyPreview.NetworkPolicy).To(BeAssignableToTypeOf(&v3.GlobalNetworkPolicy{}))
			Expect(policyPreview.NetworkPolicy.(*v3.GlobalNetworkPolicy).Name).To(Equal("default.calico-node-alertmanager-mesh-global"))
			Expect(policyPreview.NetworkPolicy.(*v3.GlobalNetworkPolicy).Namespace).To(Equal(""))
		})

		It("should return a PolicyPreviews object when passed a valid preview string containing a Kubernetes NetworkPolicy", func() {
			validPreview, err := os.ReadFile("testdata/flow_logs_valid_preview_3.json")
			Expect(err).To(Not(HaveOccurred()))
			policyPreviews, err := getPolicyPreviews([]string{string(validPreview)})
			Expect(err).To(Not(HaveOccurred()))
			Expect(policyPreviews).To(HaveLen(1))
			policyPreview := policyPreviews[0]
			Expect(policyPreview.Verb).To(BeEquivalentTo("delete"))
			Expect(policyPreview.NetworkPolicy).To(BeAssignableToTypeOf(&networkingv1.NetworkPolicy{}))
			Expect(policyPreview.NetworkPolicy.(*networkingv1.NetworkPolicy).Name).To(Equal("calico-node-alertmanager-mesh-xx"))
			Expect(policyPreview.NetworkPolicy.(*networkingv1.NetworkPolicy).Namespace).To(Equal("tigera-prometheus"))
		})

		It("should return a PolicyPreviews object when passed a valid preview string containing a Kubernetes v1beta1 NetworkPolicy ", func() {
			validPreview, err := os.ReadFile("testdata/flow_logs_valid_preview_4.json")
			Expect(err).To(Not(HaveOccurred()))
			policyPreviews, err := getPolicyPreviews([]string{string(validPreview)})
			Expect(err).To(Not(HaveOccurred()))
			Expect(policyPreviews).To(HaveLen(1))
			policyPreview := policyPreviews[0]
			Expect(policyPreview.Verb).To(BeEquivalentTo("create"))
			Expect(policyPreview.NetworkPolicy).To(BeAssignableToTypeOf(&networkingv1.NetworkPolicy{}))
			Expect(policyPreview.NetworkPolicy.(*networkingv1.NetworkPolicy).Name).To(Equal("calico-node-alertmanager-mesh-yy"))
			Expect(policyPreview.NetworkPolicy.(*networkingv1.NetworkPolicy).Namespace).To(Equal("tigera-prometheus"))
		})

		It("should return an error when passed an invalid preview string", func() {
			policyPreview, err := getPolicyPreviews([]string{invalidPreview})
			Expect(err).To(HaveOccurred())
			Expect(policyPreview).To(BeNil())
		})
	})

	Context("Test that the validateActionsAndUnprotected function behaves as expected", func() {
		It("should return an error when passed a invalid combination of actions and uprotected", func() {
			actions := []string{"allow", "deny", "unknown"}
			unprotected := true
			valid := validateActionsAndUnprotected(actions, unprotected)
			Expect(valid).To(BeFalse())
		})

		It("should not return an error when passed a valid combination of actions and uprotected (no deny)", func() {
			actions := []string{"allow", "unknown"}
			unprotected := true
			valid := validateActionsAndUnprotected(actions, unprotected)
			Expect(valid).To(BeTrue())
		})

		It("should not return an error when passed a valid combination of actions and uprotected (unprotected false)", func() {
			actions := []string{"allow", "deny", "unknown"}
			unprotected := false
			valid := validateActionsAndUnprotected(actions, unprotected)
			Expect(valid).To(BeTrue())
		})

		It("should not return an error when passed a valid combination of actions and uprotected (empty actions)", func() {
			actions := []string{}
			unprotected := true
			valid := validateActionsAndUnprotected(actions, unprotected)
			Expect(valid).To(BeTrue())
		})
	})

})

func newTestRequestWithParam(method string, key string, value string) (*http.Request, error) {
	req, err := http.NewRequest(method, "", nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Add(key, value)
	req.URL.RawQuery = q.Encode()
	return req, nil
}
