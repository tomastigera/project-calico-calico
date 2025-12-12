package client_test

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	. "github.com/onsi/gomega"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/licensekey"
	"github.com/projectcalico/calico/licensing/client"
	"github.com/projectcalico/calico/licensing/client/features"
)

var (
	// Tigera private key location.
	pkeyPath = "../test-data/pki/intermediate/keys/intermediate.key"

	// Tigera license signing certificate path.
	certPath = "../test-data/pki/intermediate/certs/intermediate.crt"

	absPkeyPath, absCertPath string

	numNodes1 = 555
	numNodes2 = 420

	// BaseFeatures package contains all available features in a standard license
	BaseFeatures = map[string]bool{
		features.ManagementPortal:       true,
		features.PolicyRecommendation:   true,
		features.PolicyPreview:          true,
		features.PolicyManagement:       true,
		features.FileOutputFlowLogs:     true,
		features.PrometheusMetrics:      true,
		features.MultiClusterManagement: true,
		features.ComplianceReports:      true,
		features.ThreatDefense:          true,
		features.EgressAccessControl:    true,
		features.Tiers:                  true,
		features.FederatedServices:      true,
		features.ExportLogs:             true,
		features.AlertManagement:        true,
		features.TopologicalGraph:       true,
		features.KibanaDashboard:        true,
		features.FileOutputL7Logs:       true,
		features.PacketCapture:          true,
		features.IngressGateway:         true,
	}
)

func init() {
	absPkeyPath, _ = filepath.Abs(pkeyPath)
	absCertPath, _ = filepath.Abs(certPath)
}

var claimToJWTTable = []struct {
	description string
	claim       client.LicenseClaims
}{
	{
		description: "fully populated claim",
		claim: client.LicenseClaims{
			LicenseID:   uuid.NewString(),
			Nodes:       &numNodes2,
			Customer:    "meepster-inc",
			Features:    []string{"nice", "features", "for", "you"},
			GracePeriod: 88,
			Claims: jwt.Claims{
				Expiry:   jwt.NewNumericDate(time.Date(2022, 3, 14, 23, 59, 59, 999999999, time.Local)),
				IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
			},
		},
	},
	{
		description: "only required fields for v2.1 populated",
		claim: client.LicenseClaims{
			LicenseID:   uuid.NewString(),
			Nodes:       &numNodes1,
			Customer:    "cool-cat-inc",
			GracePeriod: 90,
			Claims: jwt.Claims{
				Expiry: jwt.NewNumericDate(time.Date(2022, 3, 14, 23, 59, 59, 999999999, time.Local)),
			},
		},
	},
	{
		description: "partially populated claim",
		claim: client.LicenseClaims{
			LicenseID: uuid.NewString(),
			Nodes:     &numNodes2,
			Customer:  "lame-banana-inc",
			Claims: jwt.Claims{
				Expiry: jwt.NewNumericDate(time.Date(2021, 3, 14, 23, 59, 59, 999999999, time.Local)),
			},
		},
	},
}

// TestGetLicenseFromClaims requires a key / cert that can be decoded with the real public key, e.g. a real
// valid leaf keys. Since those keys are extremely sensitive (if leaked, they can be used to furnish valid licenses)
// we accept their location by env var, and only run these tests if that is specified.
func TestGetLicenseFromClaims(t *testing.T) {
	realKeyPath := os.Getenv("REAL_KEY_PATH")
	realCertPath := os.Getenv("REAL_CERT_PATH")
	if realKeyPath == "" || realCertPath == "" {
		t.Skip("REAL_KEY_PATH / REAL_CERT_PATH not specified: skipping decode tests")
	}

	for _, entry := range claimToJWTTable {
		t.Run(entry.description, func(t *testing.T) {
			RegisterTestingT(t)

			lic, err := client.GenerateLicenseFromClaims(entry.claim, realKeyPath, realCertPath)

			spew.Dump(time.Now().Local())

			// We cannot assert the token because it's hard to generate the exact random feed used to encrypt the JWT.
			Expect(err).NotTo(HaveOccurred(), entry.description)

			// We can verify the generated resource's Objectmeta name.
			Expect(lic.Name).Should(Equal("default"), entry.description)

			claims, err := client.Decode(*lic)
			Expect(err).NotTo(HaveOccurred(), entry.description)
			Expect(claims).Should(Equal(entry.claim), entry.description)
		})
	}
}

var tokenToLicense = []struct {
	description string
	license     api.LicenseKey
	claim       client.LicenseClaims
	corrupt     bool
}{
	// {
	//	description: "fully populated uncorrupt claim",
	//	license: api.LicenseKey{
	//		ObjectMeta: v1.ObjectMeta{
	//			Name: "default",
	//		},
	//		Spec: api.LicenseKeySpec{
	//			Token:       "eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJVWHdPUDdKa3RuOVhXRTMzIiwidGFnIjoiaEdWUk9FQW9GcmluNEN5V2ZyTFVfQSIsInR5cCI6IkpXVCJ9.fNrEWcFbBh1UxOvxQOmIzA.wG0JWHnG_Suc4APp.6zu2Uu4Sm2BjJSfU9F8FsJzYj7jz5Qs4tK0lG0X_hr1lro2KFa2QEKZ4iRHcrcp3MFvQjp8VV1LYjwVqzfwqVfKjxwBZxbtUvDtDbGz3p7UmlhHSGnHyW2O_CKbf1q-UWWsAU9HNKkKKSzPIuIjXSWs6YfaBhISqJ42dbJK4ORM_Me6DXvuP3FmxEvulKSUjn0g4iUmID159svJppryyebyiVwddY1-SHZmqzPPnh0X2FTv_H1gSPhInksCdZFbnIPNUFt1Y9ZSR1xlwm-tM4sISiIxhYhLbV3zRb4_o--XUZTbiSVMCiCL8gjwDSyx80APW6Hv4Fsa3wlML0tlSVvOunNQ46k2NIXfE1GXvXp4r47TgEnq5B_peasrldKL6RSILtkU0j-iIpnd-5avy_yh-Vv-Al7q548frudKilbcBE2JmXmdGTv4zXUMIgv-tzPjrnw5dYjcoYhJrQNX04UPXVMytP3gWkg1g1s30iVQi-4WowogUJNj-NzbYHfi32WYjYmFJ4XHAgcIc1Ji-RoyJSKcjEu2VlFKRzkOhf8ADGY9xLNfHtLLEEq8tlgo5dYa-MD0vd249P5bXp9ePBbh_WXBAiGeIjj26hxFJ0R1cYhG8PFZiMxrnJR2p3aHtVxQuH-scWq65Gagm_asHitgLd88CC2fa5JYuNFjCKYWcBk96NIi545mT7SaIOptcmh19CjPweZi5kAHK0NT2dkqY54wu0XQEtJj66DPSp4muU9p-fFbNK7NrfIMMuPUXJhUaLTebGCfWUzRG02KfIezVfTteB9dkByJx44579uhUmd6sd6kDNE3yAVXf7mBr2w7w-NVxgu-E64G9r-HBC5Z48iJp6zqqVyTBGKvuIzMlMbLX_J8KTGU--JE.F1Cq9fv-6aiOvGUidHaegQ",
	//			Certificate: testCertExpired,
	//		},
	//	},
	//
	//	claim: client.LicenseClaims{
	//		LicenseID:   "5fa38831-fca5-4ea1-9722-ac601aa6852a",
	//		Nodes:       &numNodes2,
	//		Customer:    "meepster-inc",
	//		Features:    []string{"cnx", "all"},
	//		GracePeriod: 88,
	//		Claims: jwt.Claims{
	//			Expiry:   jwt.NewNumericDate(time.Date(2022, 3, 14, 23, 59, 59, 59, time.Local)),
	//			IssuedAt: 1521764255,
	//		},
	//	},
	//
	//	corrupt: false,
	// },
	// {
	//	description: "claim with the JWT header meddled with",
	//	license: api.LicenseKey{
	//		ObjectMeta: v1.ObjectMeta{
	//			Name: "default",
	//		},
	//		Spec: api.LicenseKeySpec{
	//			Token:       "eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJ3WWpuYjV6TTF5MlV6RFZ4IiwidFnIjoiN1dSUkxPanNGQ0F1R3pNRGg5akc1USIsInR5cCI6IkpXVCJ9.HtXrz5-Q_vVfKwgn9Ig_zQ.xf6FZYH3315Tffzv.v7JNl7qOWTivF3Y0Fla-5uG-SM7zCVWcOWEncS7y5kc_uIIRTvTqXV7LAB0b6rZFkXGYxo3X0nBADh7yVJO2S9LX3AbjhF4g_5Vu1uVHwNyKEmSxoMhJGK8v0kwtmXWF7dgICKlAWcSE2kscr-1P-m-MgjTPIZaQU27EN3KFNBgPtLalSKcTRoKMWbqnZRyZFB4gIhpXRKOi2wSlRwbzflumRt5PBGQ6AAdqJaZhEDKYIRVwiYiLh8ODXC2WNhF9KS7GqXRE9QopOcQkh3n_AAADIgzOMdrVr26VTXKXZlwtTYZ5cNPxRZA7QkQVB9HMh7WwwstcSLlVRnHcGZJwmTUfpdGExAywCu4DkqJRnarfJUmG1Y86ecOFnmuycFo0NPuruUEXUG33Nd_670qOWzICjqu68cx3AXcwh46m8hZGR3Zbs1usYfrWTVfFZxNUYlAOCmjrnIAKfxDe4B4fBKYEyFM7PTUQj1UTChgv5G3wRBZiVPDv67gnOrqtQQNyAtJvWsaSdxEu5LGzO68ntauYM4wohnqx4JBzFrd5YkWivHf10yFb7_mGYxhqG7_lPiWAd7zxJNGYrOHi8qEMPFtKANI4UKLAbyXVgPJuTo_kAmoHpSqvAf2DTNODBJQb_hl6F6gX0gWsJIQ1V7O7xn6aAc0nkiizYSLuoKLSsF8rWSyASnPuHhc5AeFVEqA8oRYeZLMh9BBYr8w3kGa6eobtp8j8g2YcEy-KSCgxuef94OIRn6EPbvkfhhz8bZm9c1670N701J91WnIG7l1WXFAxXnfO055W0ulpbE99sw.HACGOFtKA6ZvoAg4Prgiaw",
	//			Certificate: testCert,
	//		},
	//	},
	//
	//	claim: client.LicenseClaims{},
	//
	//	corrupt: true,
	// },
	// {
	//	description: "claim with the JWT payload meddled with",
	//	license: api.LicenseKey{
	//		ObjectMeta: v1.ObjectMeta{
	//			Name: "default",
	//		},
	//		Spec: api.LicenseKeySpec{
	//			Token:       "eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJ3WWpuYjV6TTF5MlV6RFZ4IiwidGFnIjoiN1dSUkxPanNGQ0F1R3pNRGg5akc1USIsInR5cCI6IkpXVCJ9.HtXrz5-Q_vVfKwgn9Ig_zQ.xf6FZYH3315Tffzv.v7JNl7qOWTivFY0Fla-5uG-SM7zCVWcOWEncS7y5kc_uIIRTvTqXV7LAB0b6rZFkXGYxo3X0nBADh7yVJO2S9LX3AbjhF4g_5Vu1uVHwNyKEmSxoMhJGK8v0kwtmXWF7dgICKlAWcSE2kscr-1P-m-MgjTPIZaQU27EN3KFNBgPtLalSKcTRoKMWbqnZRyZFB4gIhpXRKOi2wSlRwbzflumRt5PBGQ6AAdqJaZhEDKYIRVwiYiLh8ODXC2WNhF9KS7GqXRE9QopOcQkh3n_AAADIgzOMdrVr26VTXKXZlwtTYZ5cNPxRZA7QkQVB9HMh7WwwstcSLlVRnHcGZJwmTUfpdGExAywCu4DkqJRnarfJUmG1Y86ecOFnmuycFo0NPuruUEXUG33Nd_670qOWzICjqu68cx3AXcwh46m8hZGR3Zbs1usYfrWTVfFZxNUYlAOCmjrnIAKfxDe4B4fBKYEyFM7PTUQj1UTChgv5G3wRBZiVPDv67gnOrqtQQNyAtJvWsaSdxEu5LGzO68ntauYM4wohnqx4JBzFrd5YkWivHf10yFb7_mGYxhqG7_lPiWAd7zxJNGYrOHi8qEMPFtKANI4UKLAbyXVgPJuTo_kAmoHpSqvAf2DTNODBJQb_hl6F6gX0gWsJIQ1V7O7xn6aAc0nkiizYSLuoKLSsF8rWSyASnPuHhc5AeFVEqA8oRYeZLMh9BBYr8w3kGa6eobtp8j8g2YcEy-KSCgxuef94OIRn6EPbvkfhhz8bZm9c1670N701J91WnIG7l1WXFAxXnfO055W0ulpbE99sw.HACGOFtKA6ZvoAg4Prgiaw",
	//			Certificate: testCert,
	//		},
	//	},
	//
	//	claim: client.LicenseClaims{},
	//
	//	corrupt: true,
	// },
	// {
	//	description: "claim with the JWT signed by some evil random private key",
	//	license: api.LicenseKey{
	//		ObjectMeta: v1.ObjectMeta{
	//			Name: "default",
	//		},
	//		Spec: api.LicenseKeySpec{
	//			Token:       "eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJVeG1hUnBucS1Oc2JORWY1IiwidGFnIjoiZkFnR2I0U2R5WlRTTWJVTFZSVE91dyIsInR5cCI6IkpXVCJ9.ao8K2OAgme4kwVejNn-Lvg.CyEws8QbrDGjtkVx.Pebt9PmCpWvPcVYkzkY2BSP92RGCOfg7oGHSfo5MiabnXXn6KDQ6rT2wxHjcHTNcszYO8nZ_w4nUIvH0Vg-7VAbHhvYFpsbtuc8eXRSbqV9Vt0-jm4N9iQFbT5bEi-qyPk5p-OjK_UO8tAPll7foQz9DlqG1h55Pn2RyrjL2-oTJeDb5b7uRkLFASeD-ApqB6NylQ6oskCr9GN5vHaV5_tRaoaWTlCPFwUIQc1TMwoBDoyNTWJUV45QeuT6ha1T4IgiDS7uJcvPb7omm7dhoXK5aw-b-G8wVlWbfD-0ygzPr9qehkh9IYmJAQtYo46dTJBKIInQUss-IpURNUQKVuYrODFkw4GEpQ4FQAamIktYt_EHudzMrrtJM3xhvtYT9bYJz-0_wYnloy7kJMd7JHPaRxH3wICAw0UUe-0F8sViA5NTnADKSXnpWRRDArsFKezywdUqCgRV9lwHbaDKSJFaMSOMJ3BmTXOz_vJ1hiWCjelAUU0sE6r0tcIYPgc705hLYnRb5Xk_qePhtFdAZkqRkymnYJVRRYmQhVYaDEB33E9UYFLqL1EOhkfRnu-iNuMky9OfjuwrjoBaVJDlBQ9y76iOMoDZr4hpEIsESli8nY0MzzHLc2T4WUd1rx9XSw7VaojSYPvpK9JWhJkWcQVb28FNJB6Fui7V_T1bnF44vBqy2OKY3iK-OotULdm76Jm_rSXgpoJldUOjc31f6qTD78SeZ5UhyxgLGCzS5lHri1FCiYDjy6dcFGNfoWJ1Lpj5mTY_4OLnfLG2yqlyqRfrX8bTq5X0.V1LdXb0VgrJDlkeQ95GWmQ",
	//			Certificate: testCert,
	//		},
	//	},
	//
	//	claim: client.LicenseClaims{},
	//
	//	corrupt: true,
	// },
	// {
	//	description: "claim with the JWT signed by tigera but certificate is swapped out with an evil certificate",
	//	license: api.LicenseKey{
	//		ObjectMeta: v1.ObjectMeta{
	//			Name: "default",
	//		},
	//		Spec: api.LicenseKeySpec{
	//			Token:       "eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJ3WWpuYjV6TTF5MlV6RFZ4IiwidGFnIjoiN1dSUkxPanNGQ0F1R3pNRGg5akc1USIsInR5cCI6IkpXVCJ9.HtXrz5-Q_vVfKwgn9Ig_zQ.xf6FZYH3315Tffzv.v7JNl7qOWTivF3Y0Fla-5uG-SM7zCVWcOWEncS7y5kc_uIIRTvTqXV7LAB0b6rZFkXGYxo3X0nBADh7yVJO2S9LX3AbjhF4g_5Vu1uVHwNyKEmSxoMhJGK8v0kwtmXWF7dgICKlAWcSE2kscr-1P-m-MgjTPIZaQU27EN3KFNBgPtLalSKcTRoKMWbqnZRyZFB4gIhpXRKOi2wSlRwbzflumRt5PBGQ6AAdqJaZhEDKYIRVwiYiLh8ODXC2WNhF9KS7GqXRE9QopOcQkh3n_AAADIgzOMdrVr26VTXKXZlwtTYZ5cNPxRZA7QkQVB9HMh7WwwstcSLlVRnHcGZJwmTUfpdGExAywCu4DkqJRnarfJUmG1Y86ecOFnmuycFo0NPuruUEXUG33Nd_670qOWzICjqu68cx3AXcwh46m8hZGR3Zbs1usYfrWTVfFZxNUYlAOCmjrnIAKfxDe4B4fBKYEyFM7PTUQj1UTChgv5G3wRBZiVPDv67gnOrqtQQNyAtJvWsaSdxEu5LGzO68ntauYM4wohnqx4JBzFrd5YkWivHf10yFb7_mGYxhqG7_lPiWAd7zxJNGYrOHi8qEMPFtKANI4UKLAbyXVgPJuTo_kAmoHpSqvAf2DTNODBJQb_hl6F6gX0gWsJIQ1V7O7xn6aAc0nkiizYSLuoKLSsF8rWSyASnPuHhc5AeFVEqA8oRYeZLMh9BBYr8w3kGa6eobtp8j8g2YcEy-KSCgxuef94OIRn6EPbvkfhhz8bZm9c1670N701J91WnIG7l1WXFAxXnfO055W0ulpbE99sw.HACGOFtKA6ZvoAg4Prgiaw",
	//			Certificate: evilCert,
	//		},
	//	},
	//
	//	claim: client.LicenseClaims{},
	//
	//	corrupt: true,
	// },
	// {
	//	description: "claim with the JWT signed by an evil private key but certificate is still the tigera original cert",
	//	license: api.LicenseKey{
	//		ObjectMeta: v1.ObjectMeta{
	//			Name: "default",
	//		},
	//		Spec: api.LicenseKeySpec{
	//			Token:       "eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJLeWE0VHpEaWY2eFM3TTl2IiwidGFnIjoiYVhHR3d0alczSjhKeWgtb2hWajRJdyIsInR5cCI6IkpXVCJ9.LgbBH-IGmLH2iUFY171xwA.NImD2DVyH1ahbruT.DHhdADLX7BfwwYoknoTnPEQGh7vItF7YhYukfPDm_VlwgERXTDdqb6wFQQOZOvFFlcMRYBBzDQBguSkYEHYWegHIuZ7Amfh8uCcI0l93BPz1TrOZdX4fukikb5YVTbRJjxgJTvakucG9dh45hwks9gUCGdXFvVAJH_wMDc_kPVeb0fx84f_H30gNswvKItyIT09lOiRCfy9HOGdpo1RlA0UCZvIPYD9zSl1_ldGZ5Oj2RYz9HU7bhuqV4AU7OuglE_8yvNMmkqSD9BmiLOxzxMVvg3uj5trmuTOy4pAZuchykM3p-DgGiWuo4kyaHvpcfIISSyBU8xtVMyWALayeaschyvlAvRJHAVjKd9Cubx5akA23w4KpBGsJ2EgQPNmyHdEoxqKohO6KbYcOvsD7PThH8e9UV7GgGrQp4OUBZXfym-_yi_erI6FC91n3rgcSMqYpIrhC5-dPSExKuPVA_94dlcP-cDxAtuL8W0T8mafTqKl4Vg-Ojaj7pul4-i7223loZSbkYEpuoTzHYglgB2_PfHgkZsqgl8adlm7muKpxSe_TH-6wQh6fXxGzUJEu7DLvcy82r5v_HcWtJUj43qu8BTHR4sc4_1NU8eHya_HtwgvOo98Ze1Gd9qC_GOFkMYomEk2ogarPnGGKD-gfMN3GxziUz5d4kpb8mzknGIX5hqaxcslV4HDnSA97zjssyajg1Eh-a6xOIaPOlYW3YzXQ3GQPABLn18V2hFCNhB-ml6KWceYA6EsxnKqdEK2KN8dnDGESdjwCIUfcY7KFRD30qhAOUAKpU14.YvpAmE0JPK1Brn7kgGphlg",
	//			Certificate: testCert,
	//		},
	//	},
	//
	//	claim: client.LicenseClaims{},
	//
	//	corrupt: true,
	// },
	// {
	//	// TODO (gunjan5): THIS TEST SHOULD FAIL ONCE WE ADD CERT CHAIN VALIDATION!!!!
	//	description: "claim with the JWT signed by an evil private key with an evil cert",
	//	license: api.LicenseKey{
	//		ObjectMeta: v1.ObjectMeta{
	//			Name: "default",
	//		},
	//		Spec: api.LicenseKeySpec{
	//			Token:       "eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJyS0UycFlocnhkWl9Fd2NOIiwidGFnIjoiQ0ZEcUotaTJTRUQwVmN5Si1EdGxiUSIsInR5cCI6IkpXVCJ9.FvqJP0N6R-udVr993WXaow.T8D4LnRW5LHtlI9N.NXK2hpRK9jHK6g00PJfGD1xK5YDDtSYP0kMM6BCEjSNcGiCrKAt9bDEHsYUttkY74OO_pMfGJOx_-RdFcfk_JxKJLR2mtTX6Tyx0oP3QN6OoHbzqfIEs_FWjqyLvxnGvIgzJpusF_LBg3MOuRflLr8Wn9bGNZN37er0PtZs2L5KqtgFmPKe-IqVNXIqZ7F1DUhwNmWruGguffGtnavuXcHYvqyAX5PUsatia0tGrkIP8810DgwqPBqzZquZIncR6n_1HdW1jFFJ4SWv2J4CkKct74jxPbxQHoItvTeqtlvntjclri1LiLRzkbPU4yYA3MFibexaIbn6yD6aCZkPOwjtkciB7f-Wg-Vx7DHV6_XbEtTFjummiJY87e8R-gCxFQNRmZ5zJKuoFCo_KGLL_HRG6plNmt3M6Z3vrk28Gx26Pv_caSA9IY3hcGn89ah4Nif1pSf7ioRZDjeac3wusBper_TsZ5FJd-DSI91laYNwAh3_Obp0YswxigFLIpZzGICac6CPFx58zQp8XZAPG8LeL049Byx_yTheOwfsWIeplrBrnCCXqSQ4fPrW2Lx7aS-VyWgcDX7JhO54YzGsL9k5WUcYjVxCsO1tPdfv4uzVBRJYR27oodwdCs0cOEAP8uZBDpGGFeVlWDAZatSCX8MLSBzu3Fo97HafabQ8jg3Piy0XTaBUC1fWJU6ygLdLxtzpRERUJL32-DbdWw0j4YfgDrqYZhpk_XXhNHiPKUbyC7kPh8jaFwHgYbq2jwHBMo4pOs3tLH9-36q4FNeHOIFN7ZqsGENLl-3bgHfRj5eJT1nhcc2z_6D0036pgZDcTOh_wfFoI0FujD0A3NKNhBUueo_rTjFIqA7l_WiNZj0HLaCU1ezx1GuoM.UPz5crKaIBcSwsaeLvaq6w",
	//			Certificate: evilCert,
	//		},
	//	},
	//
	//	claim: client.LicenseClaims{
	//		LicenseID:   "a34d87c2-aea0-4b40-8c8b-1dae3fd13990",
	//		Nodes:       &numNodes1,
	//		Customer:    "iwantcake5",
	//		Features: []string{"cnx", "all"},
	//		GracePeriod: 88,
	//		Claims: jwt.Claims{
	//			Expiry:   jwt.NewNumericDate(time.Date(2029, 3, 14, 23, 59, 59, 59, time.Local)),
	//			IssuedAt: 1521765193,
	//		},
	//	},
	//
	//	corrupt: false,
	// },
}

func TestDecodeAndVerify(t *testing.T) {
	for _, entry := range tokenToLicense {
		t.Run(entry.description, func(t *testing.T) {
			RegisterTestingT(t)

			// lic, err := client.GenerateLicenseFromClaims(entry.claim, absPkeyPath, absCertPath)
			// spew.Dump(lic)

			claims, err := client.Decode(entry.license)

			if entry.corrupt {
				Expect(err).To(HaveOccurred(), entry.description)
			} else {
				Expect(err).NotTo(HaveOccurred(), entry.description)
				Expect(claims).Should(Equal(entry.claim), entry.description)
			}
		})
	}
}

//go:embed testutils/test-data/test-customer-license.pem
var testCert string

//go:embed testutils/test-data/test-customer-token.txt
var testToken string

//go:embed testutils/test-data/test-customer-signed-by-intermediate-license.pem
var testIntermediateCert string

//go:embed testutils/test-data/test-customer-signed-by-intermediate-token.txt
var testIntermediateToken string

func TestDecodeNewRoot(t *testing.T) {
	RegisterTestingT(t)
	licenseKey := api.LicenseKey{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: api.LicenseKeySpec{
			Token:       testToken,
			Certificate: testCert,
		},
	}
	claims, err := client.Decode(licenseKey)
	Expect(err).To(BeNil())
	Expect(claims.Customer).To(Equal("test-customer"))
	Expect(claims.Expiry.Time().Compare(time.Date(2125, 1, 2, 7, 59, 59, 0, time.UTC))).To(Equal(0))

	// Tests that api-server wouldn't panic when handling this license. (This can happen when the license has nil nodes.)
	strategy := licensekey.NewStrategy(runtime.NewScheme())
	strategy.PrepareForCreate(context.TODO(), &licenseKey)
}

func TestDecodeNewIntermediate(t *testing.T) {
	RegisterTestingT(t)
	licenseKey := api.LicenseKey{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: api.LicenseKeySpec{
			Token:       testIntermediateToken,
			Certificate: testIntermediateCert,
		},
	}
	claims, err := client.Decode(licenseKey)
	Expect(err).To(BeNil())
	Expect(claims.Customer).To(Equal("test-customer-signed-by-intermediate"))
	Expect(claims.Expiry.Time().Compare(time.Date(2125, 1, 2, 7, 59, 59, 0, time.UTC))).To(Equal(0))

	// Tests that api-server wouldn't panic when handling this license. (This can happen when the license has nil nodes.)
	strategy := licensekey.NewStrategy(runtime.NewScheme())
	strategy.PrepareForCreate(context.TODO(), &licenseKey)
}

func TestFeatureFlags(t *testing.T) {
	numNodes := 5
	sampleClaims := client.LicenseClaims{
		LicenseID:   "yaddayadda",
		Nodes:       &numNodes,
		Customer:    "MyFavCustomer99",
		GracePeriod: 90,
		Claims: jwt.Claims{
			Expiry: jwt.NewNumericDate(time.Now().Add(72 * time.Hour).UTC()),
			Issuer: "Gunjan's office number 5",
		},
	}

	t.Run("a license with 'all' features states that each feature is enabled.", func(t *testing.T) {
		RegisterTestingT(t)

		claims := sampleClaims
		claims.Features = []string{features.All}
		Expect(claims.ValidateFeature(features.AWSCloudwatchMetrics)).To(BeTrue())
	})

	t.Run("a license only valid for cloudwatch metrics is valid for cloudwatch metrics.", func(t *testing.T) {
		RegisterTestingT(t)

		claims := sampleClaims
		claims.Features = []string{features.AWSCloudwatchMetrics}
		Expect(claims.ValidateFeature(features.AWSCloudwatchMetrics)).To(BeTrue())
	})

	t.Run("a license only valid for cloudwatch metrics is not valid for ipsec.", func(t *testing.T) {
		RegisterTestingT(t)

		claims := sampleClaims
		claims.Features = []string{features.AWSCloudwatchMetrics}
		Expect(claims.ValidateFeature(features.IPSec)).To(BeFalse())
	})

	t.Run("validate a new base feature", func(t *testing.T) {
		RegisterTestingT(t)

		claims := sampleClaims
		claims.Features = []string{"cnx", "all"}

		Expect(claims.ValidateFeature("new-base-feature")).To(BeTrue())
	})
}

func TestLicenseStatus(t *testing.T) {
	t.Run("empty claims status is none", func(t *testing.T) {
		RegisterTestingT(t)

		var claims *client.LicenseClaims
		Expect(claims.Validate()).To(Equal(client.NoLicenseLoaded))
	})

	t.Run("valid claims are valid", func(t *testing.T) {
		RegisterTestingT(t)

		claims := client.LicenseClaims{
			GracePeriod: 0,
			Claims: jwt.Claims{
				Expiry: jwt.NewNumericDate(time.Now().Add(72 * time.Hour).UTC()),
			},
		}

		Expect(claims.Validate()).To(Equal(client.Valid))
	})

	t.Run("grace period claims are in grace period", func(t *testing.T) {
		RegisterTestingT(t)

		claims := client.LicenseClaims{
			GracePeriod: 2,
			Claims: jwt.Claims{
				Expiry: jwt.NewNumericDate(time.Now().UTC()),
			},
		}

		Expect(claims.Validate()).To(Equal(client.InGracePeriod))
	})

	t.Run("expired claims are expired", func(t *testing.T) {
		RegisterTestingT(t)

		claims := client.LicenseClaims{
			GracePeriod: 0,
			Claims: jwt.Claims{
				Expiry: jwt.NewNumericDate(time.Now().UTC()),
			},
		}

		Expect(claims.Validate()).To(Equal(client.Expired))
	})

	t.Run("expired claims are expired after grace period", func(t *testing.T) {
		RegisterTestingT(t)

		claims := client.LicenseClaims{
			GracePeriod: 1,
			Claims: jwt.Claims{
				Expiry: jwt.NewNumericDate(time.Now().Add(-48 * time.Hour).UTC()),
			},
		}

		Expect(claims.Validate()).To(Equal(client.Expired))
	})

}
