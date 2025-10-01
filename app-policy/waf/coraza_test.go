package waf_test

import (
	_ "embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	geo "github.com/corazawaf/coraza-geoip"
	envoyauthz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/code"

	"github.com/projectcalico/calico/app-policy/internal/util/testutils"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/waf"
	"github.com/projectcalico/calico/felix/proto"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

//go:embed testdata/tigera.conf
var tigeraConfContents string

func TestCorazaWAFAuthzScenarios(t *testing.T) {
	RegisterTestingT(t)
	logrus.SetLevel(logrus.TraceLevel)

	corazaWAFScenarios := []corazaWAFScenario{
		{
			name:  "allow",
			store: nil,
			directives: []string{
				"Include @coraza.conf-recommended",
				"Include @crs-setup.conf.example",
				"Include @owasp_crs/*.conf",
				"SecRuleEngine On",
			},
			checkReq:         testutils.NewCheckRequestBuilder(),
			expectedResponse: waf.OK,
			expectedErr:      nil,
			expectedLogs:     nil,
		},
		{
			name:       "deny - SQL injection 1",
			store:      nil,
			directives: []string{},
			additionalConfigFiles: map[string]string{
				"tigera.conf": tigeraConfContents,
			},
			checkReq: testutils.NewCheckRequestBuilder(
				testutils.WithMethod("GET"),
				testutils.WithHost("my.loadbalancer.address"),
				testutils.WithPath("/cart?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user"),
			),
			expectedResponse: waf.DENY,
			expectedErr:      nil,
			expectedLogs: []*v1.WAFLog{
				{},
			},
		},
		{
			name:  "deny - SQL injection 2, detection only",
			store: nil,
			directives: []string{
				"Include @coraza.conf-recommended",
				"Include @crs-setup.conf.example",
				"Include @owasp_crs/*.conf",
				"SecRuleEngine DetectionOnly",
			},
			checkReq: testutils.NewCheckRequestBuilder(
				testutils.WithMethod("POST"),
				testutils.WithHost("www.example.com"),
				testutils.WithPath("/vulnerable.php?id=1' waitfor delay '00:00:10'--"),
				testutils.WithScheme("https"),
			),
			expectedResponse: waf.OK,
			expectedErr:      nil,
			expectedLogs: []*v1.WAFLog{
				{},
			},
		},
		{
			name:  "deny - SQL injection 2, detection only with rootFS",
			store: nil,
			// In this test case, we setup a sample ruleset that only detects SQL injection.
			// It's based on coraza-coreruleset, but only contains the 3 fields we need.
			rootFS: func(t *testing.T) fs.FS {
				corazaConf, err := fs.ReadFile(coreruleset.FS, "@coraza.conf-recommended")
				if err != nil {
					t.Error(err)
				}
				crsSetup, err := fs.ReadFile(coreruleset.FS, "@crs-setup.conf.example")
				if err != nil {
					t.Error(err)
				}
				sqliConf, err := fs.ReadFile(coreruleset.FS, "@owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
				if err != nil {
					t.Error(err)
				}
				return fstest.MapFS{
					"coraza.conf":    {Data: corazaConf},
					"crs-setup.conf": {Data: crsSetup},
					"crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": {Data: sqliConf},
				}
			}(t),
			directives: []string{
				"Include coraza.conf",
				"Include crs-setup.conf",
				"Include crs/*.conf",
				"SecRuleEngine DetectionOnly",
			},
			checkReq: testutils.NewCheckRequestBuilder(
				testutils.WithMethod("POST"),
				testutils.WithHost("www.example.com"),
				testutils.WithPath("/vulnerable.php?id=1' waitfor delay '00:00:10'--"),
				testutils.WithScheme("https"),
			),
			expectedResponse: waf.OK,
			expectedErr:      nil,
			expectedLogs: []*v1.WAFLog{
				{},
			},
		},
	}

	// geoip database tests
	geoIPInitFn := func(t *testing.T) func() error {
		return func() error {
			mmdbBytes, err := createSingleRUEntryMMDB()
			if err != nil {
				t.Fatalf("Failed to create MMDB: %v", err)
				return err
			}
			if err := geo.RegisterGeoDatabase(mmdbBytes, "city"); err != nil {
				t.Fatalf("Failed to register GeoIP database: %s", err)
				return err
			}
			return nil
		}
	}

	corazaWAFScenarios = append(corazaWAFScenarios,
		corazaWAFScenario{
			name:    "geoip - deny certain countries",
			initFns: []func() error{geoIPInitFn(t)},
			store:   nil,
			directives: []string{
				"Include @coraza.conf-recommended",
				"Include @crs-setup.conf.example",
				"Include @owasp_crs/*.conf",
				`SecRule REMOTE_ADDR "@geoLookup" "phase:1,id:155,nolog,pass"`,
				`SecRule &GEO "@eq 0" "phase:1,id:156,deny,msg:'Failed to lookup IP'"`,
				`SecRule GEO:COUNTRY_CODE "@streq RU" "phase:1,id:157,deny,msg:'Access from Russia is not allowed'"`,
				"SecRuleEngine On",
			},
			checkReq: testutils.NewCheckRequestBuilder(
				testutils.WithMethod("GET"),
				testutils.WithHost("my.loadbalancer.address"),
				testutils.WithPath("/cart"),
				testutils.WithSourceHostPort("95.173.136.1", 0), // Russian IP (Moscow, Moscow, Russia (RU), Europe)
			),
			expectedResponse: waf.DENY,
			expectedErr:      nil,
			expectedLogs: []*v1.WAFLog{
				{},
			},
		},
		corazaWAFScenario{
			name:    "geoip - deny traffic that is not in the database (e.g. private IPs)",
			initFns: []func() error{geoIPInitFn(t)},
			store:   nil,
			directives: []string{
				"Include @coraza.conf-recommended",
				"Include @crs-setup.conf.example",
				"Include @owasp_crs/*.conf",
				`SecRule REMOTE_ADDR "@geoLookup" "phase:1,id:155,nolog,pass"`,
				`SecRule &GEO "@eq 0" "phase:1,id:156,deny,msg:'Failed to lookup IP'"`,
				"SecRuleEngine On",
			},
			checkReq: testutils.NewCheckRequestBuilder(
				testutils.WithMethod("GET"),
				testutils.WithHost("my.loadbalancer.address"),
				testutils.WithPath("/cart"),
				testutils.WithSourceHostPort("10.0.0.1", 0), // Private IP (not in geoip database)
			),
			expectedResponse: waf.DENY,
			expectedErr:      nil,
			expectedLogs: []*v1.WAFLog{
				{},
			},
		},
		corazaWAFScenario{
			name:    "geoip - only deny traffic from Russia, allow all others including private IPs",
			initFns: []func() error{geoIPInitFn(t)},
			store:   nil,
			directives: []string{
				"Include @coraza.conf-recommended",
				"Include @crs-setup.conf.example",
				"Include @owasp_crs/*.conf",
				`SecRule REMOTE_ADDR "@geoLookup" "phase:1,id:155,nolog,pass"`,
				`SecRule GEO:COUNTRY_CODE "@streq RU" "phase:1,id:157,deny,msg:'Access from Russia is not allowed'"`,
				"SecRuleEngine On",
			},
			checkReq: testutils.NewCheckRequestBuilder(
				testutils.WithMethod("GET"),
				testutils.WithHost("my.loadbalancer.address"),
				testutils.WithPath("/cart"),
				testutils.WithSourceHostPort("10.0.0.1", 0), // Private IP (not in geoip database)
			),
			expectedResponse: waf.OK,
			expectedErr:      nil,
			expectedLogs: []*v1.WAFLog{
				{},
			},
		},
	)

	for _, scenario := range corazaWAFScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			runCorazaWAFAuthzScenario(t, &scenario)
		})
	}

}

func runCorazaWAFAuthzScenario(t testing.TB, scenario *corazaWAFScenario) {
	psm := policystore.NewPolicyStoreManager()
	psm.OnInSync()

	tempDir := t.TempDir()
	files := []string{}
	for name, content := range scenario.additionalConfigFiles {
		t.Log("Writing additional config file", tempDir, name)
		if err := os.WriteFile(filepath.Join(tempDir, name), []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write file %s: %s", name, err)
		}
		// append the file to the directives
		files = append(files, filepath.Join(tempDir, name))
	}
	var observedLogs []*proto.WAFEvent
	cb := func(v *proto.WAFEvent) {
		observedLogs = append(observedLogs, v)
	}
	evp := waf.NewEventsPipeline(cb)
	waf, err := waf.New(
		scenario.rootFS,
		files,
		scenario.directives,
		true,
		evp,
		scenario.initFns...,
	)
	if err != nil {
		t.Fatalf("Failed to create WAF: %s", err)
	}

	resp, err := waf.Check(scenario.store, scenario.checkReq.Value())
	if err != scenario.expectedErr {
		t.Fatalf("Expected error %v, but got %v", scenario.expectedErr, err)
	}

	if resp.Status.Code != scenario.expectedResponse.Status.Code {
		t.Fatalf(
			"Expected response code %s, but got %s",
			code.Code(scenario.expectedResponse.Status.Code),
			code.Code(resp.Status.Code),
		)
	}

	Eventually(func() error {
		if len(observedLogs) != len(scenario.expectedLogs) {
			return fmt.Errorf("Expected %d logs, but got %d", len(scenario.expectedLogs), len(observedLogs))
		}

		return nil
	}, "2s", "200ms")
}

type corazaWAFScenario struct {
	name                  string
	rootFS                fs.FS
	directives            []string
	additionalConfigFiles map[string]string
	store                 *policystore.PolicyStore
	checkReq              *testutils.CheckRequestBuilder
	expectedResponse      *envoyauthz.CheckResponse
	expectedErr           error
	expectedLogs          []*v1.WAFLog
	initFns               []func() error
}
