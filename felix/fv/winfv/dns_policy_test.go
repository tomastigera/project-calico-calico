// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package winfv_test

import (
	"fmt"
	"log"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/windows-networking/pkg/testutils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/projectcalico/calico/felix/fv/winfv"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

var allowDnsPolicy string = `
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: default.allow-dns
  namespace: demo
spec:
  order: 1
  selector: app == 'porter'
  types:
  - Egress
  egress:
  - action: Allow
    protocol: UDP
    destination:
      ports:
      - 53
`

var allowDomainPolicy string = `
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: default.allow-domain
  namespace: demo
spec:
  order: 1
  selector: app == 'porter'
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      domains:
      - "gobyexample.com"
      - "*.google.com"
`

var _ = Describe("Windows DNS policy test", func() {
	var (
		fv       *WinFV
		err      error
		porterIP string
		dnsMap   []JsonMappingV1
	)

	Context("Check DNS policy", func() {
		BeforeEach(func() {
			rootDir := winutils.GetHostPath("c:\\CalicoWindows")
			flowLogDir := winutils.GetHostPath("c:\\TigeraCalico\\flowlogs")
			dnsCacheFile := winutils.GetHostPath("c:\\TigeraCalico\\felix-dns-cache.txt")

			fv, err = NewWinFV(rootDir,
				flowLogDir,
				dnsCacheFile)
			Expect(err).NotTo(HaveOccurred())

			var tenSeconds metav1.Duration
			tenSeconds.Duration = 10 * time.Second
			config := map[string]any{
				"WindowsDNSExtraTTL":   &tenSeconds,
				"DNSCacheSaveInterval": &tenSeconds,
			}

			err := fv.AddConfigItems(config)
			Expect(err).NotTo(HaveOccurred())

			fv.RestartFelix()

			porterIP = testutils.InfraPodIP("porter", "demo")
			Expect(porterIP).NotTo(BeEmpty())

			testutils.KubectlApply("allow-dns.yaml", allowDnsPolicy)

			Eventually(retryCurlUntilFailure("www.google.com"), "30s", "1s").Should(BeTrue())
			Eventually(retryCurlUntilFailure("gobyexample.com"), "30s", "1s").Should(BeTrue())
		})

		AfterEach(func() {
			testutils.KubectlDelete("allow-domain.yaml")
			testutils.KubectlDelete("allow-dns.yaml")
			err := fv.RestoreConfig()
			Expect(err).NotTo(HaveOccurred())
		})

		// The test code does not check or depend on this, but currently:
		// www.google.com has one ip per DNS request.
		// gobyexample.com has 4 ips per DNS request.
		getDomainIPs := func(domain string) []string {
			result := []string{}
			for _, m := range dnsMap {
				if m.LHS == domain {
					result = append(result, m.RHS)
				}
			}
			return result
		}
		It("should get expected DNS policy", func() {
			// Apply DNS policy
			testutils.KubectlApply("allow-domain.yaml", allowDomainPolicy)

			// curl in Powershell will retransmit SYN packet if there are drops.
			// So we should see packets to go through after the DNS policy is in place.
			t1 := time.Now()
			Eventually(retryCurlUntilSuccess("www.google.com"), "30s", "1s").Should(BeTrue())
			t2 := time.Now()
			Eventually(retryCurlUntilSuccess("gobyexample.com"), "30s", "1s").Should(BeTrue())

			log.Printf("-----\nhttp www.google.com took %v seconds \n-----", t2.Sub(t1).Seconds())

			Expect(strings.Contains(getEndpointInfo(porterIP), "allow-domain")).To(BeTrue())

			displayDNS()

			// All the above code (with logging) takes time, could be more than DNS TTL so when we
			// try to check DNS cache file, the DNS map could have been cleared.
			// We should initiate the traffic again before checking DNS cache file.

			checkCache := func(domain string) error {
				Eventually(retryCurlUntilSuccess(domain), "10s", "1s").Should(BeTrue())
				// Get IPs from DNS cache file
				dnsMap, err = fv.ReadDnsCacheFile()
				if err != nil {
					return err
				}
				if len(dnsMap) == 0 {
					return fmt.Errorf("no DNS map yet")
				}
				log.Printf("dns map %v", dnsMap)

				ips := getDomainIPs(domain)
				if len(ips) == 0 {
					return fmt.Errorf("no ip for %s in DNS map", domain)
				}
				log.Printf("domain ips %v", ips)
				return nil
			}

			checkCacheFunc := func(domain string) func() error {
				return func() error {
					return checkCache(domain)
				}
			}

			// Make sure we see domain ips in DNS Cache file
			Eventually(checkCacheFunc("gobyexample.com"), "30s", "1s").Should(BeNil())

			// Make sure we see domain ips in DNS Cache file
			Eventually(checkCacheFunc("www.google.com"), "30s", "1s").Should(BeNil())
		})
	})

	Context("Check cleanup of the resources", func() {
		BeforeEach(func() {
			if IsRunningHPC() {
				Skip("Skip when using Host Process Container")
			}
			testutils.Powershell("Stop-Service -Name CalicoFelix")
		})

		It("should cleanup etw sessions", func() {
			output, stderr := testutils.Powershell("logman query -ets")
			log.Printf("-----\n%s\n-----", output)
			log.Printf("-----\n%s\n-----", stderr)

			Expect(strings.Contains(output, "tigera")).To(BeFalse())
			Expect(strings.Contains(output, "PktMon")).To(BeFalse())
		})

		AfterEach(func() {
			testutils.Powershell("Start-Service -Name CalicoFelix")
		})
	})
})

func retryCurlUntilSuccess(domain string) func() bool {
	return func() bool {
		OK, err := curl(domain)
		return err == nil && OK
	}
}

func retryCurlUntilFailure(domain string) func() bool {
	return func() bool {
		OK, err := curl(domain)
		return err != nil || !OK
	}
}

func curl(target string) (bool, error) {
	cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config exec -t porter -n demo -- powershell.exe "curl %s -UseBasicParsing -TimeoutSec 10"`,
		target)
	output, stderr, err := powershell(cmd)
	log.Printf("-----\n%s\n-----", output)
	log.Printf("-----\n%s\n-----", stderr)
	return strings.Contains(output, "200"), err
}

func displayDNS() {
	cmd := `c:\k\kubectl.exe --kubeconfig=c:\k\config exec -t porter -n demo -- powershell.exe "ipconfig /displaydns"`
	output, stderr := testutils.Powershell(cmd)
	log.Printf("-----\n%s\n-----", output)
	log.Printf("-----\n%s\n-----", stderr)
}

func getEndpointInfo(target string) string {
	cmd := fmt.Sprintf(` Get-HnsEndpoint | where  IpAddress -EQ %s | ConvertTo-Json -Depth 5`, target)
	output, stderr := testutils.Powershell(cmd)
	log.Printf("-----\n%s\n-----", output)
	log.Printf("-----\n%s\n-----", stderr)
	return output
}
