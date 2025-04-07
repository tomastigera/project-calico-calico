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

			config := map[string]interface{}{
				"WindowsDNSExtraTTL":   "10",
				"DNSCacheSaveInterval": "10",
			}

			err := fv.AddConfigItems(config)
			Expect(err).NotTo(HaveOccurred())

			fv.RestartFelix()

			porterIP = testutils.InfraPodIP("porter", "demo")
			Expect(porterIP).NotTo(BeEmpty())

			testutils.KubectlApply("allow-dns.yaml", allowDnsPolicy)

			curlWithError("www.google.com")
			curlWithError("gobyexample.com")
		})

		AfterEach(func() {
			testutils.KubectlDelete("allow-domain.yaml")
			testutils.KubectlDelete("allow-dns.yaml")
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
			curl("www.google.com")
			t2 := time.Now()
			curl("gobyexample.com")

			log.Printf("-----\nhttp www.google.com took %v seconds \n-----", t2.Sub(t1).Seconds())

			Expect(strings.Contains(getEndpointInfo(porterIP), "allow-domain")).To(BeTrue())

			displayDNS()

			// All the above code (with logging) takes time, could be more than DNS TTL so when we
			// try to check DNS cache file, the DNS map could have been cleared.
			// We should initiate the traffic again before checking DNS cache file.

			checkCache := func(domain string) error {
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

			curl("gobyexample.com")
			// Make sure we see domain ips in DNS Cache file
			Eventually(checkCacheFunc("gobyexample.com"), "30s", "1s").Should(BeNil())

			curl("www.google.com")
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
			output := testutils.Powershell("logman query -ets")
			log.Printf("-----\n%s\n-----", output)

			Expect(strings.Contains(output, "tigera")).To(BeFalse())
			Expect(strings.Contains(output, "PktMon")).To(BeFalse())
		})

		AfterEach(func() {
			testutils.Powershell("Start-Service -Name CalicoFelix")
		})
	})
})

func curl(target string) {
	cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config exec -t porter -n demo -- powershell.exe "curl %s -UseBasicParsing -TimeoutSec 10"`,
		target)
	output := testutils.Powershell(cmd)
	log.Printf("-----\n%s\n-----", output)
	Expect(strings.Contains(output, "200")).To(BeTrue())
}

func curlWithError(target string) {
	cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config exec -t porter -n demo -- powershell.exe "curl %s -UseBasicParsing -TimeoutSec 10"`,
		target)
	testutils.PowershellWithError(cmd)
}

func displayDNS() {
	cmd := `c:\k\kubectl.exe --kubeconfig=c:\k\config exec -t porter -n demo -- powershell.exe "ipconfig /displaydns"`
	output := testutils.Powershell(cmd)
	log.Printf("-----\n%s\n-----", output)
}

func getEndpointInfo(target string) string {
	cmd := fmt.Sprintf(` Get-HnsEndpoint | where  IpAddress -EQ %s | ConvertTo-Json -Depth 5`, target)
	output := testutils.Powershell(cmd)
	log.Printf("-----\n%s\n-----", output)
	return output
}
