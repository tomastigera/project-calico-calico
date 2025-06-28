// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package utils

import (
	"os"
	"path"

	"github.com/projectcalico/go-yaml-wrapper"
	"github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

func loadTestLicense(name string) (filePath string, lic *api.LicenseKey) {
	// Try to find the license in the standard banzai secrets dir (for devs) and the dir
	// used in CI.
	paths := []string{
		path.Join(os.Getenv("HOME"), ".banzai", "secrets", name),
		path.Join(os.Getenv("HOME"), "secrets", name),
		path.Join("/", "secrets", name),
	}
	// Allow override of the license dir.
	if licEnv := os.Getenv("CALICO_TEST_LICENSE_DIR"); licEnv != "" {
		paths = append([]string{path.Join(licEnv, name)}, paths...)
	}
	for _, licenseFilePath := range paths {
		var lk api.LicenseKey
		rawKey, err := os.ReadFile(licenseFilePath)
		if os.IsNotExist(err) {
			logrus.WithField("file", licenseFilePath).Debug("Candidate license file didn't exist")
			continue
		}
		err = yaml.Unmarshal(rawKey, &lk)
		if err != nil {
			logrus.WithField("file", licenseFilePath).WithError(err).Warn("Failed to parse candidate license file, may try another.")
			continue
		}
		logrus.WithField("file", licenseFilePath).Info("Loaded test license from file.")
		return licenseFilePath, &lk
	}
	panic("Failed to load license file")
}

func ValidEnterpriseTestLicensePath() string {
	p, _ := loadTestLicense("license.yaml")
	return p
}

func ValidEnterpriseTestLicense() *api.LicenseKey {
	_, lic := loadTestLicense("license.yaml")
	return lic
}

func GracePeriodTestLicense() *api.LicenseKey {
	_, lic := loadTestLicense("license-grace.yaml")
	return lic
}

const ExpiredCert = `-----BEGIN CERTIFICATE-----
MIIFzjCCA7agAwIBAgIQDLgkTDLTHuGmiazKQo08BzANBgkqhkiG9w0BAQsFADCB
tTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xFDASBgNVBAoTC1RpZ2VyYSwgSW5jMSIwIAYDVQQLDBlTZWN1
cml0eSA8c2lydEB0aWdlcmEuaW8+MT8wPQYDVQQDEzZUaWdlcmEgRW50aXRsZW1l
bnRzIEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTgwNDA1
MjMzNDA4WhcNMTgwNDA0MjMzNDA3WjCBpjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
CkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xFDASBgNVBAoTC1Rp
Z2VyYSwgSW5jMSIwIAYDVQQLDBlTZWN1cml0eSA8c2lydEB0aWdlcmEuaW8+MTAw
LgYDVQQDEydUaWdlcmEgRW50aXRsZW1lbnRzIEV4cGlyZWQgQ2VydGlmaWNhdGUw
ggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC8Znw08LfOuISeYGseLAsr
Xzh/UU98qsnxZDnIrCMDtRxn1Xcu5KaHfNxAgNRYGXtgI/gT1lPdX01v3FUesGvi
nRugOnH/3JqpWkWf2rPxnxFxyEvOVty1LmZZF3rDxMYA11n9RLej+OCH22siA4dg
d4qTWncX1E62QR9c84WHImELo5m0809zPfGBrsDHRC6xcYZJP/gT/ddDkp4zSQwz
KTlVGXj4m6uewAfR+5HW35Xf5UALc/n6TwJSR3A4P5VCKUGT6WwWCLadjjBIYoAg
u3vQ1IFj6wKz4NPxev0hMOJ0MZB6KiX+KJ4UtEU2XyzGtvf5R49Zc9OLYJc9dNY2
RAUHSfduy2rXFUXTdMBKSr0amOtkO0gLwVeqfCGnZCkeVF+g5ruBy3oR790vSd/5
lwQgW4ZUDUY7VJQkC1pe2oPmvoyP3WdXMvlLz4uP7Ge4FfhjjJpBH5Lk0sxRziuo
Qch4PHKA0KhMQ1BtVM1K0QvXii5GTBoCeR65BVz+tF0CAwEAAaNnMGUwDgYDVR0P
AQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBQup4vPb8uI
ca01T6Bh3SepMQ1oZDAfBgNVHSMEGDAWgBTFkDmSJ/Ojg2eJB8Ypv7jCu5MgWjAN
BgkqhkiG9w0BAQsFAAOCAgEAhL15o5tSiu+4pQh0lVlMxFq9OW2HS8RHHH9cb/ns
Xke/F3POI7bZ4IxivAcaNBfYMKwlAAbYOOYHzwBbswyD53VZi6WTMBd4xQpeChrW
9BkAWShOt6tim3RH7K5LyajOwVWrE1yo26oj2pexG7nQqg0WTd9YmsZGPp1oPraQ
Hs18tBbjCCs/NkDlwfqvrCm8T6+MW1jLE/1q1bdBoZuICb+hKK8HjDxP7QPCX51F
4WHAMxVSCJe5m0o+cIo5Q4GY3tjAvNv1AKY1jxPkocbah+6I6dhqf3aRz+As1EHI
bd/1LFskx3K7FF2wHkTDS+FnxIPAwCH8CYRmypIQBEN7ItKsksXu6ZVpG44e/naI
9JeMRSg59SwEgS6/kKOLoF7zJcyLF56LN80QHFVaLKCWWm7vBKuMVxOxT9wuQP0l
0sglXHZ36qrk2UXebHPkvJCjY3j2dIP6Tv5bSfXVb43HjumsKB2hUu74xYbPZDuo
O70Yf/Rspkb4Fv2OHXMHtP+Y3WCIOzF2+e9sNB4WTFv/EJz18o0nvVvYEmtiWBQd
ATrr8ARvAp8p3d1JNXcgxPMJkOg1KWUgquiDGj5OVo4/XxAsDCdmKmC9+SARyl/b
QdtP3kQuhNNtAiZMMo+/HrsJfmrhr1o66a4RlhRhAoj4qewX56RKy2vQOdFaD+ZH
NSs=
-----END CERTIFICATE-----`

const ExpiredToken = `eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJvTGJ2cDhjOVRQdWR` +
	`ka3hiIiwidGFnIjoiSlNHMTZNT1hYRTBiUXpNc082OVFNdyIsInR5cCI6IkpXVCJ9.trUzyPt-thRmY0Xx23JAWQ.EzvF_OIEKtvzlXb` +
	`N.EOyEEePRt2Ns1gb9UFvK8Ta-bI7Z5UjEz-mSpdFHTlnJq4kr4c2RWr8x-uEMPt5tgbSPl37P46HxxaLpq_lQLdGUgELkGvPZ-co-ro` +
	`GQaNF5NRRsyOtaug4oFRTUjXb0blzhptUKWIpdfDWBbK1o44EvrCaq3J6mP_-HTVygIQgOzORybRhHwO8fYApKWAPRtS04A6zMGj_FJr` +
	`-2HvctKaoxpqi6O_Up-zvtnQZYJvEqhW9h1U3Yo5zI4op7K5piz2V5ELtybFla-bMmMUB5Hq7rKDdnORfGic6TVtLr2L_hv3BwEp-m8z` +
	`rqUAfuzYRdT4IYeQebW9mwyrAGoSoA-QknT4fLLXxn0SzxzAKEC6stU4bDRbKW8sxqkDHVhBh3WpIGYOZC4b_QKCDI0Ri8MgB-ifPHDy` +
	`iphAzohOxb2vpuU7GNq5F5vP3B1tMXsiIhMKOe6af5nptBqsH9-1WOGwgzc0VgnEnRaXOrRVENzhP1fybBWgZG9sitNq7AxQklZY4s59` +
	`-BPKF9Jcd_7W35ylLvRpHoXArgd9dNPdDYMt_tfBgrl-ChJGBA_FyloUAnVj4A-RWh4D54bkFupyIsw873C1QBS25Aee0qsldPmq3rpX` +
	`iSd1ecClmtsWs6vxquhSq63TDcl1mhxXEKSLjQngpnk2N81lDbfiVXc4ZhpFY2TtZn5myCePf2dNk88V_KZ0jZvdsTBFH3ztZ-bD17_d` +
	`EAb5a2Ne1-6_7xE47EBMtdXOh4CKEv-p2NGOzk84YUqWwMOY9_e3imENRlnGWolyzJu_VhDMRKWMk1JbaDRigkjEYv3yUQ_dRPrNLUXC` +
	`PDS3DUsjmc0HFhytTtvgWjj6E1-hqMXv5GkVLEu6noPY09drlR9xydd2Ka5xxDLzadulErKu5jZAzBQ43TvogKY31OHh6yXnlpvpkgpG` +
	`6JGkzb1YcpnmUveXLSnbjxVmO21ID4hlB6y0B5ZtKnpFILhxTAz0_YKMdfv0V0K4vQS4zm_mNk_OzhAbZJiB7uhwCDj0H-T1sTCxH1lJ` +
	`NtxW8dwTMoii1PR_K0Mna9TdxVcE2XrGRxkqVfUonm7MSzH-DbyU-9pYbIafRtzKLlzrr-XCNVBTz31ZVmalFm2T8.qUaE2G1nzptgmAumyFOF8g`

func ExpiredTestLicense() *api.LicenseKey {
	// We can pre-can the expired license, it's not going to get any more expired.
	lic := api.NewLicenseKey()
	lic.Name = "default"
	lic.Spec.Certificate = ExpiredCert
	lic.Spec.Token = ExpiredToken
	return lic
}
