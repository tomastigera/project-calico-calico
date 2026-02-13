// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package etcdv3_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/etcdv3"
)

var (
	etcdCACertWrongFormatValue = `-----BEGIN CERTIFICATE-----
MIIDvgYJKoZIhvcNAQcCoIIDrzCCA6sCAQExADALBgkqhkiG9w0BBwGgggORMIID
jTCCAvagAwIBAgIQUuSuRj0Dyvze/mcVMwwBCTANBgkqhkiG9w0BAQUFADCBzjEL
MAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTESMBAGA1UEBxMJQ2Fw
ZSBUb3duMR0wGwYDVQQKExRUaGF3dGUgQ29uc3VsdGluZyBjYzEoMCYGA1UECxMf
Q2VydGlmaWNhdGlvbiBTZXJ2aWNlcyBEaXZpc2lvbjEhMB8GA1UEAxMYVGhhd3Rl
IFByZW1pdW0gU2VydmVyIENBMSgwJgYJKoZIhvcNAQkBFhlwcmVtaXVtLXNlcnZl
ckB0aGF3dGUuY29tMB4XDTA2MTAyMDAzMzIyNVoXDTA3MTAyMDAzMzIyNVowgZEx
CzAJBgNVBAYTAkFVMREwDwYDVQQIEwhWaWN0b3JpYTESMBAGA1UEBxMJTWVsYm91
cm5lMS0wKwYDVQQKEyRDYXJlIEZvciBLaWRzIEludGVybmV0IFNlcnZpY2VzIFAv
TCAxCzAJBgNVBAsTAklTMR8wHQYDVQQDExZ3d3cuY2FyZWZvcmtpZHMuY29tLmF1
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCw/gfqN/0OAf3uZku10cQSJw48
HUgfqRHZTRWHAvdxyORjWY/+7qozwx/Ja9VyxX/Z87hcY+EEXJ8WzB6Ojchl/D1K
9oWN9DnxDmiQgvPQ0F92nfxXeg71oIUS2EVChZoqHa25lv3VuKyk3eX0NFzKITwn
+qvYFcejBzTvUV5ewQIDAQABo4GmMIGjMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vY3JsLnRoYXd0ZS5jb20v
VGhhd3RlUHJlbWl1bVNlcnZlckNBLmNybDAyBbbqBgEFBQcBAQQmMCQwIgYIKwYB
BQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0ZS5jb20wDAYDVR0TAQH/BAIwADANBgkq
hkiG9w0BAQUFAAOBgQDKFdgfgF6/y/aRvkRKVtU+PqCfiQ2+bLNEPy2xCK7LVM0k
SaZ407kT4F1I4NlPEyoKRNMa3b6m0+fk8J3yvqiZKI1eJbaLTDEeG7BtgcdaM1ST
iNaH2zqWlIShVTKEc8ACo1HUTP2slfQ7Q7GIR3sGU2Z+fRD3GXwwAoyo5Mh1aEA
MQA=
-----END CERTIFICATE-----`
	etcdCACertValue = `-----BEGIN CERTIFICATE-----
MIIC9DCCAdygAwIBAgIUE/sKmkwLzAXSd3edTjVgkt3WsFcwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAxMHZXRjZC1jYTAeFw0yMDAyMTMxODQ5MDBaFw0zMDAyMTAx
ODQ5MDBaMBIxEDAOBgNVBAMTB2V0Y2QtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDH7xNFOmiMjJWFyhkMrY8AvNjozmgm1EBCWPxIz9ovJn4X/H5f
nNYDRq3T9+UfeO5975J6f2cGtKsHsUqSmNDDQOnPeEH7bARt/cZgiqhYwIKB5bIf
5ZfOVB0EljKffwAT9kkU4Sh0I1GNUvXl5CjJMvegYqaebYxtDwxoLwHJAwH2I5js
o104JQRwid09n1O37Oa9nz2+yNg/j/qYv1oVx08rGewRaH+L71OU5ZGxdr9Stn/f
vHr9jlfcVIIdyrJq2nIM6W0uCQGn3SxIiVuVKrE/MSI4wBXYh8onJlV4Tn/TjsQ9
GbKfvcFr7pz45SxeRTXw8VT39NU/wktxp9bRAgMBAAGjQjBAMA4GA1UdDwEB/wQE
AwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSwfgPlktHF4IwoJuXBTTwU
PBIDDjANBgkqhkiG9w0BAQsFAAOCAQEAMHzZdL6HS1WL/wYqcDEpD2OLyAXi0j7y
M28r0uLTbExPO7X3ulrtaSfKxCKyM846wsGySwazVU8W2nQcfyvK8XVZdT/j8fZL
9ANyAjj9BiSu/YDfFbSqRaSochRh1h6EuBXVLz0jvuiaHvj0E/sPaECHLdUbhQP8
MSmpehzr3NRfaQfF6c7yleCz9N7rP8gQlbpyk6EtjnXyE8UpwQVJ8Sp0OAZ66StR
20JExJI8nMSwhZXTLZFLxscGI/mLsbmWBtL+MZDrDw8K6fMNjWW7hETyYZXb0DDB
daNctu0/Ve1g56uPT0r1JJDTKS887tyCBrOoqGCjNYt9PRRqjGrWJQ==
-----END CERTIFICATE-----`
	etcdCertValue = `-----BEGIN CERTIFICATE-----
MIIEAzCCAuugAwIBAgIUTPM/Ax4Hyyom84Y//+Z/Qg56f7wwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAxMHZXRjZC1jYTAeFw0yMDAyMTMxOTIwMDBaFw0yMTAyMTIx
OTIwMDBaMDoxODA2BgNVBAMTL2lwLTE3Mi0yMC02My0xOC5hcC1ub3J0aGVhc3Qt
Mi5jb21wdXRlLmludGVybmFsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAsdcQvpzH9AHy8vtn3svtKf0veamxBw4kG9csRweGlTiI2jyjrP3zkj57D/ar
akjhriAcPtvXjF35eH7D0VZMQr4qhJ3X2SFMxnQXnWMzL3XepKJZ7/k4wnZfBo5y
kHAH8rJx+eTuyzMk7Sg9Fo+vfSp7She05Z7cIoPgYpiF/xPb7Dere5XXw6qfiD/C
21KhG+ULPhVLWMgeXO3n5YtIRUEJYD3o0t/to2OvPUxlIBFsALsp30r0U0JdoFMf
06hSUzAURy5uIPSwPctbqlVyCGq7DjwYpvuV8MKnxWCYkEjcQu9nvwc6ONhaWFdA
rFhofEOXctG5oP1S+67L7uKC6QIDAQABo4IBJzCCASMwDgYDVR0PAQH/BAQDAgWg
MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0G
A1UdDgQWBBQLmUjRf67kInZCSzO1HRLsf3O7TzAfBgNVHSMEGDAWgBSwfgPlktHF
4IwoJuXBTTwUPBIDDjCBowYDVR0RBIGbMIGYgi9pcC0xNzItMjAtNjMtMTguYXAt
bm9ydGhlYXN0LTIuY29tcHV0ZS5pbnRlcm5hbIIvaXAtMTcyLTIwLTYzLTE4LmFw
LW5vcnRoZWFzdC0yLmNvbXB1dGUuaW50ZXJuYWyCCWxvY2FsaG9zdIILZXRjZC1j
bGllbnSHBKwUPxKHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZIhvcNAQEL
BQADggEBAAxepic8nj2ytHQDmGZZn7FnXhvmOxi8ll4OXPlylPiP+XtIAYzC2eKp
J0yNHXhasqmU2uyOh0M2CNUni2nUR7CAYFW0/RyWc5reMUCRltYGP1bdEqYzeVzz
/n+yol3bPb3TMaLn4URMkCiNM6BJAIWU18B7m0nSMf6nDvLuDKFjFOD6z0/KITSR
3Cncw1v42msEAIhc/SLL4tPwPkcZbhUg5CZjFmtZhHRftnP0NY3xNi/Beo2qCTaH
zt5LZeD7CAwgq0zu+82Ptn5jKD7VXNNUfPVeq43Ndm7heMsGohcERRqtj98Rgg0F
lpK18pJyEqf2yLuX+bKUCKpqdDvoIU0=
-----END CERTIFICATE-----`
	etcdKeyValue = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsdcQvpzH9AHy8vtn3svtKf0veamxBw4kG9csRweGlTiI2jyj
rP3zkj57D/arakjhriAcPtvXjF35eH7D0VZMQr4qhJ3X2SFMxnQXnWMzL3XepKJZ
7/k4wnZfBo5ykHAH8rJx+eTuyzMk7Sg9Fo+vfSp7She05Z7cIoPgYpiF/xPb7Der
e5XXw6qfiD/C21KhG+ULPhVLWMgeXO3n5YtIRUEJYD3o0t/to2OvPUxlIBFsALsp
30r0U0JdoFMf06hSUzAURy5uIPSwPctbqlVyCGq7DjwYpvuV8MKnxWCYkEjcQu9n
vwc6ONhaWFdArFhofEOXctG5oP1S+67L7uKC6QIDAQABAoIBABM8kTodGV/iihYQ
bbbi1h+RnH4LhfOeavd7+fUg8kTX3a3Fm2rN+XfbPFKIuxf/FDJSlNuTyigLzj1j
cOkG7a7WhSDdNgjtmjFpQ1ip71J17IRgb1wO2D3osfSymd/XznRJKxz9z3q5aIgi
ryDun+vpGXb1Q4MHAQbWvwHLP8tMe2nqgoSd4CxxL3drbCZQ7AqQL2IlxMjYs+bO
sjZQixJORnfJFZdDJRqS+P2sJITEZkeCfMuP3CW2ylePPOEyak2iyoeLxPZ1S44g
yL4Uarzu/RV4NyVUODFLZRNjyp17lg+SH4gjQz8BlrgClYOCBKPIjl7LyWX/5j+n
JzuSlkUCgYEAy2mI2XBHqsRbqIxwVM7/I62lgojKdOaxkms6Poe6BciMtcJ9w8PI
ludsAv7H1gm4udHhlaK+kLxCQ6xwXX9vt0okG3mynFcOy9Vi376KQnB1qSxGYYLW
jOc3vl+lt4BfemGZUgcPB6g/8BpjsXtx3OTlW6tlC7HhbJKyUxHNj7sCgYEA39EV
3ojRRVyS0rR+FZ5ck82BFGojHdqB2GlbOM3YuJRq6yQj+0z2B7HRMV3uQLDWeTN7
D+tYJSGHhTrKFBuM36WXEghxuc1Ig68RUE1mQjcBdKtY5MR4U9fnM4su6GIPURUU
Gp7XwTwZPMqGjbUEJuraRg7r0uJ1fFQQDJKf86sCgYB5y5oWYAV5eZNMS7LjBQJ+
EXZdv5xB/PPsMOoyEMDQv7GJD4iQVEViHfVtobJ0NWP3V3VUTJsAPMkMjk7FnQ1+
WRVfojHRLMt+PymxwPw2JfI9tnX54wamXbfh9JFcW7BPrerI09MrCZInKRXyanDW
C/RNPEYHh53rjbbayHkmCwKBgDbfyIDbApQC8mx+nDsorIIAbJlYvGthW1x32EnB
DlWS7fPg1IGUiO2yBxwXb4ak1LC6kn2AsgfIhLWBiHINnyhmLPfa4icv0YuXrKMH
lv69BbpZGF5eXTIRSTo18bY/9IlopZkxQKy702Q4M20i6HWyNvneRqtZonxtD9JF
ULopAoGAbwgzZG9ntIPZGZwAiTmUj7sR10oGbAq3lY2jbq35sQ9yLgCwvNJPRQlZ
PXfxCJ/ok5riuRMqQk5ckfKHdTQd3LS8yBDWtO4QghcVylXyaCRBt/D8ixGvWkfo
Txamon6zeVAtPfChqBEHSbftWr3vX26IXR4IKbM7Nz/02c4fAPM=
-----END RSA PRIVATE KEY-----`
)

var _ = Describe("RulesAPIToBackend", func() {
	It("should raise an error if specified certs files don't exist", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "/fake/path",
			EtcdCertFile:   "/fake/path",
			EtcdKeyFile:    "/fake/path",
			EtcdEndpoints:  "http://fake:2379",
		})
		Expect(err).To(HaveOccurred())
	})

	It("shouldn't create a client with empty certs", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "/dev/null",
			EtcdCertFile:   "/dev/null",
			EtcdKeyFile:    "/dev/null",

			EtcdCACert: "",
			EtcdCert:   "",
			EtcdKey:    "",

			EtcdEndpoints: "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	It("should raise an error if conflicting endpoint discovery configuration provided", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdEndpoints:    "https://127.0.0.1:5007",
			EtcdDiscoverySrv: "example.com",
		})
		Expect(err).To(HaveOccurred())
	})

	It("[Datastore] should raise an error for providing only inline Key and not Certificate", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACert:    "",
			EtcdCert:      "",
			EtcdKey:       etcdKeyValue,
			EtcdEndpoints: "https://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	It("[Datastore] should raise an error for providing only inline Certificate and not Key", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACert: "",
			EtcdCert:   etcdCertValue,
			EtcdKey:    "",

			EtcdEndpoints: "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	It("[Datastore] should raise an error for providing a mix of inline Certificate-Key and Certificate-Key Files as parameters", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "/fake/path",

			EtcdCACert: "",
			EtcdCert:   etcdCertValue,
			EtcdKey:    etcdKeyValue,

			EtcdEndpoints: "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	It("[Datastore] should raise an error for not being able to decode inline CA certificate", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "",

			EtcdCACert: etcdCACertWrongFormatValue,
			EtcdCert:   etcdCertValue,
			EtcdKey:    etcdKeyValue,

			EtcdEndpoints: "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})
	It("[Datastore] should raise an error for providing a mix of all inline Certificate-Key and Certificate-Key Files as parameters", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "/fake/path",
			EtcdCertFile:   "/fake/path",
			EtcdKeyFile:    "/fake/path",

			EtcdCACert: etcdCACertValue,
			EtcdCert:   etcdCertValue,
			EtcdKey:    etcdKeyValue,

			EtcdEndpoints: "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	// CASEY: This test has been flaking in private without a discernable cause. Given we don't even support etcdv3 in Calico Enterprise,
	// it seems reasonable to comment this test out for now.
	//
	// It("[Datastore] should not raise any error while creating client object with inline Certificate-Key values as parameters", func() {
	// 	_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
	// 		EtcdCACert: etcdCACertValue,
	// 		EtcdCert:   etcdCertValue,
	// 		EtcdKey:    etcdKeyValue,

	// 		EtcdEndpoints: "https://127.0.0.1:5007",
	// 	})
	// 	Expect(err).ToNot(HaveOccurred())
	// })

	It("[Datastore] should discover etcd via SRV records", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdDiscoverySrv: "etcd.local",
		})
		Expect(err).ToNot(HaveOccurred())
	})

	It("[Datastore] should fail if SRV discovery finds no records", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdDiscoverySrv: "fake.local",
		})
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("failed to discover etcd endpoints through SRV discovery")))
	})
})
