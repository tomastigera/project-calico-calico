// Copyright (c) 2019-2020, 2022 Tigera, Inc. All rights reserved.

// Package test provides utilities for writing tests
package test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/projectcalico/calico/voltron/internal/pkg/utils"
)

const pubRSA = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAutvmpHMbizCMfqbA5BmbpkNDZofdMXsXfL+3zas5SIkfaeaIK9BV
A5RPmYSO1wZstdbjdzq+zRw/Ot1SCZz/RcQKFCI3QYllgvcsh/x0RT0eGNYUUHQ1
jCGHPoMjaEeeIXVz7yr2xRnlCbHWvnmgEC8cuMkunSwsY3pZfAmURDMAEN/uA2HK
Y5dKcJ4VJ8XIpd4gyjyT3aRQk+kHvKkoippShRW1jF/j7tF5sjKW4w9bOhY9vC9l
UrfLZqwU/rkCTTBiorFn/de9/l7lt4AGA6KAYBe6aNV7MmKOUy/BDQKstU1B1QNi
c5J88YcvVRHr3lrMldlFqeCd6IHj61K1AQIDAQAB
-----END RSA PUBLIC KEY-----
`

// PrivateRSA is the private key used to sign the certificates
const PrivateRSA = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAutvmpHMbizCMfqbA5BmbpkNDZofdMXsXfL+3zas5SIkfaeaI
K9BVA5RPmYSO1wZstdbjdzq+zRw/Ot1SCZz/RcQKFCI3QYllgvcsh/x0RT0eGNYU
UHQ1jCGHPoMjaEeeIXVz7yr2xRnlCbHWvnmgEC8cuMkunSwsY3pZfAmURDMAEN/u
A2HKY5dKcJ4VJ8XIpd4gyjyT3aRQk+kHvKkoippShRW1jF/j7tF5sjKW4w9bOhY9
vC9lUrfLZqwU/rkCTTBiorFn/de9/l7lt4AGA6KAYBe6aNV7MmKOUy/BDQKstU1B
1QNic5J88YcvVRHr3lrMldlFqeCd6IHj61K1AQIDAQABAoIBAGrrgSIAK3aNpRaj
XCQo8wND4cE9ZLf3cw0Stp2cp/51V+BE5Q4M+1g8+P8i9ojbSEEUYLvMhXjf/N41
3cdaakcFUa8LlQqPD+LMhFKbhfxIaHxVovIWTL2OQdDnQM9ei4Ehr+DeeK13j7Lo
a7Q56/jWvFyP4XhV2mBhlep/oLMUcSO2Nj4KSjscMeg4ED4VPM0N8iQ6eaWNe/+6
aciRdHMmiNSR4SobK2+rskEZxkYKnzQeQT8dblggxN0uNlrhWEhaRFHnLYv41RMm
4ZrMkAMsTex2UUCYt5MUcaJfiafkRt1CbPVDkNKqKiHYTgn3pEIplEOWp7DDlMzT
8kHue0ECgYEA5CR+51SMIC+hY2FfP1oTxnzk+WHHhDTIjlEKNkyuJRUkiFloisi6
zI5001qbP4ufE9gk/AFsbRR4yhLPufgZPwccupAVzFKnsJI7MwpMvtgsJEEfIg5h
oToOE32/oCDGn3AMmwl7ob1pz3C/Jo8QZIpXCVPOAzVx1d1QNHBWjM0CgYEA0azs
ON7yAeAH1gtvtgD+lX294GxUoqa1BwLY2t18Rr0CsTfrKyyHCx+mqj3XPjh+eEUm
tsGt4QWXQOlYANoPx8uIzCvCvga7EEMuA8QRiPsLo03h3UFmHXI6EcQJIK5RMhjC
3KVaG+2LMdvAJLhQWQfz/X7BC4SMc/2zEhlpyQUCgYAwdfQi7VmqiJOOiaNy0I58
zhDRTEzWL2QenuY9bIJdTCVrdRp4yHSteOEl+AwcLmtHCtWoViES9pNF0UMgrKuo
MLmQg4St1yzZm+ZJTDnLHB4cQVz8nfNtDOjqiP6IZA3s1h9HW3dQfuyX7Modxavk
v2IHkC6ljde1ZwJfcTFhTQKBgCgOSPJ0ZPdGvTh+5tB2UCxu4R9GksSf5GV6fcMS
HPPGmAUTEbIlx4awfT54oe4ZDNAdJdA0H+ulDcgwy8cd4XXhxDh9A68ZyhLJQrkl
c9QfYZHJByUloURu1fke4j+EDa7sXA2a6SP8tWLJAGQDchYQFuSOmoKAx/RAuzzx
7euhAoGAZ1yQgvj12oF2bXTUTC64OgpaikmSc5G9xtstA2V4KlxSOu2jS4j4gsov
Vmy/ivvlEE9JkNBLRMxur/WEhE7Udx2JbveDWqe+T5UaG6IdaeE2HNqjPw8fbhE/
Gbs6cLS+CkglnRCvTeWtkqf7SawqfH4eKPu6k6xO1yuL2ylbFp0=
-----END RSA PRIVATE KEY-----
`

func loadKeys() (any, any, error) {
	block, _ := pem.Decode([]byte(pubRSA))
	if block == nil {
		return nil, nil, errors.New("no block in public key")
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing public failed: %s", err)
	}

	block, _ = pem.Decode([]byte(PrivateRSA))
	if block == nil {
		return nil, nil, errors.New("no block in private key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing private failed: %s", err)
	}

	return pubKey, privKey, nil
}

func createX509Cert(clusterID string, isCA bool, parent *x509.Certificate) ([]byte, error) {
	templ := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: clusterID},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: isCA,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"voltron"},
	}
	if isCA {
		templ.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent = templ
	}
	pubKey, privKey, err := loadKeys()
	if err != nil {
		return nil, err
	}
	bytes, err := x509.CreateCertificate(rand.Reader, templ, parent, pubKey, privKey)

	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// CreateSelfSignedX509Cert creates a self-signed certificate using predefined
// keys that includes the given cluster ID
func CreateSelfSignedX509Cert(clusterID string, isCA bool) (*x509.Certificate, error) {
	bytes, _ := createX509Cert(clusterID, isCA, nil)
	return x509.ParseCertificate(bytes)
}

// CreateSelfSignedX509CertBinary creates a self-signed certificate using predefined
// keys that includes the given cluster ID
func CreateSelfSignedX509CertBinary(clusterID string, isCA bool) ([]byte, error) {
	return createX509Cert(clusterID, isCA, nil)
}

// CreateSignedX509Cert creates a cert signed by a parent cert using predefined
// keys that includes the given cluster ID
func CreateSignedX509Cert(clusterID string, parent *x509.Certificate) (*x509.Certificate, error) {
	bytes, _ := createX509Cert(clusterID, false, parent)
	return x509.ParseCertificate(bytes)
}

// CreateSelfSignedX509CertRandom returns a random self-signed X509 cert and its key
func CreateSelfSignedX509CertRandom() (*x509.Certificate, crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return nil, nil, fmt.Errorf("generating RSA key: %s", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1000000 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	bytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating X509 cert: %s", err)
	}

	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		// should never happen, we just generated the key
		return nil, nil, fmt.Errorf("parsing X509 cert: %s", err)
	}

	return cert, key, nil
}

// PemEncodeCert encde a cert as PEM
func PemEncodeCert(cert *x509.Certificate) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	return pem.EncodeToMemory(block)
}

// DataFlow sends a message from the io Reader to the io Writer. Returns the sent message.
func DataFlow(r io.Reader, w io.Writer, msg []byte) ([]byte, error) {
	if r == nil || w == nil {
		return nil, errors.New("invalid parameters")
	}
	var wg sync.WaitGroup

	errChan := make(chan error, 2)
	resChan := make(chan []byte, 1)
	defer close(errChan)
	defer close(resChan)

	// Writer sends the msg
	wg.Go(func() {

		buf := msg

		for len(buf) > 0 {
			n, err := w.Write(buf)
			if err != nil {
				errChan <- errors.WithMessage(err, "Failed to Write")
				return
			}
			buf = buf[n:]
		}
	})

	// Reader reads the message
	wg.Add(1)
	go func() {
		var res []byte
		defer wg.Done()

		for len(res) < len(msg) {
			data := make([]byte, 100)
			n, err := r.Read(data)
			if err != nil {
				errChan <- errors.WithMessage(err, "Failed to Read")
				return
			}
			res = append(res, data[:n]...)
		}

		resChan <- res
	}()

	wg.Wait()

	var err error
	var res []byte

	select {
	case err = <-errChan:
	case res = <-resChan:
	}

	return res, err
}

func GenerateTestCredentials(clusterName string, caCert *x509.Certificate, caKey crypto.Signer) (cert []byte, key []byte, fingerprint string, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: clusterName},
		DNSNames:     []string{"voltron"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1000000 * time.Hour), // XXX TBD
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	bytes, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, "", err
	}

	x509Cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, nil, "", err
	}

	var block1 = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}

	key = pem.EncodeToMemory(block1)

	var block2 = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x509Cert.Raw,
	}

	cert = pem.EncodeToMemory(block2)
	fingerprint = utils.GenerateFingerprint(x509Cert)

	return cert, key, fingerprint, nil

}

func CreateCACertificateTemplate(sans ...string) *x509.Certificate {
	certTemplate := DefaultCertificationTemplate()
	certTemplate.IsCA = true
	certTemplate.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	certTemplate.DNSNames = sans
	certTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	return certTemplate
}

func CreateServerCertificateTemplate(sans ...string) *x509.Certificate {
	certTemplate := DefaultCertificationTemplate()
	certTemplate.IsCA = false
	certTemplate.DNSNames = sans
	certTemplate.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	return certTemplate
}

func CreateClientCertificateTemplate(cn string, sans ...string) *x509.Certificate {
	certTemplate := DefaultCertificationTemplate()
	certTemplate.IsCA = false
	certTemplate.DNSNames = sans
	certTemplate.Subject = pkix.Name{CommonName: cn}
	certTemplate.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	return certTemplate
}

func DefaultCertificationTemplate() *x509.Certificate {
	now := time.Now()
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	return &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
}

func CreateCertPair(template *x509.Certificate, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	if parentCert == nil {
		parentCert = template
	}

	if parentKey == nil {
		parentKey = privKey
	}

	rootBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, privKey.Public(), parentKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(rootBytes)
	if err != nil {
		return nil, nil, err
	}

	return privKey, cert, nil
}

func CertToPemBytes(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func KeyToPemBytes(key *rsa.PrivateKey) []byte {
	privBytes := x509.MarshalPKCS1PrivateKey(key)

	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
}

func X509CertToTLSCert(cert *x509.Certificate, key *rsa.PrivateKey) (tls.Certificate, error) {
	return tls.X509KeyPair(CertToPemBytes(cert), KeyToPemBytes(key))
}
