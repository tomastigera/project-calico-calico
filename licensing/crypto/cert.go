package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"time"
)

const (
	CertCommonName      = "tigera.io"
	CertEmailAddress    = "licensing@tigera.io"
	CertLicensingDomain = "licensing.tigera.io"
	CertOrgName         = "Tigera Inc."
	CertTigeraDomain    = "https://tigera.io"
	CertType            = "CERTIFICATE"

	randSerialSeed = 9223372036854775807
)

// Generatex509Cert generates an x.509 certificate with start and expiration time
// provided and the RSA private key provided and returns cert DER bytes and error.
// This function also populates Tigera org default information.
func Generatex509Cert(start, exp time.Time, priv *rsa.PrivateKey) ([]byte, error) {
	template := x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(rand.Int63n(randSerialSeed)),
		Subject: pkix.Name{
			CommonName:   CertCommonName,
			Organization: []string{CertOrgName},
		},

		NotBefore: start,
		NotAfter:  exp,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,

		BasicConstraintsValid: true,
		IsCA:                  true,
		EmailAddresses:        []string{CertEmailAddress},
		DNSNames:              []string{CertTigeraDomain},
	}

	return x509.CreateCertificate(RandomGen, &template, &template, &priv.PublicKey, priv)
}

func Generatex509CertChain(start, exp time.Time, root *x509.Certificate, priv *rsa.PrivateKey) ([]byte, error) {
	template := x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(rand.Int63n(randSerialSeed)),
		Subject: pkix.Name{
			CommonName:   CertCommonName,
			Organization: []string{"tigera-leaf"},
		},

		NotBefore: start,
		NotAfter:  exp,

		//	SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,

		BasicConstraintsValid: true,
		IsCA:                  false,
		EmailAddresses:        []string{CertEmailAddress},
		DNSNames:              []string{CertTigeraDomain},
	}

	return x509.CreateCertificate(RandomGen, &template, root, &priv.PublicKey, priv)
}

func SaveCertToFile(derBytes []byte, filePath string) error {
	certCerFile, err := os.Create(filePath)
	if err != nil {
		return err
	}

	defer func() { _ = certCerFile.Close() }()

	if _, err = certCerFile.Write(derBytes); err != nil {
		return err
	}
	return nil
}

func SaveCertAsPEM(derBytes []byte, filePath string) error {
	certPEMFile, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = certPEMFile.Close() }()

	if err := pem.Encode(certPEMFile,
		&pem.Block{
			Type:  CertType,
			Bytes: derBytes,
		}); err != nil {
		return err
	}
	return nil
}

func ReadCertPemFromFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("error reading file: %s", err)
	}

	return string(data)
}

// ExportCertAsPemStr converts x.509 cert DER bytes to PEM encoded string.
func ExportCertAsPemStr(derBytes []byte) string {
	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  CertType,
			Bytes: derBytes,
		},
	)

	return string(pubPem)
}

func LoadCertFromPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
