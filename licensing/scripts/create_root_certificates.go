package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// Path to the root certificate and private key files (in PEM format)
const (
	rootCertFileLocation         = "ca.crt"
	rootKeyFileLocation          = "ca.key"
	intermediateCertFileLocation = "intermediate_ca.crt"
	intermediateKeyFileLocation  = "intermediate_ca.key"
)

func main() {
	createCertificate("Tigera Self-Signed Root Certificate Authority", rootKeyFileLocation, rootCertFileLocation, rootKeyFileLocation, rootCertFileLocation)
	createCertificate("Tigera Intermediate Certificate Authority", intermediateKeyFileLocation, intermediateCertFileLocation, rootKeyFileLocation, rootCertFileLocation)
}

func createCertificate(cn, keyFilePath, certFilePath, rootKeyFilePath, rootCertFilePath string) {
	fmt.Printf("Generating certificates for cn: \"%s\" key: \"%s\", certificate: \"%s\"...\n", cn, keyFilePath, certFilePath)

	_, err := os.Stat(keyFilePath)
	if err == nil {
		fmt.Println("File has already been created, skipping.")
		return
	}
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(130), nil))
	if err != nil {
		fmt.Println("Error generating serial number:", err)
		return
	}
	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Security <sirt@tigera.io>"},
			Country:      []string{"US"},
			Province:     []string{"California"},
			Locality:     []string{"San Francisco"},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("Error creating root certificate:", err)
		return
	}

	var caDER []byte
	if keyFilePath == rootKeyFilePath {
		// We are creating the root and self-signing it.
		caTemplate.NotAfter = caTemplate.NotBefore.AddDate(100, 0, 0)

		caDER, err = x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
		if err != nil {
			fmt.Println("Error creating root certificate:", err)
			return
		}
	} else {
		// We are creating an intermediate from the root.
		caTemplate.NotAfter = caTemplate.NotBefore.AddDate(1, 0, 0)

		// Read the root certificate and private key
		rootCert, rootKey, err := readPEMFile(rootCertFilePath, rootKeyFilePath)
		if err != nil {
			fmt.Println("Error reading root certificate and key:", err)
			return
		}
		// Sign the intermediate certificate with the root certificate and its private key
		caDER, err = x509.CreateCertificate(rand.Reader, caTemplate, rootCert, &caPrivateKey.PublicKey, rootKey)
		if err != nil {
			fmt.Println("Error creating intermediate certificate:", err)
			return
		}
	}

	// Write the intermediate certificate to a PEM file
	certFile, err := os.Create(certFilePath)
	if err != nil {
		fmt.Println("Error creating certificate file:", err)
		return
	}
	defer func() { _ = certFile.Close() }()

	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	})
	if err != nil {
		fmt.Println("Error encoding certificate:", err)
		return
	}

	// Write the intermediate private key to a PEM file
	keyFile, err := os.Create(keyFilePath)
	if err != nil {
		fmt.Println("Error creating private key file:", err)
		return
	}
	defer func() { _ = keyFile.Close() }()

	privKeyBytes := x509.MarshalPKCS1PrivateKey(caPrivateKey)
	err = pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	if err != nil {
		fmt.Println("Error encoding private key:", err)
		return
	}

	fmt.Println("Success!")
}

// Function to read a PEM encoded file and return the private key and certificate
func readPEMFile(certFile, keyFile string) (*x509.Certificate, any, error) {
	// Read certificate PEM file
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read cert file: %v", err)
	}

	// Decode certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Read private key PEM file
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file: %v", err)
	}

	// Decode the private key
	block, _ = pem.Decode(keyData)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse key PEM")
	}

	// Parse the private key (assuming it's an RSA key here, could be ECDSA or other types)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Return certificate and private key
	return cert, privKey, nil
}
