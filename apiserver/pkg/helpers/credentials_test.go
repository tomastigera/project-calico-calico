// Copyright (c) 2020 Tigera, Inc. All rights reserved.
package helpers

import (
	"crypto/x509"
	"os"
	"testing"

	. "github.com/onsi/gomega"
)

func TestDecodeCertAndKey(t *testing.T) {
	g := NewGomegaWithT(t)

	tests := []struct {
		description  string
		caCert       []byte
		key          []byte
		shouldError  bool
		errorMessage string
	}{
		{
			"nil cert and key returns an error",
			nil,
			nil,
			true,
			"provided key does not have PKCS#1 format",
		},
		{
			"nil cert returns an error",
			nil,
			[]byte(PKCS1Key),
			true,
			"provided cert is not in PEM format",
		},
		{
			"nil key returns an error",
			[]byte(CACert),
			nil,
			true,
			"provided key does not have PKCS#1 format",
		},
		{
			"empty cert and key returns an error",
			[]byte{},
			[]byte{},
			true,
			"provided key does not have PKCS#1 format",
		},
		{
			"malformed cert and key returns an error",
			[]byte("#23df"),
			[]byte("#23df"),
			true,
			"provided key does not have PKCS#1 format",
		},
		{
			"malformed cert returns an error",
			[]byte("#23df"),
			[]byte(PKCS1Key),
			true,
			"provided cert is not in PEM format",
		},
		{
			"PKCS8 format key returns an error",
			[]byte("#23df"),
			[]byte(PKCS8Key),
			true,
			"provided key does not have PKCS#1 format",
		},
		{
			"malformed cert and key returns an error",
			[]byte(CACert),
			[]byte(PKCS1Key),
			false,
			"",
		},
	}

	for _, test := range tests {
		t.Log(test.description)

		// Invoke DecodeCertAndKey
		genCert, genKey, err := DecodeCertAndKey(test.caCert, test.key)

		// Assert behaviour
		if test.shouldError {
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(Equal(test.errorMessage))
		} else {
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(genCert).NotTo(BeNil())
			g.Expect(genKey).NotTo(BeNil())
		}
	}
}

func TestReadCredentials(t *testing.T) {
	g := NewGomegaWithT(t)

	var err error
	var certFile *os.File
	var keyFile *os.File

	// Create a temporary file for cert
	certFile, err = createTemp("cert.*", "cert")
	defer func() { _ = os.Remove(certFile.Name()) }()
	g.Expect(err).NotTo(HaveOccurred())

	// Create a temporary file for key
	keyFile, err = createTemp("key.*", "key")
	defer func() { _ = os.Remove(keyFile.Name()) }()
	g.Expect(err).NotTo(HaveOccurred())

	type testFile struct {
		path string
		data []byte
	}

	negativeScenarios := []struct {
		description  string
		certFile     testFile
		keyFile      testFile
		shouldError  bool
		errorMessage string
	}{
		{
			"empty path returns an error",
			testFile{"", nil},
			testFile{"", nil},
			true,
			"path provided for credentials is empty",
		},
		{
			"bogus cert path returns an error",
			testFile{"bogus", nil},
			testFile{keyFile.Name(), []byte("key")},
			true,
			"open bogus: no such file or directory",
		},
		{
			"bogus key returns an error",
			testFile{certFile.Name(), []byte("cert")},
			testFile{"bogus", nil},
			true,
			"open bogus: no such file or directory",
		},
		{
			"read valid data",
			testFile{certFile.Name(), []byte("cert")},
			testFile{keyFile.Name(), []byte("key")},
			false,
			"",
		},
	}

	for _, test := range negativeScenarios {
		t.Log(test.description)

		// ReadCredentials
		cert, key, err := ReadCredentials(test.certFile.path, test.keyFile.path)

		// Assert behaviour
		if test.shouldError {
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(Equal(test.errorMessage))
		} else {
			g.Expect(cert).To(Equal(test.certFile.data))
			g.Expect(key).To(Equal(test.keyFile.data))
		}
	}
}

func createTemp(pattern string, data string) (*os.File, error) {
	file, err := os.CreateTemp("/tmp", pattern)
	if err != nil {
		return file, err
	}
	_, err = file.Write([]byte(data))
	return file, err
}

func TestGenerate(t *testing.T) {
	g := NewGomegaWithT(t)
	tests := []struct {
		description string
		caCertBytes []byte
		caKeyBytes  []byte
		clusterName string
		shouldError bool
	}{
		{
			"generate credentials for any cluster",
			[]byte(CACert),
			[]byte(PKCS1Key),
			"any",
			false,
		},
		{
			"missing cluster name return an error",
			[]byte(CACert),
			[]byte(PKCS1Key),
			"",
			true,
		},
	}

	for _, test := range tests {
		t.Log(test.description)

		// Transform ca cert and key into parameters needed by Generate
		var err error
		caCert, caKey, err := DecodeCertAndKey(test.caCertBytes, test.caKeyBytes)
		g.Expect(err).NotTo(HaveOccurred())

		// Invoke Generate
		cert, key, err := Generate(caCert, caKey, test.clusterName)

		// Assert behaviour
		if test.shouldError {
			g.Expect(err).To(HaveOccurred())
		} else {
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cert).NotTo(BeNil())
			g.Expect(key).NotTo(BeNil())
			g.Expect(cert.Subject.CommonName).To(Equal(test.clusterName))
			g.Expect(cert.IsCA).To(Equal(false))
			g.Expect(cert.ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}))
			g.Expect(key.Public()).To(Equal(cert.PublicKey))
		}
	}

	t.Run("Check that serial numbers differ for two cert", func(t *testing.T) {
		// Transform ca cert and key into parameters needed by Generate
		caCert, caKey, err := DecodeCertAndKey([]byte(CACert), []byte(PKCS1Key))
		g.Expect(err).NotTo(HaveOccurred())

		// Generate first cert
		cert1, _, err := Generate(caCert, caKey, "cluster-1")
		g.Expect(err).NotTo(HaveOccurred())
		// Generate second cert
		cert2, _, err := Generate(caCert, caKey, "cluster-2")
		g.Expect(err).NotTo(HaveOccurred())

		g.Expect(cert1.SerialNumber).NotTo(Equal(cert2.SerialNumber))
	})
}
