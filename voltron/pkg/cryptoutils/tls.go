package cryptoutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	mathrand "math/rand"

	"github.com/projectcalico/calico/lib/std/time"
)

const (
	defaultKeySizeBits = 2048

	blockTypePrivateKey = "RSA PRIVATE KEY"
	blockTypeCert       = "CERTIFICATE"
)

type certConfig struct {
	privateKey *rsa.PrivateKey
	parent     *x509.Certificate
	template   *x509.Certificate
}

// KeyPair contains a certificate and the private key used to generate that certificate. This type can be used to easily
// get the X509Certificate or a TLS certificate.
type KeyPair struct {
	privateKey *rsa.PrivateKey
	certBytes  []byte
}

func (kp KeyPair) X509Certificate() (*x509.Certificate, error) {
	return x509.ParseCertificate(kp.certBytes)
}

func (kp KeyPair) TLSCertificate() (tls.Certificate, error) {
	keyBytes := x509.MarshalPKCS1PrivateKey(kp.privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: blockTypePrivateKey, Bytes: keyBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: blockTypeCert, Bytes: kp.certBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func CreateCertificateAuthority(opts ...Option) (*x509.Certificate, error) {
	opts = append(opts, withCAUsage())
	kp, err := createCertificate(opts...)
	if err != nil {
		return nil, err
	}
	return kp.X509Certificate()
}

func CreateServerTLSCertificate(opts ...Option) (tls.Certificate, error) {
	opts = append(opts, withServerUsage())
	kp, err := createCertificate(opts...)
	if err != nil {
		return tls.Certificate{}, err
	}

	return kp.TLSCertificate()
}

func CreateClientTLSCertificate(opts ...Option) (tls.Certificate, error) {
	opts = append(opts, withClientUsage())

	kp, err := createCertificate(opts...)
	if err != nil {
		return tls.Certificate{}, err
	}

	return kp.TLSCertificate()
}

func createCertificate(opts ...Option) (*KeyPair, error) {
	cfg := certConfig{}

	cfg.template = &x509.Certificate{
		SerialNumber:          big.NewInt(randomSerialNumber()),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.privateKey == nil {
		privateKey, err := rsa.GenerateKey(rand.Reader, defaultKeySizeBits)
		if err != nil {
			return nil, err
		}

		cfg.privateKey = privateKey
	}

	if cfg.parent == nil {
		cfg.parent = cfg.template
	}

	bytes, err := x509.CreateCertificate(rand.Reader, cfg.template, cfg.parent, cfg.privateKey.Public(), cfg.privateKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		privateKey: cfg.privateKey,
		certBytes:  bytes,
	}, nil
}

// randomSerialNumber returns a random int64 serial number based on
// time.Now. It is defined separately from the generator interface so
// that the caller doesn't have to worry about an input template or
// error - these are unnecessary when creating a random serial.
func randomSerialNumber() int64 {
	r := mathrand.New(mathrand.NewSource(time.Now().UTC().UnixNano()))
	return r.Int63()
}

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, defaultKeySizeBits)
}
