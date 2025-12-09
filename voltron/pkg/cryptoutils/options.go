package cryptoutils

import (
	"crypto/rsa"
	"crypto/x509"
)

type Option func(*certConfig)

func WithRSAPrivateKey(privateKey *rsa.PrivateKey) Option {
	return func(c *certConfig) {
		c.privateKey = privateKey
	}
}

func WithParent(parent *x509.Certificate) Option {
	return func(c *certConfig) {
		c.parent = parent
	}
}

func WithDNSNames(dnsNames ...string) Option {
	return func(c *certConfig) {
		c.template.DNSNames = append(c.template.DNSNames, dnsNames...)
	}
}

func withServerUsage() Option {
	return func(cfg *certConfig) {
		cfg.template.KeyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		cfg.template.ExtKeyUsage = append(cfg.template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
}

func withClientUsage() Option {
	return func(cfg *certConfig) {
		cfg.template.KeyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		cfg.template.ExtKeyUsage = append(cfg.template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
}

func withCAUsage() Option {
	return func(cfg *certConfig) {
		cfg.template.BasicConstraintsValid = true
		cfg.template.IsCA = true
		cfg.template.KeyUsage |= x509.KeyUsageCertSign
	}
}
