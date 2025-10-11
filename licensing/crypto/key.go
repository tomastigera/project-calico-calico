package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	// DefaultKeyLength is the default private key length.
	DefaultKeyLength = 2048

	// PrivKeyType is the const string to mark the beginning
	// and end of a PEM encoded private key.
	PrivKeyType = "RSA PRIVATE KEY"

	// PubKeyType is the const string to mark the beginning
	// and end of a PEM encoded public key.
	PubKeyType = "RSA PUBLIC KEY"
)

var (
	// RandomGen is a crypto pseudo-random generator.
	RandomGen = rand.Reader
)

// GenerateKeyPair generates a public private key pair
// with the default key length of 1024 bit.
func GenerateKeyPair() (*rsa.PrivateKey, error) {
	// Generate and return a 1024-bit private-key and error.
	// Public key is a field of the private key.
	return rsa.GenerateKey(RandomGen, DefaultKeyLength)
}

// ExportRsaPrivateKeyAsPemStr converts RSA private key to PEM encoded string.
// This is generally used for storing the private key onto the filesystem.
func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privBytes := x509.MarshalPKCS1PrivateKey(privkey)

	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  PrivKeyType,
			Bytes: privBytes,
		},
	)

	return string(privPem)
}

// SavePrivateKeyAsPEM PEM encodes the provided rsa private key and saves it as a file.
func SavePrivateKeyAsPEM(priv *rsa.PrivateKey, filePath string) error {
	keyPEMFile, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = keyPEMFile.Close() }()

	if err := pem.Encode(keyPEMFile, &pem.Block{Type: PrivKeyType, Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}
	return nil
}

// ParseRsaPrivateKeyFromPemStr PEM encoded private key string to rsa.PrivateKey struct.
// This is generally used for reading a private key stored on the filesystem
func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ReadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %s", err)
	}

	return ParseRsaPrivateKeyFromPemStr(string(data))
}

// ExportRsaPublicKeyAsPemStr converts RSA public key to PEM encoded string.
// This is generally used for storing the public key onto the filesystem.
func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", fmt.Errorf("error marshaling public key: %s", err)
	}

	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  PubKeyType,
			Bytes: pubBytes,
		},
	)

	return string(pubPem), nil
}

// SavePublicKeyAsPEM PEM encodes the provided rsa private key and saves it as a file.
func SavePublicKeyAsPEM(pub *rsa.PublicKey, filePath string) error {
	keyPEMFile, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = keyPEMFile.Close() }()

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("error marshaling public key: %s", err)
	}

	if err := pem.Encode(keyPEMFile, &pem.Block{Type: PrivKeyType, Bytes: pubBytes}); err != nil {
		return err
	}
	return nil
}

// ParseRsaPublicKeyFromPemStr PEM encoded public key string to rsa.PublicKey struct.
// This is generally used for reading a public key stored on the filesystem
func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if pk, ok := pub.(*rsa.PublicKey); ok {
		return pk, nil
	}

	return nil, fmt.Errorf("key type is not RSA")
}
