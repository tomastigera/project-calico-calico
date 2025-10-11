package client

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	cryptolicensing "github.com/projectcalico/calico/licensing/crypto"
)

var (
	jwtType = jose.ContentType("JWT")
)

// GenerateLicenseFromClaims generates LicenseKey resource from LicenseClaims with the
// JWT that is encrypted and signed using the private key provided and includes the certificate
// at the path provided to this function.
func GenerateLicenseFromClaims(claims LicenseClaims, pkeyPath, certPath string) (*api.LicenseKey, error) {

	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.A128GCMKW,
			Key:       symKey,
		},
		(&jose.EncrypterOptions{}).WithType(jwtType).WithContentType(jwtType))
	if err != nil {
		return nil, fmt.Errorf("error generating claims: %s", err)
	}

	priv, err := cryptolicensing.ReadPrivateKeyFromFile(pkeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading private key: %s", err)
	}

	// Instantiate a signer using RSASSA-PSS (SHA512) with the given private key.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS512, Key: priv}, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating signer: %s", err)
	}

	raw, err := jwt.SignedAndEncrypted(signer, enc).Claims(claims).Serialize()
	if err != nil {
		return nil, fmt.Errorf("error signing the JWT: %s", err)
	}

	licX := api.NewLicenseKey()
	licX.Name = ResourceName
	licX.Spec.Token = raw
	licX.Spec.Certificate = cryptolicensing.ReadCertPemFromFile(certPath)

	return licX, nil
}
