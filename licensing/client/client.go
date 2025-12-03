package client

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/licensing/client/features"
	cryptolicensing "github.com/projectcalico/calico/licensing/crypto"
)

var (
	// root20180405 is the original root certificate (that has since expired).
	//go:embed root-certificates/root20180405.pem
	root20180405 []byte

	// root20241231 is a new root certificate that is used to sign licenses.
	//go:embed root-certificates/root20241231.pem
	root20241231 []byte

	// rootCerts is a list of trusted license signers.
	rootCerts []*x509.Certificate

	// Symmetric key to encrypt and decrypt the JWT.
	// It has to be 32-byte long UTF-8 string.
	symKey = []byte("i༒2ஹ阳0?!pᄚ3-)0$߷५ૠm")
)

// ResourceName is the name of the LicenseKey, which is a singleton resource.
const ResourceName = "default"

func init() {

	cert20180405, err := cryptolicensing.LoadCertFromPEM(root20180405)
	if err != nil {
		panic(err)
	}

	cert20241231, err := cryptolicensing.LoadCertFromPEM(root20241231)
	if err != nil {
		panic(err)
	}

	rootCerts = append(rootCerts, cert20180405, cert20241231)
}

// LicenseClaims contains all the license control fields.
// This includes custom JWT fields and the default ones.
type LicenseClaims struct {
	// LicenseID is a unique UUID assigned for each customer license.
	LicenseID string `json:"license_id"`

	// Node count is not enforced in v2.1. If it’s not set then it means it’s unlimited nodes
	// (site license)
	Nodes *int `json:"nodes" validate:"required"`

	// Customer is the name of the customer, so we can use the same name for multiple
	// licenses for a customer, but they'd have different LicenseID.
	Customer string `json:"name" validate:"required"`

	// ClusterGUID is an optional field that can be filled out to limit the use of license only on
	// a cluster with this specific ClusterGUID. This can also be used when client sends
	// license call-home checkins. Not used for v2.1.
	ClusterGUID string `json:"cluster_guid"`

	// Version of the license claims. Could be useful in future if/when we add new fields in
	// the license. This is different from the LicenseKey APIVersion field.
	Version string `json:"version"`

	// Features field is for future use.
	// We will default this with `[ “cnx”, “all”]` for v2.1 and Enterprise package
	// Cloud licenses will have one of the following values: ["cloud", "community", ...],
	// ["cloud", "starter", ...] or [ "cloud", "pro", ...]. Individual features are appended after the license
	// package.
	Features []string `json:"features"`

	// GracePeriod is how many days the cluster will keep working even after
	// the license expires. This defaults to 90 days.
	// Currently not enforced.
	GracePeriod int `json:"grace_period"`

	// CheckinInterval is how frequently we call home (in hours).
	// Not used for v2.1. Defaults to once a week. If it’s not set then it’s an offline license.
	CheckinInterval *int `json:"checkin_interval"`

	// Include the default JWT claims.
	// Built-in field `Expiry` is used to set the license expiration date.
	// Built-in IssuedAt is set to the time of license generation (UTC), not used in v2.1.
	// Precision is day, and expires end of the day (on customer local timezone).
	jwt.Claims
}

// Decode takes a license resource and decodes the claims
// It returns the decoded LicenseClaims and an error. A non-nil error means the license is corrupted.
func Decode(lic api.LicenseKey) (LicenseClaims, error) {
	tok, err := jwt.ParseSignedAndEncrypted(
		lic.Spec.Token,
		[]jose.KeyAlgorithm{jose.A128GCMKW},
		[]jose.ContentEncryption{jose.A128GCM},
		[]jose.SignatureAlgorithm{jose.PS512})
	if err != nil {
		return LicenseClaims{}, fmt.Errorf("error parsing license: %s", err)
	}

	nested, err := tok.Decrypt(symKey)
	if err != nil {
		return LicenseClaims{}, fmt.Errorf("error decrypting license: %s", err)
	}

	cert, err := cryptolicensing.LoadCertFromPEM([]byte(lic.Spec.Certificate))
	if err != nil {
		return LicenseClaims{}, fmt.Errorf("error loading license certificate: %s", err)
	}

	// We only check if the certificate was signed by Tigera root certificate.
	// Verify() also checks if the certificate is expired before checking if it was signed by the root cert,
	// which is not what we want to do for v2.1 behavior.
	for _, root := range rootCerts {
		err = cert.CheckSignatureFrom(root)
		if err == nil {
			break
		}
	}
	if err != nil {
		return LicenseClaims{}, fmt.Errorf("error checking license signature: %s", err)
	}

	// For v2.1 we are not checking certificate expiration, verifying the cert chain also checks if the leaf certificate
	// is expired, and since we don't really stop any features from working after the license expires (at least in v2.1)
	// We have to deal with a case where the certificate is expired but license is still "valid" - i.e. within the grace period
	// which could be max int.
	// We can uncomment this when we actually enforce license and stop the features from running.
	//if _, err := cert.Verify(opts); err != nil {
	//	return LicenseClaims{}, fmt.Errorf("failed to verify the certificate: %s", err)
	//}

	var claims LicenseClaims
	if err := nested.Claims(cert.PublicKey, &claims); err != nil {
		return LicenseClaims{}, fmt.Errorf("error parsing license claims: %s", err)
	}

	return claims, nil
}

// IsOpenSourceAPI determines is a calico API is defined as an open
// source API
func IsOpenSourceAPI(resourceGroupVersionKind string) bool {
	return features.OpenSourceAPIs[resourceGroupVersionKind]
}

// IsManagementAPI determines is a calico API is defined as an api used to managed/access
// resources on a calico install
func IsManagementAPI(resourceGroupVersionKind string) bool {
	return features.ManagementAPIs[resourceGroupVersionKind]
}

// ErrExpiredButWithinGracePeriod indicates the license has expired but is within the grace period.
type ErrExpiredButWithinGracePeriod struct {
	Err error
}

func (e ErrExpiredButWithinGracePeriod) Error() string {
	return "license expired"
}

type LicenseStatus int

const (
	Unknown LicenseStatus = iota
	Valid
	InGracePeriod
	Expired
	NoLicenseLoaded
)

func (s LicenseStatus) String() string {
	switch s {
	case Valid:
		return "valid"
	case InGracePeriod:
		return "in-grace-period"
	case Expired:
		return "expired"
	case NoLicenseLoaded:
		return "no-license-loaded"
	default:
		return "unknown"
	}
}

// Validate checks if the license is expired.
func (c *LicenseClaims) Validate() LicenseStatus {
	return c.ValidateAtTime(time.Now())
}

// Validate checks if the license is expired.
func (c *LicenseClaims) ValidateAtTime(t time.Time) LicenseStatus {
	if c == nil {
		return NoLicenseLoaded
	}

	expiryTime := c.Expiry.Time()
	if expiryTime.After(t) {
		return Valid
	}

	gracePeriodExpiryTime := expiryTime.Add(time.Duration(c.GracePeriod) * time.Hour * 24)
	if gracePeriodExpiryTime.After(t) {
		return InGracePeriod
	}

	return Expired
}

// ValidateFeature returns true if the feature is enabled, false if it is not.
// False is returned if the license is invalid in any of the following ways:
// - there isn't a license
// - the license has expired and is no longer in its grace period.
func (c *LicenseClaims) ValidateFeature(feature string) bool {
	return c.ValidateFeatureAtTime(time.Now(), feature)
}

// ValidateFeature returns true if the feature is enabled, false if it is not.
// False is returned if the license is invalid in any of the following ways:
// - there isn't a license
// - the license has expired and is no longer in its grace period.
func (c *LicenseClaims) ValidateFeatureAtTime(t time.Time, feature string) bool {
	switch c.ValidateAtTime(t) {
	case NoLicenseLoaded, Expired:
		return false
	}

	if len(c.Features) == 0 {
		return false
	}

	for _, f := range c.Features {
		if f == features.All {
			return true
		}
		if f == feature {
			return true
		}
	}

	return false
}

// ValidateAPIUsage checks if the API can be accessed.
func (c *LicenseClaims) ValidateAPIUsage(gvk string) bool {
	if IsOpenSourceAPI(gvk) || IsManagementAPI(gvk) {
		return true
	}

	feature, ok := features.EnterpriseAPIsToFeatureName[gvk]
	if ok {
		return c.ValidateFeature(feature)
	}

	return false
}
