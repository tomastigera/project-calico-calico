package datastore

import (
	"strings"
	"time"

	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/licensing/client"
)

type LicenseInfo struct {
	UUID     string
	Expiry   time.Time
	Nodes    *int
	Features string
	JWT      string
	Cert     string
}

func (db *DB) GetLicensesByCompany(companyID int64) ([]*LicenseInfo, error) {
	rows, err := db.Query("SELECT license_uuid, expiry, nodes, features, jwt, certificate FROM licenses WHERE company_id = ?", companyID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	licenses := make([]*LicenseInfo, 0)
	for rows.Next() {
		lic := &LicenseInfo{}
		err := rows.Scan(&lic.UUID, &lic.Expiry, &lic.Nodes, &lic.Features, &lic.JWT, &lic.Cert)
		if err != nil {
			return nil, err
		}
		licenses = append(licenses, lic)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return licenses, nil
}

func (db *DB) GetLicenseByUUID(uuid string) (*LicenseInfo, error) {
	lic := &LicenseInfo{}
	row := db.QueryRow("SELECT expiry, nodes, features, jwt, certificate FROM licenses WHERE license_uuid = ?", uuid)
	err := row.Scan(&lic.Expiry, &lic.Nodes, &lic.Features, &lic.JWT, &lic.Cert)
	if err != nil {
		return nil, err
	}
	lic.UUID = uuid
	return lic, nil
}

// CreateLicense saves a license in the database; returning the LicenseID or an error.
func (db *DB) CreateLicense(license *api.LicenseKey, companyID int64, claims *client.LicenseClaims) (int64, error) {
	// Leave the following fields unset since they're not implemented yet:
	// - cluster_guid
	res, err := db.Exec("INSERT INTO licenses "+
		"(license_uuid, nodes, company_id, version, features, grace_period, checkin_int, expiry, issued_at, jwt, certificate) "+
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		claims.LicenseID,
		claims.Nodes,
		companyID,
		claims.Version,
		strings.Join(claims.Features, "|"),
		claims.GracePeriod,
		claims.CheckinInterval,
		claims.Expiry.Time(),
		claims.IssuedAt.Time(),
		license.Spec.Token,
		license.Spec.Certificate,
	)
	if err != nil {
		return -1, err
	}

	licenseID, err := res.LastInsertId()
	if err != nil {
		return -1, err
	}

	return licenseID, nil
}

// DeleteLicense removes a license from the database, given the ID returned by CreateLicense().
func (db *DB) DeleteLicense(licenseID int64) error {
	_, err := db.Exec("DELETE FROM licenses WHERE id = ?", licenseID)
	if err != nil {
		return err
	}

	return nil
}
