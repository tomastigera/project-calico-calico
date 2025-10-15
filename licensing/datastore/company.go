package datastore

import (
	"errors"
)

type Company struct {
	ID   int64
	Name string
}

func (db *DB) AllCompanies() ([]*Company, error) {
	rows, err := db.Query("SELECT id, name FROM companies")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	companies := make([]*Company, 0)
	for rows.Next() {
		cmp := &Company{}
		err := rows.Scan(&cmp.ID, &cmp.Name)
		if err != nil {
			return nil, err
		}
		companies = append(companies, cmp)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return companies, nil
}

func (db *DB) GetCompanyIdByName(name string) (int64, error) {
	var companyID int64
	row := db.QueryRow("SELECT id FROM companies WHERE name = ?", name)
	err := row.Scan(&companyID)
	if err != nil {
		return -1, err
	}
	return companyID, nil
}

func (db *DB) GetCompanyById(id int64) (*Company, error) {
	cmp := &Company{}
	row := db.QueryRow("SELECT id, name FROM companies WHERE id = ?", id)
	err := row.Scan(&cmp.ID, &cmp.Name)
	if err != nil {
		return nil, err
	}
	return cmp, nil
}

func (db *DB) CreateCompany(name string) (int64, error) {
	res, err := db.Exec("INSERT INTO companies (name) VALUES (?)", name)
	if err != nil {
		return -1, err
	}
	companyID, err := res.LastInsertId()
	if err != nil {
		return -1, err
	}
	return companyID, nil
}

func (db *DB) DeleteCompanyById(id int64) error {
	res, err := db.Exec("DELETE FROM companies WHERE id = ?", id)
	if err != nil {
		return err
	}
	if ra, err := res.RowsAffected(); err != nil || ra != 1 {
		return errors.New("unable to delete company by id")
	}
	return nil
}
