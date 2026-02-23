// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Package elasticsearch This package is responsible for the communicating with elasticsearch, mainly transferring objects to requests to send
// to elasticsearch and parsing the responses from elasticsearch
package elasticsearch

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	es7 "github.com/elastic/go-elasticsearch/v7"

	"github.com/projectcalico/calico/crypto/pkg/tls"
)

type client struct {
	*es7.Client
}

type Client interface {
	GetUsers() ([]User, error)
	UserExists(username string) (bool, error)
	UpdateUser(user User) error
	DeleteUser(user User) error
	CreateUser(user User) error
	CreateRoles(roles ...Role) error
	DeleteRole(role Role) error
	CreateRoleMapping(roleMapping RoleMapping) error
	GetRoleMappings() ([]RoleMapping, error)
	DeleteRoleMapping(name string) (bool, error)
	SetUserPassword(user User) error
}

// User represents an Elasticsearch user, which may or may not have roles attached to it
type User struct {
	Username string
	Password string
	FullName string
	Roles    []Role
	// Indicate whether this user will connect directly to Elastic or via a proxy
	DirectConnection bool
}

// RoleNames is a convenience function for getting the names of all the roles defined for this Elasticsearch user
func (u User) RoleNames() []string {
	// The Elasticsearch users API expects a string array in the "roles" field and will fail if it detects a null value
	// instead. Initialising the slice in this manner ensures that even in the case that there are no roles we still
	// send an empty array of strings rather than null.
	names := []string{}
	for _, role := range u.Roles {
		names = append(names, role.Name)
	}

	return names
}

// Role represents an Elasticsearch role that may be attached to a User
type Role struct {
	Name       string `json:"-"`
	Definition *RoleDefinition
}

type RoleDefinition struct {
	Cluster      []string      `json:"cluster"`
	Indices      []RoleIndex   `json:"indices"`
	Applications []Application `json:"applications,omitempty"`
}

type RoleIndex struct {
	Names      []string `json:"names"`
	Privileges []string `json:"privileges"`
}

type Application struct {
	Application string   `json:"application"`
	Privileges  []string `json:"privileges"`
	Resources   []string `json:"resources"`
}

// Rule represent an Elasticsearch RoleMapping Rule.
type Rule struct {
	Field map[string]string `json:"field"`
}

// RoleMapping represents an Elasticsearch RoleMapping.
type RoleMapping struct {
	Name    string            `json:"-"`
	Roles   []string          `json:"roles"`
	Rules   map[string][]Rule `json:"rules"`
	Enabled bool              `json:"enabled"`
}

// ClientBuild is used to build an Elasticsearch client. The main benefit of this builder in the context of this project
// is that it allows us to create the builder and share it among all the controllers that need access to Elasticsearch
// but delay creating the client because it requires Elasticsearch to be available.
type ClientBuilder interface {
	Build() (Client, error)
}

func NewClientBuilder(url, username, password string, certPath string) ClientBuilder {
	return &clientBuilder{
		url:      url,
		username: username,
		password: password,
		certPath: certPath,
	}
}

type clientBuilder struct {
	url      string
	username string
	password string
	certPath string
}

func (builder *clientBuilder) Build() (Client, error) {
	cert, err := os.ReadFile(builder.certPath)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(cert)
	if !ok {
		return nil, fmt.Errorf("failed to parse root certificate")
	}

	return NewClient(builder.url, builder.username, builder.password, certPool)
}

func NewClient(url, username, password string, roots *x509.CertPool) (Client, error) {
	tlsConfig, err := tls.NewTLSConfig()
	if err != nil {
		return nil, err
	}
	tlsConfig.RootCAs = roots
	config := es7.Config{
		Addresses: []string{
			url,
		},
		Username: username,
		Password: password,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	esClient, err := es7.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &client{esClient}, nil
}

// CreateRoles wraps createRoles to make creating multiple rows slightly more convenient
func (cli *client) CreateRoles(roles ...Role) error {
	for _, role := range roles {
		if err := cli.createRole(role); err != nil {
			return err
		}
	}

	return nil
}

// createRole attempts to create (or updated) the given Elasticsearch role.
func (cli *client) createRole(role Role) error {
	if role.Name == "" {
		return fmt.Errorf("can't create a role with an empty name")
	}

	j, err := json.Marshal(role.Definition)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("/_security/role/%s", role.Name), bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != 200 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}

	return nil
}

// DeleteRole will delete the Elasticsearch role
func (cli *client) DeleteRole(role Role) error {
	if role.Name == "" {
		return fmt.Errorf("can't delete a role with an empty name")
	}

	req, err := http.NewRequest("DELETE", fmt.Sprintf("/_security/role/%s", role.Name), nil)
	if err != nil {
		return err
	}

	response, err := cli.Perform(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != 200 && response.StatusCode != 404 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}

	return nil
}

// CreateUser will create the Elasticsearch user and roles (if any roles are defined for the user). If the roles exist they
// will be updated.
func (cli *client) CreateUser(user User) error {
	var rolesToCreate []Role
	for _, role := range user.Roles {
		if role.Definition != nil {
			rolesToCreate = append(rolesToCreate, role)
		}
	}

	if len(rolesToCreate) > 0 {
		if err := cli.CreateRoles(rolesToCreate...); err != nil {
			return err
		}
	}

	j, err := json.Marshal(map[string]any{
		"password":  user.Password,
		"roles":     user.RoleNames(),
		"full_name": user.FullName,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("/_security/user/%s", user.Username), bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != 200 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}

	return nil
}

// DeleteUser will delete the Elasticsearch user
func (cli *client) DeleteUser(user User) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("/_security/user/%s", user.Username), nil)
	if err != nil {
		return err
	}

	response, err := cli.Perform(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != 200 && response.StatusCode != 404 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}

	return nil
}

// UpdateUser will update the Elasticsearch users password (if password is set for the User) and roles (if roles are defined for the user).
// If the roles don't exist they will be created.
func (cli *client) UpdateUser(user User) error {
	var rolesToCreate []Role
	for _, role := range user.Roles {
		if role.Definition != nil {
			rolesToCreate = append(rolesToCreate, role)
		}
	}

	if len(rolesToCreate) > 0 {
		if err := cli.CreateRoles(rolesToCreate...); err != nil {
			return err
		}
	}

	reqBody := map[string]any{
		"roles": user.RoleNames(),
	}

	if user.Password != "" {
		reqBody["password"] = user.Password
	}
	if user.FullName != "" {
		reqBody["full_name"] = user.FullName
	}

	j, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("/_security/user/%s", user.Username), bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != 200 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}

	return nil
}

// UserExists queries Elasticsearch to see if a user with the given username already exists
func (cli *client) UserExists(username string) (bool, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("/_security/user/%s", username), nil)
	if err != nil {
		return false, err
	}

	response, err := cli.Perform(req)
	if err != nil {
		return false, err
	}
	_ = response.Body.Close()

	return response.StatusCode == 200, nil
}

type esUsers map[string]esUser
type esUser struct {
	Roles    []string `json:"roles"`
	Username string   `json:"username"`
	FullName string   `json:"full_name"`
}

// GetUsers returns all users stored in ES
func (cli *client) GetUsers() ([]User, error) {
	req, err := http.NewRequest("GET", "/_security/user", nil)
	if err != nil {
		return nil, err
	}

	response, err := cli.Perform(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 {
		return nil, errors.New(string(body))
	}

	var data esUsers
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}
	var users []User
	for k, v := range data {
		var roles []Role
		for _, role := range v.Roles {
			roles = append(roles, Role{Name: role})
		}
		users = append(users, User{Username: k, Roles: roles, FullName: v.FullName})
	}

	if users == nil {
		return []User{}, nil
	}

	return users, nil
}

// SetUserPassword sets the password on an existing user.
func (cli *client) SetUserPassword(user User) error {
	j, err := json.Marshal(map[string]any{
		"password": user.Password,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("/_security/user/%s/_password", user.Username), bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != 200 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}

	return nil
}

// CreateRoleMapping creates the given RoleMapping in Elasticsearch. The Name field in the RoleMapping is used as the role
// mapping name in the request.
func (cli *client) CreateRoleMapping(roleMapping RoleMapping) error {
	j, err := json.Marshal(roleMapping)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("/_security/role_mapping/%s", roleMapping.Name), bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != 200 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}

	return nil
}

// GetRoleMappings retrieves all RoleMappings in Elasticsearch
func (cli *client) GetRoleMappings() ([]RoleMapping, error) {
	req, err := http.NewRequest("GET", "/_security/role_mapping", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != 200 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return nil, errors.New(string(body))
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var mapp map[string]RoleMapping

	if err := json.Unmarshal(body, &mapp); err != nil {
		return nil, err
	}

	var roleMappings []RoleMapping
	for name, roleMapping := range mapp {
		roleMapping.Name = name
		roleMappings = append(roleMappings, roleMapping)
	}

	return roleMappings, nil
}

// DeleteRoleMapping attempts to delete the RoleMapping with the given name. If there is no RoleMapping that exists with
// the given name, no error is return.
func (cli *client) DeleteRoleMapping(name string) (bool, error) {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("/_security/role_mapping/%s", name), nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != 200 && response.StatusCode != 404 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return false, err
		}
		return false, errors.New(string(body))
	}

	return response.StatusCode == 200, nil
}
