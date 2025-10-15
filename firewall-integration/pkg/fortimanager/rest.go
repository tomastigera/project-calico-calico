package fortimanager

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type FortiGateRestClientApi interface {
	FortiGateRestGet(url string) ([]uint8, error)
	FortiGateRestDelete(url string) ([]uint8, error)
	FortiGateRestPut(url string, payload []uint8) ([]uint8, error)
	FortiGateRestPost(url string, payload []uint8) ([]uint8, error)
}

const FortiManagerCodeOK = 0

// FortiManagerRestClient contains connectivity information and
// manages sessions when connecting to a Fortimanager.
// At any time only a single session is open until FortiManager expires
// it at which point a new session is automatically created/refreshed.
type FortiManagerRestClient struct {
	name               string
	URL                string
	applicationType    string
	session            string
	sessionId          int
	inSecureSkipVerify bool
}

func (f *FortiManagerRestClient) Post(payload []uint8) ([]uint8, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: f.inSecureSkipVerify},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Post(f.URL, f.applicationType, bytes.NewBuffer(payload))
	if err != nil {
		log.Error(err)
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).WithField("payload", string(payload)).Error("Received error from Fortimanager")
		return nil, err
	}

	return body, err
}

type FortiGateRestClient struct {
	applicationType    string
	inSecureSkipVerify bool
}

func NewFortiGateRestClient(applicationType string, inSecureSkipVerify bool) FortiGateRestClientApi {
	return &FortiGateRestClient{
		applicationType:    applicationType,
		inSecureSkipVerify: inSecureSkipVerify,
	}
}

func (f *FortiGateRestClient) FortiGateRestGet(url string) ([]uint8, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: f.inSecureSkipVerify},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(url)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	//Handle errors from http request, these errors are from http response.
	if resp != nil && resp.StatusCode != FortiGateReturnSuccess && resp.StatusCode != FortiGateResourceNotFound {
		log.WithError(err).Error("Error from FortiGate ")
		return nil, fmt.Errorf("Error from FortiGate, GET Status:%s StatusCode:%d", resp.Status, resp.StatusCode)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("Error from FortiGate for GET request")
		return nil, err
	}

	return body, err
}

func (f *FortiGateRestClient) FortiGateRestPut(url string, payload []uint8) ([]uint8, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: f.inSecureSkipVerify},
	}
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", f.applicationType)
	resp, err := client.Do(req)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	//Handle errors from http request, these errors are from http response.
	if resp != nil && resp.StatusCode != FortiGateReturnSuccess && resp.StatusCode != FortiGateResourceNotFound {
		log.WithError(err).Error("Error from FortiGate for PUT request")
		return nil, fmt.Errorf("Error from FortiGate, PUT Status:%s StatusCode:%d", resp.Status, resp.StatusCode)
	}

	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("Error from FortiGate for PUT request")
		return nil, err
	}

	return body, err
}

func (f *FortiGateRestClient) FortiGateRestPost(url string, payload []uint8) ([]uint8, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: f.inSecureSkipVerify},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Post(url, f.applicationType, bytes.NewBuffer(payload))
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if resp != nil && resp.StatusCode != FortiGateReturnSuccess {
		log.WithError(err).Error("Error from FortiGate for POST request")
		return nil, fmt.Errorf("Error from FortiGate, POST Status:%s StatusCode:%d", resp.Status, resp.StatusCode)
	}

	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("Error from FortiGate for POST request")
		return nil, err
	}

	return body, err
}

func (f *FortiGateRestClient) FortiGateRestDelete(url string) ([]uint8, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: f.inSecureSkipVerify},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// Return Errors for other than ResponseNotFound [404]
	if resp != nil && resp.StatusCode != FortiGateReturnSuccess && resp.StatusCode != FortiGateResourceNotFound {
		log.Error("Error from FortiGate for DELETE request")
		return nil, fmt.Errorf("Error from FortiGate, DELETE Status:%s StatusCode:%d", resp.Status, resp.StatusCode)
	}

	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("Error from FortiGate for DELETE request")
		return nil, err
	}

	return body, err
}
