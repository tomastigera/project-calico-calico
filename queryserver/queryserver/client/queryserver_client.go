package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"

	querycacheclient "github.com/projectcalico/calico/queryserver/pkg/querycache/client"
)

type QueryServerConfig struct {
	QueryServerTunnelURL string
	QueryServerURL       string
	QueryServerCA        string
	QueryServerToken     string
}

var errInvalidToken = errors.New("queryServer Token is not valid")

type QueryServerClient interface {
	Client() *http.Client
	SearchEndpoints(*QueryServerConfig, *querycacheclient.QueryEndpointsReq) (*http.Response, error)
}

type queryServerClient struct {
	client *http.Client
}

type QueryServerResults struct {
	Err        error
	Body       []byte
	StatusCode int
}

func (q *queryServerClient) Client() *http.Client {
	return q.client
}

func NewQueryServerClient(cfg *QueryServerConfig) (*queryServerClient, error) {
	// create client
	cert, err := os.ReadFile(cfg.QueryServerCA)
	if err != nil {
		log.WithError(err).Info("failed to read queryserver CA from file: ", err)
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	return &queryServerClient{
		client: client,
	}, nil
}

func (q *queryServerClient) SearchEndpoints(cfg *QueryServerConfig, reqBody *querycacheclient.QueryEndpointsReqBody,
	clusterId string) (*querycacheclient.QueryEndpointsResp, error) {
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		log.WithError(err).Info("failed to json.marshal QueryEndpointsReqBody: ", err)
		return nil, err
	}
	path := "/endpoints"

	// service url is set differently for mcm vs standalone environments
	url := cfg.QueryServerURL
	if clusterId != "cluster" {
		url = cfg.QueryServerTunnelURL
	}

	req, err := http.NewRequest("POST", url+path, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		log.WithError(err).Info("failed to create http request: ", err)
		return nil, err
	}
	if cfg.QueryServerToken == "" {
		log.WithError(errInvalidToken).Info("token is empty: ", errInvalidToken)
		return nil, errInvalidToken
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", cfg.QueryServerToken))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("x-cluster-id", clusterId)

	resp, err := q.client.Do(req)
	if err != nil {
		log.WithError(err).Info("failed to execute queryserver request: ", err)
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// read response from queryserver endpoints call
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("call to read response body from queryserver failed.")
		return nil, errors.New("failed to read response from queryserver")
	}

	if resp.StatusCode != http.StatusOK {
		log.Errorf("queryserver returned status %d: %s", resp.StatusCode, string(respBytes))
		return nil, fmt.Errorf("queryserver returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	qsResp := querycacheclient.QueryEndpointsResp{}
	err = json.Unmarshal(respBytes, &qsResp)
	if err != nil {
		log.Errorf("Response: %s", string(respBytes))
		log.WithError(err).Error("unmarshalling endpointsRespBody failed.")
		return nil, err
	}

	return &qsResp, err
}
