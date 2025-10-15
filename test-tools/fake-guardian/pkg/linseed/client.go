package linseed

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	linseedv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

type Client struct {
	k8sClient  kubernetes.Interface
	namespace  string
	proxyAddr  string
	httpClient *http.Client
}

func NewClient(
	k8sClient kubernetes.Interface,
	namespace string,
	proxyPort int,
) (*Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "tigera-linseed.tigera-elasticsearch.svc",
	}
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &Client{
		k8sClient:  k8sClient,
		namespace:  namespace,
		proxyAddr:  fmt.Sprintf("https://localhost:%d", proxyPort),
		httpClient: httpClient,
	}, nil
}

func (c *Client) tokenFromSecret(ctx context.Context) (string, error) {
	secret, err := c.k8sClient.CoreV1().Secrets("tigera-fluentd").Get(ctx, "fluentd-node-tigera-linseed-token", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get linseed token secret: %w", err)
	}

	token := string(secret.Data["token"])
	if token == "" {
		return "", fmt.Errorf("token secret is empty")
	}

	return token, nil
}

func (c *Client) PostFlowLogs(ctx context.Context, flowlogs []linseedv1.FlowLog) (*linseedv1.BulkResponse, error) {

	// the body of the request is a newline-delimited JSON array of flow logs
	var body bytes.Buffer
	for _, flowlog := range flowlogs {
		if err := json.NewEncoder(&body).Encode(flowlog); err != nil {
			return nil, fmt.Errorf("failed to encode flow log: %w", err)
		}
		body.WriteString("\n")
	}

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v1/flows/logs/bulk", c.proxyAddr), &body)
	if err != nil {
		return nil, err
	}

	token, err := c.tokenFromSecret(ctx)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	r.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var bulkResp linseedv1.BulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &bulkResp, nil
}
