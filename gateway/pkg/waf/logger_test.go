package waf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/projectcalico/calico/felix/proto"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func TestConvertWAFEventToWAFLog(t *testing.T) {
	t.Setenv(GatewayNameEnvVar, "test-gateway")
	t.Setenv(GatewayNamespaceEnvVar, "test-gateway-namespace")

	now := time.Now().UTC()

	event := &proto.WAFEvent{
		TxId:    "tx001",
		SrcIp:   "10.3.53.1",
		SrcPort: 65500,
		Rules: []*proto.WAFRuleHit{
			{
				Rule: &proto.WAFRule{
					Id:       "1620",
					Message:  "Fake rule",
					Severity: "high",
					File:     "/etc/m/test.conf",
					Line:     "58800",
				},
				Disruptive: false,
			},
		},
		Action: "pass",
		Request: &proto.HTTPRequest{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
		Timestamp: timestamppb.New(now),
	}
	log := ConvertWAFEventToWAFLog(event)

	require.Equal(t, now, log.Timestamp)
	require.Equal(t, "/test", log.Path)
	require.Equal(t, "GET", log.Method)
	require.Equal(t, "tx001", log.RequestId)
	require.Equal(t, "HTTP/1.1", log.Protocol)
	require.Equal(t, []v1.WAFRuleHit{
		{
			Id:         "1620",
			Message:    "Fake rule",
			Severity:   "high",
			File:       "/etc/m/test.conf",
			Line:       "58800",
			Disruptive: false,
		},
	}, log.Rules)
	require.Equal(t, "test-gateway", log.GatewayName)
	require.Equal(t, "test-gateway-namespace", log.GatewayNamespace)
}
