// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package l3

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/proto"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
)

func newFlow(i int64) *proto.Flow {
	return &proto.Flow{
		Key: &proto.FlowKey{
			Action:     proto.Action_Allow,
			Reporter:   proto.Reporter_Dst,
			Proto:      "tcp",
			SourceName: fmt.Sprintf("source-%d", i),
			SourceType: proto.EndpointType_WorkloadEndpoint,
			DestType:   proto.EndpointType_WorkloadEndpoint,
			DestName:   fmt.Sprintf("dest-%d", i),
			DestPort:   80,
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:   proto.PolicyKind_AdminNetworkPolicy,
						Name:   fmt.Sprintf("policy-%d", i),
						Tier:   fmt.Sprintf("tier-%d", i),
						Action: proto.Action_Allow,
					},
				},
				PendingPolicies: []*proto.PolicyHit{
					{
						Kind:   proto.PolicyKind_AdminNetworkPolicy,
						Name:   fmt.Sprintf("pending-policy-%d", i),
						Tier:   fmt.Sprintf("tier-%d", i),
						Action: proto.Action_Allow,
					},
				},
			},
		},
	}
}

func TestGoldmaneFlows_Bulk(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	// Test data.
	twoFlows := []*proto.Flow{newFlow(1), newFlow(2)}

	// Create an invalid flow.
	invalidFlow := newFlow(3)
	invalidFlow.Key = nil
	invalidBatch := []*proto.Flow{invalidFlow, newFlow(4)}

	// Create a batch where all flows are invalid.
	allInvalidFlow1 := newFlow(5)
	allInvalidFlow1.Key = nil
	allInvalidFlow2 := newFlow(6)
	allInvalidFlow2.Key = nil
	allInvalidBatch := []*proto.Flow{allInvalidFlow1, allInvalidFlow2}

	// Tests.
	tests := []struct {
		name            string
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// A batch with one invalid flow should partially succeed, skipping the invalid one.
		// The backend receives 1 valid flow (Total:1, Succeeded:1), then FailedCount (1) is added.
		{
			name:            "invalid flow",
			backendError:    nil,
			backendResponse: &v1.BulkResponse{Total: 1, Succeeded: 1, Failed: 0},
			reqBody:         testutils.MarshalBulkParams[*proto.Flow](invalidBatch),
			want:            testResult{false, 200, ""},
		},

		// A batch where all flows are invalid should return 400.
		{
			name:            "all flows invalid",
			backendError:    nil,
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[*proto.Flow](allInvalidBatch),
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains no valid flow logs", "Status":400}`,
			},
		},

		// Ingest all flow logs
		{
			name:            "ingest flows",
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[*proto.Flow](twoFlows),
			want:            testResult{false, 200, "{}"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := mockGoldmaneBulk(tt.backendResponse, tt.backendError)

			logrus.Infof("Body: %s", tt.reqBody)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/x-ndjson")
			require.NoError(t, err)

			b.hdlr.Create().ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = testutils.Marshal(t, tt.backendResponse)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes), "Unexpected response body")
		})
	}
}
