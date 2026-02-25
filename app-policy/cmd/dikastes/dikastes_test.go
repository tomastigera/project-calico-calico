// Copyright (c) 2022 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"
	"testing"
	"time"

	authzv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/projectcalico/calico/app-policy/flags"
	"github.com/projectcalico/calico/app-policy/internal/util/testutils"
	fakepolicysync "github.com/projectcalico/calico/app-policy/test/fv/policysync"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/uds"
)

//go:embed testdata/tigera.conf
var tigeraConfContents string
var tigeraConfName = "tigera.conf"

func TestRunServer(t *testing.T) {
	ctx := t.Context()

	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, tigeraConfName)
	if err := os.WriteFile(confPath, []byte(tigeraConfContents), 0644); err != nil {
		t.Fatalf("Failed to write file %s: %s", tigeraConfName, err)
	}

	listenPath := filepath.Join(tempDir, "dikastes.sock")
	policySyncPath := filepath.Join(tempDir, "nodeagent.sock")

	fps, err := fakepolicysync.NewFakePolicySync(policySyncPath)
	if err != nil {
		t.Fatalf("cannot setup policysync fake %v", err)
		return
	}
	go fps.Serve(ctx)

	config := flags.New()
	args := []string{
		"dikastes", "server",
		"-log-level", "trace",
		"-dial", policySyncPath,
		"-listen", listenPath,
		"-per-host-waf-enabled",
		"-waf-ruleset-file", confPath,
		"-waf-directive", "SecRuleEngine On",
		"-subscription-type", "per-host-policies",
		"-geo-db-path", "",
	}

	if err := config.Parse(args); err != nil {
		t.Fatalf("cannot parse config %v", err)
		return
	}

	ready := make(chan struct{}, 1)
	go runServer(ctx, config, ready)
	<-ready
	fps.SendUpdates(inSync())

	client, err := NewExtAuthzClient(ctx, listenPath)
	if err != nil {
		t.Fatal("cannot create client", err)
		return
	}

	requests := []struct {
		*testutils.CheckRequestBuilder
		expectedCode code.Code
		expectedErr  error
	}{
		{testutils.NewCheckRequestBuilder(), code.Code_OK, nil},
		{testutils.NewCheckRequestBuilder(
			testutils.WithDestinationHostPort("1.1.1.1", 443),
			testutils.WithMethod("GET"),
			testutils.WithHost("my.loadbalancer.address"),
			testutils.WithPath("/cart?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user"),
		), code.Code_PERMISSION_DENIED, nil},
		{testutils.NewCheckRequestBuilder(
			testutils.WithDestinationHostPort("2.2.2.2", 443),
			testutils.WithMethod("POST"),
			testutils.WithHost("www.example.com"),
			testutils.WithPath("/vulnerable.php?id=1' waitfor delay '00:00:10'--"),
			testutils.WithScheme("https"),
		), code.Code_PERMISSION_DENIED, nil},
	}

	for _, req := range requests {
		resp, err := client.Check(ctx, req.Value())
		assert.Nil(t, err, "error must not have occurred")
		assert.Equal(t, req.expectedErr, err)
		assert.Equal(t, req.expectedCode, code.Code(resp.Status.Code))
	}
	<-time.After(500 * time.Millisecond)

	entries := fps.GetWAFEvents()
	assert.Equal(t, 2, len(entries), "expected the correct number of logs")

	// test resend after client disconnects
	fps.StopAndDisconnect()
	for _, req := range requests {
		resp, err := client.Check(ctx, req.Value())
		assert.Nil(t, err, "error must not have occurred")
		assert.Equal(t, req.expectedErr, err)
		assert.Equal(t, req.expectedCode, code.Code(resp.Status.Code))
	}
	fps.Resume()
	<-time.After(9 * time.Second)

	entries = fps.GetWAFEvents()
	assert.Equal(t, 4, len(entries), "expected the correct number of logs")
}

func NewExtAuthzClient(ctx context.Context, addr string) (authzv3.AuthorizationClient, error) {
	dialOpts := uds.GetDialOptionsWithNetwork("unix")
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	cc, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, err
	}
	return authzv3.NewAuthorizationClient(cc), nil
}

func inSync() *proto.ToDataplane {
	return &proto.ToDataplane{
		Payload: &proto.ToDataplane_InSync{
			InSync: &proto.InSync{},
		},
	}
}
