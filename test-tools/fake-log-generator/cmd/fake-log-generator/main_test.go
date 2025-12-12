package main

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

func init() {
	logutils.ConfigureFormatter("fake-log-gen")
}

func CreateConfig(directoutput bool) Config {
	cfg := Config{
		loaded: LoadedConfig{PromPort: 2112,
			Rate:         1,
			BatchSize:    1,
			FlowFile:     "test.log",
			TokenPath:    "",
			TenantID:     "",
			DirectOutput: directoutput,
		},
		period: 1,
	}
	flow := v1.FlowLog{}
	line := `{"startTime":1699375161,"endTime":1699375483,"source_ip":null,"source_name":"-","source_name_aggr":"frontend-755cdc7957-*","source_namespace":"default","nat_outgoing_ports":null,"source_port":null,"source_type":"wep","source_labels":{"labels":["app=frontend","pod-template-hash=755cdc7957"]},"dest_ip":null,"dest_name":"-","dest_name_aggr":"cartservice-7d4899b484-*","dest_namespace":"default","dest_port":7070,"dest_type":"wep","dest_labels":{"labels":["pod-template-hash=7d4899b484","app=cartservice"]},"dest_service_namespace":"default","dest_service_name":"cartservice","dest_service_port":"grpc","dest_service_port_num":7070,"dest_domains":null,"proto":"tcp","action":"allow","reporter":"src","policies":{"all_policies":["0|__PROFILE__|__PROFILE__.kns.default|allow|0"],"enforced_policies":["0|__PROFILE__|__PROFILE__.kns.default|allow|0"],"pending_policies":["0|__PROFILE__|__PROFILE__.kns.default|allow|0"],"transit_policies":["0|default|fwd-policy|allow|0"]},"bytes_in":133612,"bytes_out":196245,"num_flows":1,"num_flows_started":1,"num_flows_completed":0,"packets_in":1417,"packets_out":2418,"http_requests_allowed_in":0,"http_requests_denied_in":0,"process_name":"/src/server","num_process_names":1,"process_id":"21842","num_process_ids":1,"process_args":["-"],"num_process_args":0,"original_source_ips":null,"num_original_source_ips":0,"tcp_mean_send_congestion_window":0,"tcp_min_send_congestion_window":0,"tcp_mean_smooth_rtt":0,"tcp_max_smooth_rtt":0,"tcp_mean_min_rtt":0,"tcp_max_min_rtt":0,"tcp_mean_mss":0,"tcp_min_mss":0,"tcp_total_retransmissions":0,"tcp_lost_packets":0,"tcp_unrecovered_to":0}`
	err := json.Unmarshal([]byte(line), &flow)
	if err != nil {
		log.Infof("Error hit on line:\n %s\n", line)
		panic(err)
	}
	cfg.exampleFlows = append(cfg.exampleFlows, flow)
	return cfg
}

func TestFlowLogFile(t *testing.T) {
	cfg := CreateConfig(false)
	_ = os.Remove(cfg.loaded.FlowFile)
	startTime := time.Now()
	endTime := flowLogIteration(startTime, cfg, nil)

	if endTime != startTime.Add(time.Duration(cfg.period)) {
		t.Fatalf(`flowLogIteration returned wrong time: %v`, endTime)
	}
	file, err := os.Open(cfg.loaded.FlowFile)
	if err != nil {
		t.Fatalf(`Unable to open flow file: %v`, cfg.loaded.FlowFile)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		outline := scanner.Text()
		if !strings.Contains(outline, "pod-template-hash=755cdc7957") {
			t.Fatalf(`output file didn't contain the correct log.  Got:\n %v`, outline)
		}
	}
	_ = os.Remove(cfg.loaded.FlowFile)
}

func TestFlowLogSend(t *testing.T) {

	log.Info("Creating Config")
	cfg := CreateConfig(true)

	log.Info("Creating mock client")
	cli := client.NewMockClient(cfg.loaded.TenantID, rest.MockResult{})

	startTime := time.Now()
	log.Info("Starting test")
	endTime := flowLogIteration(startTime, cfg, cli)
	if endTime != startTime.Add(time.Duration(cfg.period)) {
		t.Fatalf(`flowLogIteration returned wrong time: %v`, endTime)
	}
}

type Envvar struct {
	name  string
	value string
}

func Test_loadConfig(t *testing.T) {
	tests := []struct {
		name    string
		envvars []Envvar
		want    LoadedConfig
	}{
		{"default",
			[]Envvar{{"FLOW_LOG_FILE", "../../example-flows/flows.log"}},
			LoadedConfig{
				PromPort:       2112,
				Rate:           2,
				BatchSize:      10,
				FlowFile:       "../../example-flows/flows.log",
				TokenPath:      "/certs/token",
				DirectOutput:   false,
				URL:            "https://tigera-linseed.tigera-elasticsearch.svc:9443",
				CACertPath:     "/certs/cacert.crt",
				ClientCertPath: "/certs/tls.crt",
				ClientKeyPath:  "/certs/tls.key",
				LogLevel:       "INFO",
			},
		},
		{"custom",
			[]Envvar{
				{"FLOW_LOG_FILE", "../../example-flows/flows.log"},
				{"PROMETHEUSMETRICSPORT", "1234"},
				{"RATE", "7"},
				{"BATCH_SIZE", "123"},
				{"LINSEED_TOKEN", "/custom/token"},
				{"DIRECT_OUTPUT", "true"},
				{"LINSEED_ENDPOINT", "https://custom.svc:9443"},
				{"ELASTIC_INDEX_SUFFIX", "abcdef"},
				{"LINSEED_CA_PATH", "/custom/cacert.crt"},
				{"TLS_CRT_PATH", "/custom/tls.crt"},
				{"TLS_KEY_PATH", "/custom/tls.key"},
				{"LOG_LEVEL", "DEBUG"},
			},
			LoadedConfig{
				PromPort:       1234,
				Rate:           7,
				BatchSize:      123,
				FlowFile:       "../../example-flows/flows.log",
				TokenPath:      "/custom/token",
				DirectOutput:   true,
				URL:            "https://custom.svc:9443",
				CACertPath:     "/custom/cacert.crt",
				ClientCertPath: "/custom/tls.crt",
				ClientKeyPath:  "/custom/tls.key",
				TenantID:       "abcdef",
				LogLevel:       "DEBUG",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, envvar := range tt.envvars {
				t.Setenv(envvar.name, envvar.value)
			}
			if got := loadConfig(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
