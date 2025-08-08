package collector

import (
	"io"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/grpc"
)

var (
	// LoggingServer implements  v3.AccessLogServiceServer interface.
	// this is used by envoy to stream access logs to this service.
	_ v3.AccessLogServiceServer = (*LoggingServer)(nil)
)

type LoggingServer struct {
	logEntryFn func(log *accesslogv3.HTTPAccessLogEntry)
}

func NewLoggingServer(logEntryFn func(log *accesslogv3.HTTPAccessLogEntry)) *LoggingServer {
	return &LoggingServer{logEntryFn: logEntryFn}
}

func (s *LoggingServer) StreamAccessLogs(srv v3.AccessLogService_StreamAccessLogsServer) error {
	ctx := srv.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		payload, err := srv.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		switch logEntry := payload.LogEntries.(type) {
		case *v3.StreamAccessLogsMessage_HttpLogs:
			for _, log := range logEntry.HttpLogs.LogEntry {
				s.processHTTPLogEntry(log)
			}
		default:
		}
	}
}

func (s *LoggingServer) processHTTPLogEntry(log *accesslogv3.HTTPAccessLogEntry) {
	s.logEntryFn(log)
}

func (s *LoggingServer) RegisterAccessLogServiceServer(gs *grpc.Server) {
	v3.RegisterAccessLogServiceServer(gs, s)
}
