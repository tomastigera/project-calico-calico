// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
package main

import (
	"os"
	"unsafe"

	"github.com/fluent/fluent-bit-go/output"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fluent-bit/plugins/out_linseed/pkg/config"
	"github.com/projectcalico/calico/fluent-bit/plugins/out_linseed/pkg/controller/endpoint"
	lshttp "github.com/projectcalico/calico/fluent-bit/plugins/out_linseed/pkg/http"
	"github.com/projectcalico/calico/fluent-bit/plugins/out_linseed/pkg/recordprocessor"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

import "C"

var (
	client             *lshttp.Client
	endpointController *endpoint.EndpointController

	stopCh chan struct{}
)

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	configureLogging()

	return output.FLBPluginRegister(def, "linseed", "Calico Enterprise linseed output plugin")
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	cfg, err := config.NewConfig(plugin, output.FLBPluginConfigKey)
	if err != nil {
		logrus.WithError(err).Error("failed to create config")
		return output.FLB_ERROR
	}

	endpointController, err = endpoint.NewController(cfg)
	if err != nil {
		logrus.WithError(err).Error("failed to initialize endpoint controller")
		return output.FLB_ERROR
	}

	client, err = lshttp.NewClient(cfg)
	if err != nil {
		logrus.WithError(err).Error("failed to create http client")
		return output.FLB_ERROR
	}

	stopCh = make(chan struct{})
	if err := endpointController.Run(stopCh); err != nil {
		logrus.WithError(err).Error("failed to start endpoint controller")
		return output.FLB_ERROR
	}

	logrus.Info("linseed output plugin initialized")
	return output.FLB_OK
}

//export FLBPluginFlushCtx
func FLBPluginFlushCtx(ctx, data unsafe.Pointer, length C.int, tag *C.char) int {
	// process fluent-bit internal messagepack buffer
	processor := recordprocessor.NewRecordProcessor()
	ndjsonBuffer, count, err := processor.Process(data, int(length))
	if err != nil {
		logrus.WithError(err).Error("failed to process record data")
		// drop the buffer when processor failed to process
		return output.FLB_ERROR
	}

	if count == 0 {
		logrus.Debug("empty flush buffer, skipping")
		return output.FLB_OK
	}

	// post to the cluster ingestion endpoint
	// when FLB_RETRY is returned to the fluent-bit engine, it will ask the scheduler to retry
	// to flush the data. The fluent-bit scheduler will decide how many seconds to wait.
	// See more at https://docs.fluentbit.io/manual/administration/scheduling-and-retries
	endpoint := endpointController.Endpoint()
	tagString := C.GoString(tag)
	err = client.Do(endpoint, tagString, ndjsonBuffer)
	if err != nil {
		logrus.WithError(err).Errorf("failed to send %d logs", count)
		// retry the buffer when we failed to send
		return output.FLB_RETRY
	}

	logrus.Infof("successfully sent %d logs", count)
	return output.FLB_OK
}

//export FLBPluginExit
func FLBPluginExit() int {
	if stopCh != nil {
		close(stopCh)
	}
	return output.FLB_OK
}

func configureLogging() {
	logutils.ConfigureFormatter("linseed")
	logrus.SetOutput(os.Stdout)

	logLevel := logrus.InfoLevel
	rawLogLevel := os.Getenv("LOG_LEVEL")
	if rawLogLevel != "" {
		parsedLevel, err := logrus.ParseLevel(rawLogLevel)
		if err == nil {
			logLevel = parsedLevel
		} else {
			logrus.WithError(err).Warnf("failed to parse log level %q, defaulting to INFO.", rawLogLevel)
		}
	}

	logrus.SetLevel(logLevel)
	logrus.Infof("log level set to %q", logLevel)
}

func main() {
}
