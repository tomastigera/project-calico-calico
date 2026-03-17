// Copyright (c) 2019-2026 Tigera Inc. All rights reserved.
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

const (
	stateFilePfx   = "elf-state"
	stateFileSep   = "_"
	rubyFileSep    = "/"
	rubyFileSepSub = "-"
)

// cwLogsClient is the interface used by internal functions for testability.
type cwLogsClient interface {
	DescribeLogStreams(ctx context.Context, params *cloudwatchlogs.DescribeLogStreamsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error)
	GetLogEvents(ctx context.Context, params *cloudwatchlogs.GetLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error)
}

// Setup AWS session to cloudwatch logs service, returns session handler.
func AwsSetupLogSession(ctx context.Context) (*cloudwatchlogs.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	return cloudwatchlogs.NewFromConfig(cfg), nil
}

// Using AWS session handler, cloudwatch logs specifics and a timestamp, return a log token.
func AwsGetStateFileWithToken(ctx context.Context, logs cwLogsClient, group, prefix string, startTime int64) (map[string]string, error) {
	results := make(map[string]string)

	streams, err := getLogStreams(ctx, logs, group, prefix)
	if err != nil {
		return nil, err
	}

	for _, stream := range streams {
		token, err := getToken(ctx, logs, group, stream, startTime)
		if err != nil {
			return nil, err
		}

		replaced := strings.ReplaceAll(stream, rubyFileSep, rubyFileSepSub)
		stateFile := stateFilePfx + stateFileSep + replaced
		results[stateFile] = token
	}

	return results, nil
}

// Wrapper over cloudwatchlogs description, this function returns a slice of log-stream name using log-group name and stream prefix.
// It paginates through all results so that no streams are silently dropped.
func getLogStreams(ctx context.Context, logs cwLogsClient, groupName, streamPrefix string) ([]string, error) {
	var streams []string

	// Logstream name is dynamic for each EKS deployment. We use LogStreamName prefix to gather the actual stream name.
	paginator := cloudwatchlogs.NewDescribeLogStreamsPaginator(logs, &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupName:        aws.String(groupName),
		LogStreamNamePrefix: aws.String(streamPrefix),
	})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, stream := range resp.LogStreams {
			if stream.LogStreamName != nil {
				streams = append(streams, *stream.LogStreamName)
			}
		}
	}
	return streams, nil
}

// Get cloudwatchlogs token pointing to the log stream forward.
func getToken(ctx context.Context, logs cwLogsClient, group, stream string, startTime int64) (string, error) {
	resp, err := logs.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
		Limit:         aws.Int32(1),
		LogGroupName:  aws.String(group),
		LogStreamName: aws.String(stream),
		StartTime:     aws.Int64(startTime),
	})
	if err != nil {
		return "", err
	}

	if resp.NextForwardToken == nil {
		return "", fmt.Errorf("no forward token returned for stream %s", stream)
	}
	return *resp.NextForwardToken, nil
}
