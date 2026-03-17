// Copyright (c) 2026 Tigera Inc. All rights reserved.
package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCWLogsClient implements cwLogsClient for testing.
type mockCWLogsClient struct {
	describeLogStreamsFunc func(ctx context.Context, params *cloudwatchlogs.DescribeLogStreamsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error)
	getLogEventsFunc       func(ctx context.Context, params *cloudwatchlogs.GetLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error)
}

func (m *mockCWLogsClient) DescribeLogStreams(ctx context.Context, params *cloudwatchlogs.DescribeLogStreamsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
	return m.describeLogStreamsFunc(ctx, params, optFns...)
}

func (m *mockCWLogsClient) GetLogEvents(ctx context.Context, params *cloudwatchlogs.GetLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error) {
	return m.getLogEventsFunc(ctx, params, optFns...)
}

func TestGetLogStreams(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, params *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			assert.Equal(t, "my-group", *params.LogGroupName)
			assert.Equal(t, "my-prefix", *params.LogStreamNamePrefix)
			// Single page, no NextToken.
			return &cloudwatchlogs.DescribeLogStreamsOutput{
				LogStreams: []types.LogStream{
					{LogStreamName: aws.String("my-prefix-stream-1")},
					{LogStreamName: aws.String("my-prefix-stream-2")},
				},
			}, nil
		},
	}

	streams, err := getLogStreams(ctx, mock, "my-group", "my-prefix")
	require.NoError(t, err)
	require.Len(t, streams, 2)
	assert.Equal(t, "my-prefix-stream-1", streams[0])
	assert.Equal(t, "my-prefix-stream-2", streams[1])
}

func TestGetLogStreamsPagination(t *testing.T) {
	ctx := context.Background()

	callCount := 0
	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, params *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			callCount++
			if callCount == 1 {
				assert.Nil(t, params.NextToken)
				return &cloudwatchlogs.DescribeLogStreamsOutput{
					LogStreams: []types.LogStream{
						{LogStreamName: aws.String("stream-1")},
					},
					NextToken: aws.String("page-2-token"),
				}, nil
			}
			assert.Equal(t, "page-2-token", *params.NextToken)
			return &cloudwatchlogs.DescribeLogStreamsOutput{
				LogStreams: []types.LogStream{
					{LogStreamName: aws.String("stream-2")},
				},
			}, nil
		},
	}

	streams, err := getLogStreams(ctx, mock, "my-group", "my-prefix")
	require.NoError(t, err)
	require.Len(t, streams, 2)
	assert.Equal(t, "stream-1", streams[0])
	assert.Equal(t, "stream-2", streams[1])
	assert.Equal(t, 2, callCount)
}

func TestGetLogStreamsError(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			return nil, fmt.Errorf("access denied")
		},
	}

	streams, err := getLogStreams(ctx, mock, "my-group", "my-prefix")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
	assert.Nil(t, streams)
}

func TestGetLogStreamsEmpty(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			return &cloudwatchlogs.DescribeLogStreamsOutput{
				LogStreams: []types.LogStream{},
			}, nil
		},
	}

	streams, err := getLogStreams(ctx, mock, "my-group", "my-prefix")
	require.NoError(t, err)
	assert.Empty(t, streams)
}

func TestGetLogStreamsSkipsNilNames(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			return &cloudwatchlogs.DescribeLogStreamsOutput{
				LogStreams: []types.LogStream{
					{LogStreamName: aws.String("valid-stream")},
					{LogStreamName: nil},
					{LogStreamName: aws.String("another-stream")},
				},
			}, nil
		},
	}

	streams, err := getLogStreams(ctx, mock, "my-group", "my-prefix")
	require.NoError(t, err)
	require.Len(t, streams, 2)
	assert.Equal(t, "valid-stream", streams[0])
	assert.Equal(t, "another-stream", streams[1])
}

func TestGetToken(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		getLogEventsFunc: func(_ context.Context, params *cloudwatchlogs.GetLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error) {
			assert.Equal(t, "my-group", *params.LogGroupName)
			assert.Equal(t, "my-stream", *params.LogStreamName)
			assert.Equal(t, int32(1), *params.Limit)
			assert.Equal(t, int64(12345), *params.StartTime)
			return &cloudwatchlogs.GetLogEventsOutput{
				NextForwardToken: aws.String("token-abc"),
			}, nil
		},
	}

	token, err := getToken(ctx, mock, "my-group", "my-stream", 12345)
	require.NoError(t, err)
	assert.Equal(t, "token-abc", token)
}

func TestGetTokenNilForwardToken(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		getLogEventsFunc: func(_ context.Context, _ *cloudwatchlogs.GetLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error) {
			return &cloudwatchlogs.GetLogEventsOutput{
				NextForwardToken: nil,
			}, nil
		},
	}

	token, err := getToken(ctx, mock, "my-group", "my-stream", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no forward token returned for stream my-stream")
	assert.Empty(t, token)
}

func TestGetTokenError(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		getLogEventsFunc: func(_ context.Context, _ *cloudwatchlogs.GetLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error) {
			return nil, fmt.Errorf("throttled")
		},
	}

	token, err := getToken(ctx, mock, "my-group", "my-stream", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "throttled")
	assert.Empty(t, token)
}

func TestAwsGetStateFileWithToken(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			return &cloudwatchlogs.DescribeLogStreamsOutput{
				LogStreams: []types.LogStream{
					{LogStreamName: aws.String("kube-apiserver-audit/abc")},
					{LogStreamName: aws.String("kube-apiserver-audit/def")},
				},
			}, nil
		},
		getLogEventsFunc: func(_ context.Context, params *cloudwatchlogs.GetLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error) {
			// Return a unique token per stream.
			return &cloudwatchlogs.GetLogEventsOutput{
				NextForwardToken: aws.String("tok-" + *params.LogStreamName),
			}, nil
		},
	}

	results, err := AwsGetStateFileWithToken(ctx, mock, "group", "prefix", 100)
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Stream names have "/" replaced with "-" and are prefixed with "elf-state_".
	assert.Equal(t, "tok-kube-apiserver-audit/abc", results["elf-state_kube-apiserver-audit-abc"])
	assert.Equal(t, "tok-kube-apiserver-audit/def", results["elf-state_kube-apiserver-audit-def"])
}

func TestAwsGetStateFileWithTokenDescribeError(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			return nil, fmt.Errorf("describe failed")
		},
	}

	results, err := AwsGetStateFileWithToken(ctx, mock, "group", "prefix", 0)
	require.Error(t, err)
	assert.Nil(t, results)
}

func TestAwsGetStateFileWithTokenGetEventsError(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			return &cloudwatchlogs.DescribeLogStreamsOutput{
				LogStreams: []types.LogStream{
					{LogStreamName: aws.String("stream-1")},
				},
			}, nil
		},
		getLogEventsFunc: func(_ context.Context, _ *cloudwatchlogs.GetLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error) {
			return nil, fmt.Errorf("get events failed")
		},
	}

	results, err := AwsGetStateFileWithToken(ctx, mock, "group", "prefix", 0)
	require.Error(t, err)
	assert.Nil(t, results)
}

func TestAwsGetStateFileWithTokenNoStreams(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			return &cloudwatchlogs.DescribeLogStreamsOutput{
				LogStreams: []types.LogStream{},
			}, nil
		},
	}

	results, err := AwsGetStateFileWithToken(ctx, mock, "group", "prefix", 0)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestAwsGetStateFileWithTokenPartialFailure(t *testing.T) {
	ctx := context.Background()

	callCount := 0
	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			return &cloudwatchlogs.DescribeLogStreamsOutput{
				LogStreams: []types.LogStream{
					{LogStreamName: aws.String("stream-1")},
					{LogStreamName: aws.String("stream-2")},
				},
			}, nil
		},
		getLogEventsFunc: func(_ context.Context, _ *cloudwatchlogs.GetLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error) {
			callCount++
			if callCount == 1 {
				return &cloudwatchlogs.GetLogEventsOutput{
					NextForwardToken: aws.String("tok-1"),
				}, nil
			}
			return nil, fmt.Errorf("second stream failed")
		},
	}

	results, err := AwsGetStateFileWithToken(ctx, mock, "group", "prefix", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "second stream failed")
	assert.Nil(t, results)
}

func TestAwsGetStateFileWithTokenStreamNameNoSlash(t *testing.T) {
	ctx := context.Background()

	mock := &mockCWLogsClient{
		describeLogStreamsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogStreamsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
			return &cloudwatchlogs.DescribeLogStreamsOutput{
				LogStreams: []types.LogStream{
					{LogStreamName: aws.String("plain-stream-name")},
				},
			}, nil
		},
		getLogEventsFunc: func(_ context.Context, _ *cloudwatchlogs.GetLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error) {
			return &cloudwatchlogs.GetLogEventsOutput{
				NextForwardToken: aws.String("tok-plain"),
			}, nil
		},
	}

	results, err := AwsGetStateFileWithToken(ctx, mock, "group", "prefix", 0)
	require.NoError(t, err)
	require.Len(t, results, 1)
	// No "/" means no replacement; name is preserved as-is in the state file key.
	assert.Equal(t, "tok-plain", results["elf-state_plain-stream-name"])
}
