// Copyright (c) 2019 Tigera Inc. All rights reserved.

package util

import (
	"context"
	"errors"
	"time"
)

func WaitForChannel(ctx context.Context, ch <-chan struct{}, timeout time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(timeout):
		return errors.New("timeout waiting for index creation")
	case <-ch:
		return nil
	}
}
