// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

package tunnelmgr

import (
	"context"
	"fmt"

	"github.com/projectcalico/calico/lib/std/chanutil"
)

type Result[V any] struct {
	// We're not exporting these to ensure that they can only be set by functions in the package. This ensures they're
	// set correctly.
	value V
	err   error
}

func (r Result[V]) Result() (V, error) {
	return r.value, r.err
}

type ChanRequest[Req any, Resp any] struct {
	obj Req
	r   chan Result[Resp]
}

func (s *ChanRequest[Req, Resp]) Get() Req {
	return s.obj
}

func (s *ChanRequest[Req, Resp]) Return(result Resp) {
	defer close(s.r)
	s.r <- Result[Resp]{value: result}
}

func (s *ChanRequest[Req, Resp]) ReturnError(err error) {
	defer close(s.r)
	s.r <- Result[Resp]{err: err}
}

// ThreadExchange is used to communicate between two threads (or routines), with a request / response format.
type ThreadExchange[Req any, Resp any] chan *ChanRequest[Req, Resp]

func (ch ThreadExchange[Req, Resp]) Send(ctx context.Context, obj Req) (Resp, error) {
	r := make(chan Result[Resp])

	var empty Resp
	err := chanutil.Write(ctx, ch, &ChanRequest[Req, Resp]{obj: obj, r: r})
	if err != nil {
		return empty, fmt.Errorf("failed to write request: %w", err)
	}

	result, err := chanutil.Read(ctx, r)
	if err != nil {
		return empty, fmt.Errorf("failed to read response: %w", err)
	}
	return result.value, result.err
}
