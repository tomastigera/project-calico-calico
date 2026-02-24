// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package helpers

import (
	"time"
)

type NoRetryError struct {
	err error
}

func NewNoRetryError(err error) *NoRetryError {
	return &NoRetryError{err: err}
}

func (e *NoRetryError) Error() string {
	return e.err.Error()
}

type RetryFunction func() error

type BackOffFunction func(time.Duration, uint) <-chan time.Time

func RetryWithBackOff(retryFunc RetryFunction, backOffFunc BackOffFunction, duration time.Duration, times uint) (err error) {
	for iteration := range times {
		if iteration > 0 {
			<-backOffFunc(duration, iteration)
		}
		err = retryFunc()
		switch err.(type) {
		case nil, *NoRetryError:
			return
		}
	}
	return
}

func RetryWithConstantBackOff(retry RetryFunction, duration time.Duration, times uint) (err error) {
	backOffFunc := func(duration time.Duration, iteration uint) <-chan time.Time {
		return time.NewTimer(duration).C
	}
	return RetryWithBackOff(retry, backOffFunc, duration, times)
}

func RetryWithLinearBackOff(retry RetryFunction, duration time.Duration, times uint) (err error) {
	backOffFunc := func(duration time.Duration, iteration uint) <-chan time.Time {
		return time.NewTimer(duration * time.Duration(iteration)).C
	}
	return RetryWithBackOff(retry, backOffFunc, duration, times)
}

func RetryWithExponentialBackOff(retry RetryFunction, duration time.Duration, times uint) (err error) {
	backOffFunc := func(duration time.Duration, iteration uint) <-chan time.Time {
		return time.NewTimer(duration * time.Duration(0x01<<iteration-1)).C
	}
	return RetryWithBackOff(retry, backOffFunc, duration, times)
}
