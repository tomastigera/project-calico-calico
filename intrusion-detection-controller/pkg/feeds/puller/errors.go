// Copyright 2019 Tigera Inc. All rights reserved.

package puller

import "fmt"

type TemporaryError string

func (e TemporaryError) Error() string {
	return string(e)
}

func (e TemporaryError) Timeout() bool {
	return true
}

type PullerError interface {
	error
	Fatal() bool
}

type pullerError struct {
	s     string
	fatal bool
}

func (e *pullerError) Error() string {
	return e.s
}

func (e *pullerError) Fatal() bool {
	return e.fatal
}

func NonFatalError(format string, a ...any) PullerError {
	return &pullerError{fmt.Sprintf(format, a...), false}
}

func FatalError(format string, a ...any) PullerError {
	return &pullerError{fmt.Sprintf(format, a...), true}
}
