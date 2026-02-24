// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package testutils

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

// ErrorProducer produces a sequence of previously-queued errors from its NextError method.
type errorProducer struct {
	queue  map[string][]error
	newErr func(queueName string) error
}

type ErrorProducer interface {
	QueueError(queueName string)
	QueueSpecificError(queueName string, err error)
	QueueNErrors(queueName string, n int)
	NextError(queueName string) error
	ExpectAllErrorsConsumed()
	NextErrorByCaller() error
}

type ErrorProducerOpt func(producer *errorProducer)

func WithErrFactory(f func(queueName string) error) ErrorProducerOpt {
	return func(producer *errorProducer) {
		producer.newErr = f
	}
}

func NewErrorProducer(opts ...ErrorProducerOpt) *errorProducer {
	ep := &errorProducer{
		queue: map[string][]error{},
		newErr: func(queueName string) error {
			return fmt.Errorf("dummy ErrorQueue %s error", queueName)
		},
	}
	for _, o := range opts {
		o(ep)
	}
	return ep
}

// QueueError adds an error to the sequence of errors with the given name.
func (e *errorProducer) QueueError(queueName string) {
	e.QueueSpecificError(queueName, e.newErr(queueName))
}

// QueueSpecificError adds an error to the sequence of errors with the given name.
func (e *errorProducer) QueueSpecificError(queueName string, err error) {
	e.queue[queueName] = append(e.queue[queueName], err)
}

// QueueNErrors adds n errors to the sequence of errors with the given name.
func (e *errorProducer) QueueNErrors(queueName string, n int) {
	for range n {
		e.queue[queueName] = append(e.queue[queueName], e.newErr(queueName))
	}
}

// NextError returns the next error in the sequence with the given name.  It returns nil if there is no such error.
func (e *errorProducer) NextError(queueName string) error {
	errs := e.queue[queueName]
	if len(errs) > 0 {
		err := errs[0]
		if len(errs) == 1 {
			delete(e.queue, queueName)
		} else {
			e.queue[queueName] = errs[1:]
		}
		if err != nil {
			logrus.WithError(err).WithField("type", queueName).Warn("Simulating error")
			return err
		}
	}
	return nil
}

// NextErrorByCaller looks up the name of the calling function and returns the next error
// for the queue of that name. It returns nil if there is no such error.
func (e *errorProducer) NextErrorByCaller() error {
	callerName := ""
	pcs := make([]uintptr, 10)
	if numEntries := runtime.Callers(1, pcs); numEntries > 0 {
		pcs = pcs[:numEntries]
		frames := runtime.CallersFrames(pcs)
		for {
			frame, more := frames.Next()
			fullName := frame.Func.Name()
			parts := strings.Split(fullName, ".")
			funcName := parts[len(parts)-1]
			if funcName == "NextErrorByCaller" {
				if !more {
					panic("Couldn't find caller's frame")
				}
				continue
			}
			callerName = funcName
			break
		}
	}
	return e.NextError(callerName)
}

func (e *errorProducer) ExpectAllErrorsConsumed() {
	gomega.ExpectWithOffset(1, e.queue).To(gomega.BeEmpty(), "Some errors were not consumed.")
}

var _ ErrorProducer = (*errorProducer)(nil)
