// Copyright (c) 2019 Tigera, Inc. All rights reserved.

// Package utils has a set of utility function to be used across components
package utils

import (
	"io"
	"sync"

	log "github.com/sirupsen/logrus"
)

// SocketCopy copies the contents from two ReadWriteClosers to each other.
func SocketCopy(rwc1, rwc2 io.ReadWriteCloser) {
	var wg sync.WaitGroup

	log.Info("Handling Request")

	// Pass our request to the tunnel
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyOneWay(rwc1, rwc2)
	}()

	// See what the tunnel replies
	go func() {
		defer wg.Done()
		copyOneWay(rwc2, rwc1)
	}()

	wg.Wait()
}

func copyOneWay(dst, src io.ReadWriteCloser) {
	n, err := io.Copy(dst, src)
	if err != nil {
		log.Errorf("Error Reading: %s", err.Error())
	}
	log.Tracef("Copied %d bytes", n)
	_ = dst.Close()
}
