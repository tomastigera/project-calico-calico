// Copyright (c) 2022 Tigera, Inc. All rights reserved.

//go:build !windows

package netlinkshim

import (
	"context"
	"fmt"
	"reflect"
	"syscall"
	"unsafe"

	gonfqueue "github.com/florianl/go-nfqueue"
)

type NfQueue interface {
	RegisterWithErrorFunc(ctx context.Context, fn gonfqueue.HookFunc, errfn gonfqueue.ErrorFunc) error
	SetVerdict(id uint32, verdict int) error
	SetVerdictWithMark(id uint32, verdict, mark int) error
	SetVerdictBatch(id uint32, verdict int) error
	Close() error
	DebugKillConnection() error
}

func NewRealNfQueue(config *gonfqueue.Config) (NfQueue, error) {
	if raw, err := gonfqueue.Open(config); err != nil {
		return nil, err
	} else {
		return &realNfQueue{raw}, nil
	}
}

type realNfQueue struct {
	*gonfqueue.Nfqueue
}

// DebugKillConnection finds the underlying file descriptor for the nfqueue connection and closes it. This is used to
// simulate an unexpected closure of the connection. The underlying nfqueue library may close the connection without
// notification and without restarting it if it encounters errors, so this function is used to force such an error
// so the restart logic can be tested with fv's.
//
// In general, DO NOT USE THIS FUNCTION.
func (nfc *realNfQueue) DebugKillConnection() error {
	path := []string{"sock", "s", "fd", "file", "pfd", "Sysfd"}
	current := reflect.ValueOf(nfc.Con)
	for _, v := range path {
		if current.Kind() == reflect.Interface {
			current = current.Elem()
		}

		if current.Kind() == reflect.Pointer {
			current = current.Elem()
		}

		if current.Kind() != reflect.Struct {
			break
		}

		current = current.FieldByName(v)
		if !current.IsValid() {
			return fmt.Errorf("field path to file descriptor is invalid")
		}
	}

	if !current.IsValid() {
		return fmt.Errorf("field path to file descriptor is invalid")
	}

	fd := reflect.NewAt(current.Type(), unsafe.Pointer(current.UnsafeAddr())).Elem().Interface().(int)

	return syscall.Close(fd)
}
