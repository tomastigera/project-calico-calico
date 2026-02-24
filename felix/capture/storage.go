// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

package capture

import (
	"errors"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/utils/strings"

	"github.com/projectcalico/calico/felix/proto"
)

// ActiveCaptures stores the state of the current active capture
// Adding a new capture triggers a capture start
// Removing a capture triggers a capture end
// RemovingAndClean will trigger a capture end and deletion of all pcap files
type ActiveCaptures interface {
	Contains(key Key) (bool, Specification)
	Add(key Key, spec Specification) error
	Remove(key Key) Specification
	RemoveAndClean(key Key) (Specification, error)
}

// ErrNotFound will be returned when trying to remove a capture that has not been marked as active
var ErrNotFound = errors.New("no capture is active")

// ErrDuplicate will be returned when trying to add the same capture twice
var ErrDuplicate = errors.New("an active capture is already in progress")

// ErrNoSpaceLeft will be returned when no free space is detected to start a new capture
var ErrNoSpaceLeft = errors.New("no space left for capture")

// Key represent a unique identifier for the capture
type Key struct {
	WorkloadEndpointId string
	Namespace          string
	CaptureName        string
}

// Specification represent specifics for starting the capture
type Specification struct {
	Version    int
	BPFFilter  string
	DeviceName string
	StartTime  time.Time
	EndTime    time.Time
}

type captureTuple struct {
	Capture
	Specification
}

type activeCaptures struct {
	cache           map[Key]captureTuple
	captureDir      string
	maxSizeBytes    int
	rotationSeconds int
	maxFiles        int
	statusUpdates   chan any
}

func NewActiveCaptures(config Config, statusUpdates chan any) (ActiveCaptures, error) {
	var err = os.MkdirAll(config.Directory, 0755)
	if err != nil {
		return nil, err
	}

	return &activeCaptures{
		cache:           map[Key]captureTuple{},
		captureDir:      config.Directory,
		maxSizeBytes:    config.MaxSizeBytes,
		rotationSeconds: config.RotationSeconds,
		maxFiles:        config.MaxFiles,
		statusUpdates:   statusUpdates,
	}, nil
}

func (activeCaptures activeCaptures) Contains(key Key) (bool, Specification) {
	tuple, ok := activeCaptures.cache[key]
	return ok, tuple.Specification
}

func (activeCaptures *activeCaptures) Add(key Key, spec Specification) error {
	var loggingID = strings.JoinQualifiedName(key.Namespace, key.CaptureName)
	log.WithField("CAPTURE", loggingID).Infof("Adding capture for device name %s for %s", spec.DeviceName, key)

	var err error
	_, ok := activeCaptures.cache[key]
	if ok {
		return ErrDuplicate
	}

	size, err := GetFreeDiskSize(activeCaptures.captureDir)
	if err != nil {
		return err
	}

	// This will check if the free disk capacity can accommodate another capture
	// The free disk capacity is calculated per OS

	// A capture can have at most activeCaptures.maxFiles+1 (max files represents number of rotated files + current file)
	// of size maxSizeBytes
	if size <= uint64((activeCaptures.maxFiles+1)*activeCaptures.maxSizeBytes) {
		markAsError(key.CaptureName, key.Namespace, loggingID, activeCaptures.statusUpdates)
		return ErrNoSpaceLeft
	}

	var _, podName = strings.SplitQualifiedName(key.WorkloadEndpointId)

	var newCapture = NewRotatingPcapFile(activeCaptures.captureDir,
		key.Namespace,
		key.CaptureName,
		podName,
		spec.DeviceName,
		activeCaptures.statusUpdates,
		WithMaxSizeBytes(activeCaptures.maxSizeBytes),
		WithRotationSeconds(activeCaptures.rotationSeconds),
		WithMaxFiles(activeCaptures.maxFiles),
		WithBPFFilter(spec.BPFFilter),
		WithStartTime(spec.StartTime),
		WithEndTime(spec.EndTime),
	)

	go func() {
		log.WithField("CAPTURE", loggingID).Info("Start")
		err = newCapture.Start()
		if err != nil {
			log.WithField("CAPTURE", loggingID).WithError(err).Error("Failed to start capture or capture ended prematurely")
			markAsError(key.CaptureName, key.Namespace, loggingID, activeCaptures.statusUpdates)
		}
	}()

	activeCaptures.cache[key] = captureTuple{newCapture, spec}

	return nil
}

func markAsError(captureName, namespace, loggingID string, statusUpdates chan any) {
	var update = &proto.PacketCaptureStatusUpdate{
		Id:    &proto.PacketCaptureID{Name: captureName, Namespace: namespace},
		State: proto.PacketCaptureStatusUpdate_ERROR,
	}
	log.WithField("CAPTURE", loggingID).Debug("Sending PacketCaptureStatusUpdate to dataplane as Error")
	statusUpdates <- update
}

func (activeCaptures *activeCaptures) Remove(key Key) Specification {
	var loggingID = strings.JoinQualifiedName(key.Namespace, key.CaptureName)
	log.WithField("CAPTURE", loggingID).Infof("Removing capture %s", key)

	capture, ok := activeCaptures.cache[key]
	if !ok {
		return Specification{}
	}
	delete(activeCaptures.cache, key)

	capture.Stop()
	return capture.Specification
}

func (activeCaptures activeCaptures) RemoveAndClean(key Key) (Specification, error) {
	var loggingID = strings.JoinQualifiedName(key.Namespace, key.CaptureName)
	log.WithField("CAPTURE", loggingID).Infof("Removing capture %s and cleaning pcap files", key)

	capture, ok := activeCaptures.cache[key]
	if !ok {
		return Specification{}, ErrNotFound
	}
	delete(activeCaptures.cache, key)

	return capture.Specification, capture.StopAndClean()
}
