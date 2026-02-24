// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

package calc

import (
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/utils/strings"

	"github.com/projectcalico/calico/felix/calc/capture"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/multidict"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	sel "github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// PacketCaptureCalculator will match local workload endpoints against a packet capture resource
// by matching labels with the packet capture selector
type PacketCaptureCalculator struct {
	// Cache all packet captures
	allPacketCaptures map[model.ResourceKey]*v3.PacketCapture

	// Cache matching between a packet capture and workload endpoints
	packetCapturesToWorkloadEndpoints multidict.Multidict[any, any]

	// Label index, matching packet capture selectors against local endpoints.
	labelIndex *labelindex.InheritIndex

	// Packet Capture Callback to output the start/stop commands
	packetCaptureCallbacks
}

// NewPacketCaptureCalculator creates a new PacketCalculator with a given set of callback
// The callbacks will be used to inform when a match started/stop for a local endpoint
func NewPacketCaptureCalculator(callbacks packetCaptureCallbacks) *PacketCaptureCalculator {
	pcc := &PacketCaptureCalculator{}
	pcc.allPacketCaptures = make(map[model.ResourceKey]*v3.PacketCapture)
	pcc.packetCapturesToWorkloadEndpoints = multidict.New[any, any]()
	pcc.labelIndex = labelindex.NewInheritIndex(pcc.onMatchStarted, pcc.onMatchStopped)
	pcc.packetCaptureCallbacks = callbacks
	return pcc
}

func (pcc *PacketCaptureCalculator) onMatchStarted(selID, labelId any) {
	log.WithField("CAPTURE", selID).Infof("Start matching %v to packet capture", labelId)
	var pc = pcc.allPacketCaptures[selID.(model.ResourceKey)]
	var specification = pcc.extractSpecification(pc)
	pcc.packetCapturesToWorkloadEndpoints.Put(selID, labelId)
	pcc.OnPacketCaptureActive(selID.(model.ResourceKey), labelId.(model.WorkloadEndpointKey), specification)
}

func (pcc *PacketCaptureCalculator) extractSpecification(pc *v3.PacketCapture) PacketCaptureSpecification {
	return PacketCaptureSpecification{
		BPFFilter: RenderBPFFilter(pc.Spec.Filters, strings.JoinQualifiedName(pc.Namespace, pc.Name)),
		StartTime: capture.RenderStartTime(pc.Spec.StartTime),
		EndTime:   capture.RenderEndTime(pc.Spec.EndTime),
	}
}

func (pcc *PacketCaptureCalculator) onMatchStopped(selID, labelId any) {
	captureKey := selID.(model.ResourceKey)
	log.WithField("CAPTURE", selID).Debugf("Stop matching %v to packet capture", labelId)
	pcc.packetCapturesToWorkloadEndpoints.Discard(selID, labelId)
	pcc.OnPacketCaptureInactive(captureKey, labelId.(model.WorkloadEndpointKey))
}

func (pcc *PacketCaptureCalculator) RegisterWith(localEndpointDispatcher, allUpdDispatcher *dispatcher.Dispatcher) {
	// It needs local workload endpoints
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, pcc.OnUpdate)

	// and profiles and packet captures.
	allUpdDispatcher.Register(model.ResourceKey{}, pcc.OnUpdate)
}

func (pcc *PacketCaptureCalculator) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		// updating index labels and matching selectors
		pcc.labelIndex.OnUpdate(update)
	case model.ResourceKey:
		switch key.Kind {
		case v3.KindProfile:
			// updating index labels and matching selectors
			pcc.labelIndex.OnUpdate(update)
		case v3.KindPacketCapture:
			if update.Value != nil {
				old, found := pcc.allPacketCaptures[key]
				if found && reflect.DeepEqual(old, update.Value.(*v3.PacketCapture)) {
					log.WithField("CAPTURE", update.Key).Debug("No-op policy change; ignoring.")
					return
				}

				pcc.updatePacketCapture(update.Value.(*v3.PacketCapture), key, old)
			} else {
				pcc.deletePacketCapture(key)
			}
		default:
			// Ignore other kinds of v3 resource.
		}
	default:
		log.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}

	return
}

func (pcc *PacketCaptureCalculator) updatePacketCapture(capture *v3.PacketCapture, key model.ResourceKey, previousValue *v3.PacketCapture) {
	sel := pcc.parseSelector(capture)
	// add/update the packet capture value
	pcc.allPacketCaptures[key] = capture
	// update selector index and start matching against workload endpoints
	pcc.labelIndex.UpdateSelector(key, sel)
	// if other fields (than the selector) have been updated
	// we need to propagate the update to the data plane
	if pcc.hasOtherFieldsUpdated(previousValue, capture) {
		pcc.packetCapturesToWorkloadEndpoints.Iter(key, func(wep any) {
			pcc.OnPacketCaptureActive(key, wep.(model.WorkloadEndpointKey), pcc.extractSpecification(capture))
		})
	}
}

func (pcc *PacketCaptureCalculator) hasOtherFieldsUpdated(old *v3.PacketCapture, new *v3.PacketCapture) bool {
	if old != nil {
		if !reflect.DeepEqual(old.Spec.Filters, new.Spec.Filters) {
			return true
		}
		if !reflect.DeepEqual(old.Spec.StartTime, new.Spec.StartTime) {
			return true
		}
		if !reflect.DeepEqual(old.Spec.EndTime, new.Spec.EndTime) {
			return true
		}
	}
	return false
}

func (pcc *PacketCaptureCalculator) parseSelector(capture *v3.PacketCapture) *sel.Selector {
	// update the selector with the namespace selector
	var updatedSelector = fmt.Sprintf("(%s) && (%s == '%s')", capture.Spec.Selector, v3.LabelNamespace, capture.Namespace)
	sel, err := sel.Parse(updatedSelector)
	if err != nil {
		log.WithError(err).Panic("Failed to parse selector")
	}
	return sel
}

func (pcc *PacketCaptureCalculator) deletePacketCapture(key model.ResourceKey) {
	// delete all traces of the packet resource
	delete(pcc.allPacketCaptures, key)
	// delete selector index and stop matching against workload endpoints
	pcc.labelIndex.DeleteSelector(key)
}
