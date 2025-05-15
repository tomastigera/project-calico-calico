// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

package calc_test

import (
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/calc/capture"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var Wep1Key = model.WorkloadEndpointKey{WorkloadID: "wep1"}
var Wep2Key = model.WorkloadEndpointKey{WorkloadID: "wep2"}
var WepWithProfileKey = model.WorkloadEndpointKey{WorkloadID: "wep-profile"}
var Wep1Value = &model.WorkloadEndpoint{
	Name: "wep1",
	Labels: uniquelabels.Make(map[string]string{
		"label":                       "a",
		"projectcalico.org/namespace": "default",
	}),
}
var Wep1UpdatedValue = &model.WorkloadEndpoint{
	Name: "wep1",
	Labels: uniquelabels.Make(map[string]string{
		"label":                       "c",
		"projectcalico.org/namespace": "default",
	}),
}
var Wep2Value = &model.WorkloadEndpoint{
	Name: "wep2",
	Labels: uniquelabels.Make(map[string]string{
		"label":                       "b",
		"projectcalico.org/namespace": "default",
	}),
}
var WepWithProfileValue = &model.WorkloadEndpoint{
	Name: "wep-profile",
	Labels: uniquelabels.Make(map[string]string{
		"projectcalico.org/namespace": "default",
	}),
	ProfileIDs: []string{"profile-dev"},
}

var ProfileDevKey = model.ResourceKey{Kind: v3.KindProfile, Name: "profile-dev"}
var ProfileDevValue = &v3.Profile{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindProfile,
	},
	ObjectMeta: metav1.ObjectMeta{
		Name: "profile-dev",
	},
	Spec: v3.ProfileSpec{
		LabelsToApply: map[string]string{"profile": "dev"},
	},
}

var CaptureAllKey = model.ResourceKey{Name: "packet-capture-all", Namespace: "default", Kind: v3.KindPacketCapture}
var CaptureSelectionKey = model.ResourceKey{Name: "packet-capture-selection", Namespace: "default", Kind: v3.KindPacketCapture}
var CaptureDevKey = model.ResourceKey{Name: "packet-capture-dev", Namespace: "default", Kind: v3.KindPacketCapture}
var CaptureDifferentNamespaceKey = model.ResourceKey{Name: "packet-capture-different-namespace", Namespace: "different", Kind: v3.KindPacketCapture}
var CaptureBPFFilterKey = model.ResourceKey{Name: "packet-capture-bpf-filter", Namespace: "default", Kind: v3.KindPacketCapture}
var CaptureStartStopKey = model.ResourceKey{Name: "packet-capture-start-stop", Namespace: "default", Kind: v3.KindPacketCapture}
var CaptureAllValue = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "packet-capture-all",
	},
	Spec: v3.PacketCaptureSpec{
		Selector: "all()",
	},
}
var CaptureSelectAValue = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "packet-capture-selection",
	},
	Spec: v3.PacketCaptureSpec{
		Selector: "label == 'a'",
	},
}
var CaptureSelectBValue = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "packet-capture-selection",
	},
	Spec: v3.PacketCaptureSpec{
		Selector: "label == 'b'",
	},
}
var CaptureSelectDevValue = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "packet-capture-dev",
	},
	Spec: v3.PacketCaptureSpec{
		Selector: "profile == 'dev'",
	},
}
var CaptureDifferentNamespaceValue = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "different",
		Name:      "packet-capture-different-namespace",
	},
	Spec: v3.PacketCaptureSpec{
		Selector: "all()",
	},
}
var tcpProtocol = numorstring.ProtocolFromString("TCP")
var udpProtocol = numorstring.ProtocolFromString("UDP")

var CaptureTCPTrafficValue = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "packet-capture-bpf-filter",
	},
	Spec: v3.PacketCaptureSpec{
		Selector: "all()",
		Filters: []v3.PacketCaptureRule{
			{
				Protocol: &tcpProtocol,
			},
		},
	},
}

var CaptureUDPTrafficValue = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "packet-capture-bpf-filter",
	},
	Spec: v3.PacketCaptureSpec{
		Selector: "all()",
		Filters: []v3.PacketCaptureRule{
			{
				Protocol: &udpProtocol,
			},
		},
	},
}

var CaptureUDPTrafficValueAndLabelB = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "packet-capture-bpf-filter",
	},
	Spec: v3.PacketCaptureSpec{
		Selector: "label == 'b'",
		Filters: []v3.PacketCaptureRule{
			{
				Protocol: &udpProtocol,
			},
		},
	},
}

var startTime = metav1.NewTime(time.Unix(0, 0))
var updatedStartTime = metav1.NewTime(time.Unix(1, 0))
var endTime = metav1.NewTime(time.Unix(100, 0))
var updatedEndTime = metav1.NewTime(time.Unix(101, 0))

var CaptureStartStopValue = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "packet-capture-start-stop",
	},
	Spec: v3.PacketCaptureSpec{
		Selector:  "all()",
		StartTime: &startTime,
		EndTime:   &endTime,
	},
}

var CaptureUpdatedStart = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "packet-capture-start-stop",
	},
	Spec: v3.PacketCaptureSpec{
		Selector:  "all()",
		StartTime: &updatedStartTime,
		EndTime:   &endTime,
	},
}

var CaptureUpdatedEnd = &v3.PacketCapture{
	TypeMeta: metav1.TypeMeta{
		Kind: v3.KindPacketCapture,
	},
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "packet-capture-start-stop",
	},
	Spec: v3.PacketCaptureSpec{
		Selector:  "all()",
		StartTime: &startTime,
		EndTime:   &updatedEndTime,
	},
}

var EmptySpecification = calc.PacketCaptureSpecification{
	BPFFilter: "",
	StartTime: capture.MinTime,
	EndTime:   capture.MaxTime,
}

var StartStopSpecification = calc.PacketCaptureSpecification{
	BPFFilter: "",
	StartTime: time.Unix(0, 0),
	EndTime:   time.Unix(100, 0),
}

var UpdatedStartSpecification = calc.PacketCaptureSpecification{
	BPFFilter: "",
	StartTime: time.Unix(1, 0),
	EndTime:   time.Unix(100, 0),
}

var UpdatedEndSpecification = calc.PacketCaptureSpecification{
	BPFFilter: "",
	StartTime: time.Unix(0, 0),
	EndTime:   time.Unix(101, 0),
}
