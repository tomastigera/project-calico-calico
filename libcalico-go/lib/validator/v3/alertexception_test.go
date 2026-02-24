// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package v3

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = DescribeTable("AlertException Validator",
	func(input any, valid bool) {
		if valid {
			Expect(Validate(input)).NotTo(HaveOccurred(),
				"expected value to be valid")
		} else {
			Expect(Validate(input)).To(HaveOccurred(),
				"expected value to be invalid")
		}
	},

	Entry("minimal valid",
		&api.AlertException{
			ObjectMeta: v1.ObjectMeta{Name: "alert-exception"},
			Spec: api.AlertExceptionSpec{
				Description: "alert-exception-desc",
				Selector:    "origin = any",
				StartTime:   v1.Time{Time: time.Now()},
			},
		},
		true,
	),

	Entry("missing description",
		&api.AlertException{
			ObjectMeta: v1.ObjectMeta{Name: "alert-exception"},
			Spec: api.AlertExceptionSpec{
				Selector:  "origin = any",
				StartTime: v1.Time{Time: time.Now()},
			},
		},
		false,
	),

	Entry("missing startTime",
		&api.AlertException{
			ObjectMeta: v1.ObjectMeta{Name: "alert-exception"},
			Spec: api.AlertExceptionSpec{
				Description: "alert-exception-desc",
				Selector:    "origin = any",
			},
		},
		false,
	),

	Entry("missing selector",
		&api.AlertException{
			ObjectMeta: v1.ObjectMeta{Name: "alert-exception"},
			Spec: api.AlertExceptionSpec{
				Description: "alert-exception-desc",
				StartTime:   v1.Time{Time: time.Now()},
			},
		},
		false,
	),
	Entry("non parsable selector",
		&api.AlertException{
			ObjectMeta: v1.ObjectMeta{Name: "alert-exception"},
			Spec: api.AlertExceptionSpec{
				Description: "alert-exception-desc",
				Selector:    "origin = ",
			},
		},
		false,
	),
	Entry("invalid selector key",
		&api.AlertException{
			ObjectMeta: v1.ObjectMeta{Name: "alert-exception"},
			Spec: api.AlertExceptionSpec{
				Description: "alert-exception-desc",
				Selector:    "invalid = any",
			},
		},
		false,
	),

	Entry("valid startTime and endTime",
		&api.AlertException{
			ObjectMeta: v1.ObjectMeta{Name: "alert-exception"},
			Spec: api.AlertExceptionSpec{
				Description: "alert-exception-desc",
				Selector:    "origin = any",
				StartTime:   v1.Time{Time: time.Now()},
				EndTime:     &v1.Time{Time: time.Now().Add(time.Hour)},
			},
		},
		true,
	),
	Entry("invalid endTime before startTime",
		&api.AlertException{
			ObjectMeta: v1.ObjectMeta{Name: "alert-exception"},
			Spec: api.AlertExceptionSpec{
				Description: "alert-exception-desc",
				Selector:    "origin = any",
				StartTime:   v1.Time{Time: time.Now()},
				EndTime:     &v1.Time{Time: time.Now().Add(-time.Hour)},
			},
		},
		false,
	),
)
