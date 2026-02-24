// Copyright 2019-2021 Tigera Inc. All rights reserved.

package errorcondition

import (
	"fmt"
	"reflect"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

func TestErrorCondition_AddError(t *testing.T) {
	g := NewGomegaWithT(t)

	globalThreatFeed := &v3.GlobalThreatFeed{}
	AddError(&globalThreatFeed.Status, "testErrType", fmt.Errorf("testErrMessage"))

	g.Expect(len(globalThreatFeed.Status.ErrorConditions)).Should(Equal(1))
	g.Expect(globalThreatFeed.Status.ErrorConditions[0].Type).Should(Equal("testErrType"))
	g.Expect(globalThreatFeed.Status.ErrorConditions[0].Message).Should(Equal("testErrMessage"))
}

func TestErrorCondition_AddErrorOverMaxErrorLimit(t *testing.T) {
	g := NewGomegaWithT(t)

	globalThreatFeed := &v3.GlobalThreatFeed{}
	for i := range MaxErrors + 1 {
		AddError(&globalThreatFeed.Status, fmt.Sprintf("testErrType-%d", i), fmt.Errorf("testErrMessage-%d", i))
	}

	g.Expect(len(globalThreatFeed.Status.ErrorConditions)).Should(Equal(MaxErrors))
	for i := range MaxErrors {
		g.Expect(globalThreatFeed.Status.ErrorConditions[i].Type).Should(Equal(fmt.Sprintf("testErrType-%d", i+1)))
		g.Expect(globalThreatFeed.Status.ErrorConditions[i].Message).Should(Equal(fmt.Sprintf("testErrMessage-%d", i+1)))
	}
}

func TestErrorCondition_ClearError(t *testing.T) {
	g := NewGomegaWithT(t)

	globalThreatFeed := &v3.GlobalThreatFeed{}
	errorConditions := make([]v3.ErrorCondition, 0)
	errorConditions = append(errorConditions,
		v3.ErrorCondition{Type: "testErrType-1", Message: "testErrMessage-1"},
		v3.ErrorCondition{Type: "testErrType-2", Message: "testErrMessage-2"})
	globalThreatFeed.Status.ErrorConditions = errorConditions

	g.Expect(len(globalThreatFeed.Status.ErrorConditions)).Should(Equal(2))

	ClearError(&globalThreatFeed.Status, "testErrType-1")
	g.Expect(len(globalThreatFeed.Status.ErrorConditions)).Should(Equal(1))
	g.Expect(globalThreatFeed.Status.ErrorConditions[0].Type).Should(Equal("testErrType-2"))
	g.Expect(globalThreatFeed.Status.ErrorConditions[0].Message).Should(Equal("testErrMessage-2"))
}

func TestErrorCondition_ClearNonExistentError(t *testing.T) {
	g := NewGomegaWithT(t)

	globalThreatFeed := &v3.GlobalThreatFeed{}
	errorConditions := make([]v3.ErrorCondition, 0)
	errorConditions = append(errorConditions,
		v3.ErrorCondition{Type: "testErrType-1", Message: "testErrMessage-1"},
		v3.ErrorCondition{Type: "testErrType-2", Message: "testErrMessage-2"})
	globalThreatFeed.Status.ErrorConditions = errorConditions

	g.Expect(len(globalThreatFeed.Status.ErrorConditions)).Should(Equal(2))

	ClearError(&globalThreatFeed.Status, "testErrType-3")
	g.Expect(len(globalThreatFeed.Status.ErrorConditions)).Should(Equal(2))
	g.Expect(reflect.DeepEqual(globalThreatFeed.Status.ErrorConditions, errorConditions)).Should(BeTrue())
}
