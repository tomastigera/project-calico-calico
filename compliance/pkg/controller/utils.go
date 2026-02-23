// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

// Utilities for dealing with Jobs and GlobalReports and time.

func inActiveList(report v3.GlobalReport, uid types.UID) bool {
	for _, j := range report.Status.ActiveReportJobs {
		if j.Job.UID == uid {
			return true
		}
	}
	return false
}

// getReportUIDFromJob extracts UID of job's parent Report and whether it was found
func getReportUIDFromJob(j batchv1.Job) (types.UID, bool) {
	controllerRef := metav1.GetControllerOf(&j)

	if controllerRef == nil {
		log.Debug("No controller ref")
		return types.UID(""), false
	}

	if controllerRef.Kind != controllerKind.Kind {
		log.Debugf("Job with non-%s parent, name %s namespace %s", controllerKind.Kind, j.Name, j.Namespace)
		return types.UID(""), false
	}

	return controllerRef.UID, true
}

// groupJobsByReport groups jobs into a map keyed by the job Report UID.
// It has no receiver, to facilitate testing.
func groupJobsByReport(js []batchv1.Job) map[types.UID][]batchv1.Job {
	jobsByReport := make(map[types.UID][]batchv1.Job)
	for _, job := range js {
		parentUID, found := getReportUIDFromJob(job)
		if !found {
			log.Debugf("Unable to get parent uid from job %s in namespace %s", job.Name, job.Namespace)
			continue
		}
		jobsByReport[parentUID] = append(jobsByReport[parentUID], job)
	}
	return jobsByReport
}

func getFinishedStatus(j *batchv1.Job) (bool, batchv1.JobConditionType) {
	for _, c := range j.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) && c.Status == v1.ConditionTrue {
			return true, c.Type
		}
	}
	return false, ""
}

func int32Pointer(v int32) *int32 {
	return &v
}

// getReportContainer returns the report container from the PodSpec. Note that input and output
// are pointers. If you alter the returned container this will alter the original input.
func getReportContainer(p *v1.PodSpec) *v1.Container {
	var container *v1.Container
	for i := range p.Containers {
		if p.Containers[i].Name == reportContainer {
			container = &p.Containers[i]
			break
		}
	}
	return container
}

// getJobStartEndTime returns the start and end time of the Report job. If it cannot establish one of the times it
// will return nil for both.
func getJobStartEndTime(j *batchv1.Job) (*metav1.Time, *metav1.Time) {
	// The job end time is stored as an environment.
	container := getReportContainer(&j.Spec.Template.Spec)

	// Search the envs.
	var start, end time.Time
	var startFound, endFound bool
	var err error
	for i := range container.Env {
		if container.Env[i].Name == config.ReportStartEnv {
			start, err = time.Parse(time.RFC3339, container.Env[i].Value)
			if err != nil {
				return nil, nil
			}
			startFound = true
		}
		if container.Env[i].Name == config.ReportEndEnv {
			end, err = time.Parse(time.RFC3339, container.Env[i].Value)
			if err != nil {
				return nil, nil
			}
			endFound = true
		}
		if startFound && endFound {
			return &metav1.Time{Time: start}, &metav1.Time{Time: end}
		}
	}
	return nil, nil
}

// byActiveReportEndTime sorts a list of active jobs by report end timestamp.
type byActiveReportEndTime []v3.ReportJob

func (o byActiveReportEndTime) Len() int      { return len(o) }
func (o byActiveReportEndTime) Swap(i, j int) { o[i], o[j] = o[j], o[i] }

func (o byActiveReportEndTime) Less(i, j int) bool {
	if o[i].End.Equal(&o[j].End) {
		return o[i].Job.Name < o[j].Job.Name
	}
	return o[i].End.Before(&o[j].End)
}

// byCompletedReportEndTime sorts a list of active jobs by report end timestamp.
type byCompletedReportEndTime []v3.CompletedReportJob

func (o byCompletedReportEndTime) Len() int      { return len(o) }
func (o byCompletedReportEndTime) Swap(i, j int) { o[i], o[j] = o[j], o[i] }

func (o byCompletedReportEndTime) Less(i, j int) bool {
	if o[i].End.Equal(&o[j].End) {
		return o[i].Job.Name < o[j].Job.Name
	}
	return o[i].End.Before(&o[j].End)
}

// eventRecorder implements the EventRecorder interface but simply logs rather than generating events.
type eventRecorder struct {
	//recorder record.EventRecorder
}

func newEventRecorder(cfg *config.Config, clientSet datastore.ClientSet) *eventRecorder {
	/*TODO: Get event broadcasts working
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(log.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: clientSet.CoreV1().Events(cfg.Namespace)})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "tigera-compliance-controller"})
	*/
	return &eventRecorder{
		//recorder: recorder,
	}
}

func (e *eventRecorder) Event(object runtime.Object, eventtype, reason, message string) {
	if eventtype == v1.EventTypeWarning {
		log.Warnf("[EVENT] %s: %s: %s: %s", eventtype, reason, getSummaryName(object), message)
	} else {
		log.Infof("[EVENT] %s: %s: %s: %s", eventtype, reason, getSummaryName(object), message)
	}
}

func (e *eventRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...any) {
	message := fmt.Sprintf(messageFmt, args...)
	if eventtype == v1.EventTypeWarning {
		log.Warnf("[EVENT] %s: %s: %s: %s", eventtype, reason, getSummaryName(object), message)
	} else {
		log.Infof("[EVENT] %s: %s: %s: %s", eventtype, reason, getSummaryName(object), message)
	}
}

func (e *eventRecorder) PastEventf(object runtime.Object, timestamp metav1.Time, eventtype, reason, messageFmt string, args ...any) {
	e.Eventf(object, eventtype, reason, messageFmt, args...)
}

func (e *eventRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...any) {
	e.Eventf(object, eventtype, reason, messageFmt, args...)
}

func getSummaryName(object runtime.Object) string {
	if r, ok := object.(resources.Resource); ok {
		return resources.GetResourceID(r).String()
	} else {
		return object.GetObjectKind().GroupVersionKind().String()
	}
}
