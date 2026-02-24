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

/*
I did not use watch or expectations.  Those add a lot of corner cases, and we aren't
expecting a large volume of jobs or scheduledJobs.  (We are favoring correctness
over scalability.  If we find a single controller thread is too slow because
there are a lot of Jobs or Reports, we can parallelize by Namespace.
If we find the load on the API server is too high, we can use a watch and
UndeltaStore.)

Just periodically list jobs and Reports, and then reconcile them.
*/

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/robfig/cron"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/pager"
	"k8s.io/client-go/tools/record"
	ref "k8s.io/client-go/tools/reference"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/compliance/pkg/hashutils"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/jitter"
)

// Utilities for dealing with Jobs and Reports and time.

// controllerKind contains the schema.GroupVersionKind for this controller type.
var controllerKind = schema.GroupVersionKind{
	Kind:    "GlobalReport",
	Version: v3.VersionCurrent,
	Group:   v3.Group,
}

const (
	maxNameLen = 63

	// Event types
	unexpectedJob          = "UnexpectedJob"
	sawFailedJob           = "SawFailedJob"
	sawCompletedJob        = "SawCompletedJob"
	failedDelete           = "FailedDelete"
	successfulDelete       = "SuccessfulDelete"
	failedNeedsStart       = "FailedNeedsStart"
	failedNeedsPodTemplate = "FailedNeedsPodTemplate"
	failedBadPodTemplate   = "FailedBadPodTemplate"
	failedCreate           = "FailedCreate"
	successfulCreate       = "SuccessfulCreate"
)

type ComplianceController struct {
	cfg                 *config.Config
	healthy             func()
	clientSet           datastore.ClientSet
	jobControl          jobControlInterface
	reportControl       reportControlInterface
	podControl          podControlInterface
	archivedReportQuery archivedReportQueryInterface
	podTemplateQuery    podTemplateQueryInterface

	// Only filled out if we know our own namespace and name.
	recorderObj runtime.Object
	recorder    record.EventRecorder
}

func NewComplianceController(
	cfg *config.Config, clientSet datastore.ClientSet, reportRetriever api.ReportRetriever,
	healthy func(),
) (*ComplianceController, error) {
	recorderObj := &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "compliance-controller",
			Namespace: cfg.Namespace,
		},
	}

	recorder := newEventRecorder(cfg, clientSet)
	cc := &ComplianceController{
		cfg:                 cfg,
		healthy:             healthy,
		clientSet:           clientSet,
		jobControl:          &realJobControl{clientSet: clientSet},
		reportControl:       &realReportControl{clientSet: clientSet},
		podControl:          &realPodControl{clientSet: clientSet},
		archivedReportQuery: &realArchivedReportQuery{reportRetriever: reportRetriever},
		podTemplateQuery:    &realPodTemplateQuery{clientSet: clientSet},
		recorderObj:         recorderObj,
		recorder:            recorder,
	}

	return cc, nil
}

// Run the main goroutine responsible for watching and syncing jobs.
func (cc *ComplianceController) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()

	// Indicate healthy.
	cc.healthy()

	log.Infof("Starting Compliance Controller")

	ticker := jitter.NewTicker(cc.cfg.JobPollInterval, cc.cfg.JobPollInterval/10)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cc.syncAll(ctx)
		}
	}
}

// syncAll lists all the Reports and Jobs and reconciles them.
func (cc *ComplianceController) syncAll(ctx context.Context) {
	log.Debug("Perform sync")

	// Indicate we are healthy.
	cc.healthy()

	// List children (Jobs) before parents (Reports).
	// This guarantees that if we see any Job that got orphaned by the GC orphan finalizer,
	// we must also see that the parent job has non-nil DeletionTimestamp (see #42639).
	// Note that this only works because we are NOT using any caches here.
	jobListFunc := func(opts metav1.ListOptions) (runtime.Object, error) {
		return cc.clientSet.BatchV1().Jobs(cc.cfg.Namespace).List(ctx, opts)
	}
	jlTmp, _, err := pager.New(pager.SimplePageFunc(jobListFunc)).List(ctx, metav1.ListOptions{})
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("can't list Jobs: %v", err))
		return
	}
	jl, ok := jlTmp.(*batchv1.JobList)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("expected type *batchv1.JobList, got type %T", jlTmp))
		return
	}
	js := jl.Items
	log.Debugf("Found %d jobs", len(js))

	// Indicate we are healthy.
	cc.healthy()

	reportListFunc := func(opts metav1.ListOptions) (runtime.Object, error) {
		return cc.clientSet.GlobalReports().List(ctx, opts)
	}
	reportlTmp, _, err := pager.New(pager.SimplePageFunc(reportListFunc)).List(ctx, metav1.ListOptions{})
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("can't list Reports: %v", err))
		return
	}
	// Indicate we are healthy.
	cc.healthy()

	reportl, ok := reportlTmp.(*v3.GlobalReportList)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("expected type *v3.GlobalReportList, got type %T", reportlTmp))
		return
	}
	reports := reportl.Items
	log.Debugf("Found %d reports", len(reports))

	// Indicate we are healthy.
	cc.healthy()

	jobsByReport := groupJobsByReport(js)
	log.Debugf("Found %d groups", len(jobsByReport))

	for _, rep := range reports {
		log.Debugf("Processing report: %s", rep.Name)

		// Exit if context indicates.
		if ctx.Err() != nil {
			return
		}

		// Sync one report.
		cc.syncOne(&rep, jobsByReport[rep.UID], time.Now())
	}
}

// syncOne reconciles a Report with a list of any Jobs that it created.
// -  Status is updated from querying jobs and possible the archived report store.
// -  Old failed and successful jobs are deleted as per history requirements.
// -  New jobs are created to fill in missing reports upto max number of concurrent jobs.
func (cc *ComplianceController) syncOne(rep *v3.GlobalReport, js []batchv1.Job, now time.Time) {
	// Update the status from the queried jobs.
	if !cc.updateStatus(rep, js, now) {
		return
	}

	// Indicate we are healthy.
	cc.healthy()

	// Remove the oldest jobs from the successful and the failed set.
	if !cc.removeOldestJobs(rep) {
		return
	}

	// Indicate we are healthy.
	cc.healthy()

	// Start new jobs.
	if !cc.startReportJobs(rep, now) {
		return
	}

	// Indicate we are healthy.
	cc.healthy()
}

// updateStatus reconciles a Report with a list of any Jobs that it created and updates the Report Status.
// This processing is semi-resilient to the Status being deleted in the middle of processing jobs (see inline for
// more info):
//   - The set of active, successful and failed jobs is always determined from querying the jobs. Therefore, jobs
//     deleted by another process will result in the status field losing those jobs on the next poll cycle.
//   - The end time of the last scheduled report job is used to determine what jobs need to be created. If it is
//     deleted, it is repopulated from the archived report storage and the still-configured Jobs (taking the latest
//     of those times).
//
// All known jobs created by "report" should be included in "js".
func (cc *ComplianceController) updateStatus(rep *v3.GlobalReport, js []batchv1.Job, now time.Time) bool {
	// Keep track of the active, successful and failed jobs. We'll simply replace all of these in the Status
	// at the end.
	var active []v3.ReportJob
	var successful []v3.CompletedReportJob
	var failed []v3.CompletedReportJob

	// If we don't have a last scheduled time stored, and we should have scheduled at least one job by now, then we
	// should query the archived store to see if there are any archived entries.
	if rep.Status.LastScheduledReportJob == nil {
		log.Debugf("No last scheduled job recorded for %s", rep.Name)
		// In the event the schedule doesn't parse, don't worry, we'll handle that later by not scheduling anything.
		sched, err := cron.ParseStandard(rep.Spec.Schedule)
		if err == nil && cc.canSchedule(sched.Next(rep.CreationTimestamp.Time), now) {
			// At least one job should have been scheduled by now, query the datastore to check if there are any existing
			// archived reports.
			start, end, err := cc.archivedReportQuery.GetLastReportStartEndTime(rep.Name)
			if err != nil {
				if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
					// Unexpected error from the archived rep store.
					log.Errorf("Unable to query for archived reports %s: %v", rep.Name, err)
					return false
				}
				log.Infof("No archived report data for %s", rep.Name)
			} else {
				log.Infof("Updating the last end time from archived rep %s: %v - %v", rep.Name, start, end)
				rep.Status.LastScheduledReportJob = &v3.ReportJob{
					Start: *start,
					End:   *end,
					Job:   &v1.ObjectReference{},
				}
			}
		}
	}

	// Do our best to track jobs that have changed from Active to Failed or Successful. There are windows where the
	// Status may get deleted at the same time as the job changes state. In these instances the job will not be in
	// our active list and therefore we will not spot the state change, but not a lot we can do here unless we store
	// state somewhere else.
	//
	// We'll also track the last end time of the jobs incase there are jobs with later end times that archived, or
	// stored in the status.
	for _, j := range js {
		start, end := getJobStartEndTime(&j)
		if start == nil || end == nil {
			cc.recorder.Eventf(
				cc.recorderObj, v1.EventTypeWarning, unexpectedJob,
				"Saw a job that the controller did not create: Job(%s/%s)", j.Namespace, j.Name,
			)
			continue
		}
		jref, err := getRef(&j)
		if err != nil {
			cc.recorder.Eventf(
				cc.recorderObj, v1.EventTypeWarning, unexpectedJob,
				"Saw a job that the controller did not create: Job(%s/%s)", j.Namespace, j.Name,
			)
			continue
		}
		finished, status := getFinishedStatus(&j)
		inActiveList := inActiveList(*rep, j.UID)

		job := v3.ReportJob{
			Start: *start,
			End:   *end,
			Job:   jref,
		}

		if (rep.Status.LastScheduledReportJob == nil || rep.Status.LastScheduledReportJob.End.Before(end)) && end.Time.Before(now) {
			// If this job contains the latest end time (and it's not for some reason in the future) then track it
			// to update our status.
			rep.Status.LastScheduledReportJob = &job
		}

		if !finished {
			// The job is not finished, include in our active set.
			log.Debugf("Job active: %s/%s", j.Namespace, j.Name)
			active = append(active, job)
		} else if status == batchv1.JobFailed {
			// The job failed, include in our failed set.
			log.Debugf("Job failed: %s/%s", j.Namespace, j.Name)
			failed = append(failed, v3.CompletedReportJob{
				ReportJob:         job,
				JobCompletionTime: j.Status.CompletionTime,
			})

			// If previously in active list then record an event.
			if inActiveList {
				log.Debugf("Job was previously active and has now failed: %s/%s", j.Namespace, j.Name)
				cc.recorder.Eventf(
					cc.recorderObj, v1.EventTypeWarning, sawFailedJob,
					"Saw failed job: Job(%s/%s)", j.Namespace, j.Name,
				)
			}
		} else {
			// The job completed, include in our successful set.
			log.Debugf("Job successful: %s/%s", j.Namespace, j.Name)
			successful = append(successful, v3.CompletedReportJob{
				ReportJob:         job,
				JobCompletionTime: j.Status.CompletionTime,
			})
			// If previously in active list then record an event.
			if inActiveList {
				log.Debugf("Job was previously active and has now completed successfully: %s/%s", j.Namespace, j.Name)
				cc.recorder.Eventf(
					cc.recorderObj, v1.EventTypeNormal, sawCompletedJob,
					"Saw completed job: Job(%s/%s)", j.Namespace, j.Name,
				)
			}
		}
	}

	// Sort the jobs by end time.
	sort.Sort(byActiveReportEndTime(active))
	sort.Sort(byCompletedReportEndTime(successful))
	sort.Sort(byCompletedReportEndTime(failed))

	// Replace the job statuses with the latest found data.
	rep.Status.ActiveReportJobs = active
	rep.Status.LastSuccessfulReportJobs = successful
	rep.Status.LastFailedReportJobs = failed

	// Update the status.
	updatedReport, err := cc.reportControl.UpdateStatus(rep)
	if err != nil {
		log.Errorf("Unable to update status for %s (rv = %s): %v", rep.Name, rep.ResourceVersion, err)
		return false
	}
	*rep = *updatedReport

	return true
}

// removeOldestJobs deletes the oldest jobs from the successful and failed set.
// Note that this uses the values currently configured in the status, so these values should have first been updated
// and sorted by updateStatus.
func (cc *ComplianceController) removeOldestJobs(rep *v3.GlobalReport) bool {
	log.Debugf("Removing oldest jobs for %s", rep.Name)

	// Track which jobs we need to delete.
	var jobsToDelete []v3.ReportJob

	// Start with the succesful jobs.
	numSuccessfulToDelete := len(rep.Status.LastSuccessfulReportJobs) - cc.cfg.MaxSuccessfulJobsHistory
	if numSuccessfulToDelete > 0 {
		for i := range numSuccessfulToDelete {
			jobsToDelete = append(jobsToDelete, rep.Status.LastSuccessfulReportJobs[i].ReportJob)
		}
		rep.Status.LastSuccessfulReportJobs = rep.Status.LastSuccessfulReportJobs[numSuccessfulToDelete:]
	}

	// Now the failed jobs.
	numFailedToDelete := len(rep.Status.LastFailedReportJobs) - cc.cfg.MaxFailedJobsHistory
	if numFailedToDelete > 0 {
		for i := range numFailedToDelete {
			jobsToDelete = append(jobsToDelete, rep.Status.LastFailedReportJobs[i].ReportJob)
		}
		rep.Status.LastFailedReportJobs = rep.Status.LastFailedReportJobs[numFailedToDelete:]
	}

	// Delete the old jobs.
	for _, j := range jobsToDelete {
		if err := cc.jobControl.DeleteJob(j.Job.Namespace, j.Job.Name); err != nil {
			log.WithError(err).Debugf("Error deleting job %s/%s: %v", j.Job.Namespace, j.Job.Name, err)
			cc.recorder.Eventf(
				cc.recorderObj, v1.EventTypeWarning, failedDelete,
				"Failed to delete job: Job(%s/%s): %v", j.Job.Namespace, j.Job.Name, err,
			)
		} else {
			log.Debugf("Deleted job %s/%s", j.Job.Namespace, j.Job.Name)
			cc.recorder.Eventf(
				cc.recorderObj, v1.EventTypeNormal, successfulDelete,
				"Deleted job: Job(%s/%s)", j.Job.Namespace, j.Job.Name,
			)
		}
	}

	// Update the status. Note that in the event of us not managing to delete a job then we'll be deleting an entry from
	// the status that still exists. This does not matter, it will right itself next iteration.
	updatedReport, err := cc.reportControl.UpdateStatus(rep)
	if err != nil {
		log.Warnf("Unable to update status for %s (rv = %s): %v", rep.Name, rep.ResourceVersion, err)
		return false
	}
	*rep = *updatedReport
	return true
}

// startReportJobs checks to see which report schedules have not yet been met, and schedules jobs for them.
// It uses the status information in the report to determine which reports need to be generated. The controller
// is configured with the maximum number of active jobs allowed for a specific report - this value is common across
// all reports.
func (cc *ComplianceController) startReportJobs(rep *v3.GlobalReport, now time.Time) bool {
	if rep.DeletionTimestamp != nil {
		// The Report is being deleted.
		log.Debugf("Not starting job for %s because it is being deleted", rep.Name)
		return false
	}

	if rep.Spec.Suspend != nil && *rep.Spec.Suspend {
		log.Debugf("Not starting job for %s because it is suspended", rep.Name)
		return false
	}

	if rep.Spec.Schedule == "" {
		log.Debugf("Not starting job for %s because no schedule has been specified", rep.Name)
		return false
	}

	// Get a list of the jobs that we need to start. This method returns a max number of jobs based on our configuration.
	jobTimes, err := cc.getRecentUnmetScheduleTimes(*rep, now, cc.reportControl)
	if err != nil {
		log.Infof("Cannot determine if report jobs %s need to be started: %v", rep.Name, err)
		cc.recorder.Eventf(
			cc.recorderObj, v1.EventTypeWarning, failedNeedsStart,
			"Cannot determine if rep jobs for GlobalReport(%s) need to be started: %v", rep.Name, err,
		)
		return false
	}

	if len(jobTimes) == 0 {
		log.Debugf("No unmet start times, or too many active jobs for %s", rep.Name)
		return false
	}

	pt, err := cc.podTemplateQuery.GetPodTemplate(cc.cfg.Namespace, rep.Name)
	if err != nil {
		log.Errorf("Unable to locate pod template in %s: %v", rep.Name, err)
		cc.recorder.Eventf(
			cc.recorderObj, v1.EventTypeWarning, failedNeedsPodTemplate,
			"Cannot locate valid PodTemplate for GlobalReport(%s): %v", rep.Name, err,
		)
		return false
	}

	// We expect there to be a container in the pod spec called "reporter". Locate it and add the additional rep
	// specific environment variables. The pod template should otherwise have all of the required configuration.
	container := getReportContainer(&pt.Template.Spec)
	if container == nil {
		log.Errorf("Unable to locate reporter container in pod template in %s: %v", rep.Name, err)
		cc.recorder.Eventf(
			cc.recorderObj, v1.EventTypeWarning, failedBadPodTemplate,
			"Cannot locate %s container in PodTemplate for GlobalReport(%s): %v", reportContainer, rep.Name, err,
		)
		return false
	}

	for _, jobTime := range jobTimes {
		jobReq := cc.getJobFromTemplate(rep, jobTime, pt)

		// ------------------------------------------------------------------ //
		// When we re-list the Reports and Jobs on the next sync iteration we might not see the job we just created
		// (distributed systems and all that). However, we use the job name as a lock to prevent us making the same
		// job twice.

		jobResp, err := cc.jobControl.CreateJob(cc.cfg.Namespace, jobReq)
		if err != nil {
			if !errors.IsAlreadyExists(err) {
				log.Warnf("Failed to create job: %v", err)
				cc.recorder.Eventf(
					cc.recorderObj, v1.EventTypeWarning, failedCreate,
					"Error creating job for GlobalReport(%s): %v", rep.Name, err,
				)
				return false
			}

			// The job already exists. We can't update the status just yet, so just continue. We'll update the status
			// as soon as we are able to view the job.
			log.Debugf("Job already exists for %s", rep.Name)
			continue
		} else {
			log.Debugf("Created Job %s for %s", jobResp.Name, rep.Name)
			cc.recorder.Eventf(
				cc.recorderObj, v1.EventTypeNormal, successfulCreate,
				"Created job: Job(%s/%s)", jobResp.Namespace, jobResp.Name,
			)
		}

		// Add the just-started job to the status list.
		jref, err := getRef(jobResp)
		if err != nil {
			log.Debugf("Unable to make object reference for job for %s", rep.Name)
			continue
		}
		job := v3.ReportJob{
			Start: metav1.Time{Time: jobTime.Start},
			End:   metav1.Time{Time: jobTime.End},
			Job:   jref,
		}
		rep.Status.ActiveReportJobs = append(rep.Status.ActiveReportJobs, job)
		rep.Status.LastScheduledReportJob = &job

		if _, err := cc.reportControl.UpdateStatus(rep); err != nil {
			log.Debugf("Unable to update status for %s (rv = %s): %v", rep.Name, rep.ResourceVersion, err)
			return false
		}
	}

	return true
}

// getRecentUnmetScheduleTimes gets a slice of times (from oldest to latest) that have passed when a Job should have
// started but did not.
//
// If the unstarted jobs goes too far back in time, we cap the last report end time at configurable time in the past
// from the current time.
//
// If there were missed times prior to the last known start time, then those are not returned.
func (cc *ComplianceController) getRecentUnmetScheduleTimes(rep v3.GlobalReport, now time.Time, reportc reportControlInterface) ([]ReportJobTimes, error) {
	// Determine the jobs that we need to start. Since we only want a set number of active jobs at any one time
	// we need to cap this set of jobs that should be started.
	maxJobs := cc.cfg.MaxActiveJobs - len(rep.Status.ActiveReportJobs)
	log.Debugf("Maximum jobs we are able to schedule for %s: %d", rep.Name, maxJobs)
	if maxJobs <= 0 {
		return nil, nil
	}

	// Parse the schedule.
	sched, err := cron.ParseStandard(rep.Spec.Schedule)
	if err != nil {
		log.Debugf("Maximum jobs we are able to schedule for %s: %d", rep.Name, maxJobs)
		return nil, fmt.Errorf("unparseable schedule: %s : %s", rep.Spec.Schedule, err)
	}

	// Check the active, failed and successful jobs to find the one with the latest end time.
	var latestEndTime time.Time
	if rep.Status.LastScheduledReportJob != nil {
		latestEndTime = rep.Status.LastScheduledReportJob.End.Time
		log.Debugf("Using recorded last scheduled jobs time in %s: %v", rep.Name, latestEndTime)
	} else {
		// If none found, then this is either a recently created Report,
		// or the active/completed info was somehow lost (contract for status
		// in kubernetes says it may need to be recreated), or that we have
		// started a job, but have not noticed it yet (distributed systems can
		// have arbitrary delays).  In any case, use the creation time of the
		// GlobalReport as last known rep end time.  If we need to schedule a rep
		// generation then first check the archived rep store to see if it's already created.
		latestEndTime = rep.CreationTimestamp.Time
		log.Debugf("Using creation time of %s: %v", rep.Name, latestEndTime)
	}

	// If the latestEndTime is before the IgnoreUnstartedReportAfter from now then only go as far back as the
	// IgnoreUnstartedReportAfter.
	furthestBackEndTime := now.Add(-cc.cfg.IgnoreUnstartedReportAfter)
	if latestEndTime.Before(furthestBackEndTime) {
		log.Debugf("The last scheduled job for %s had an end time outside the range "+
			"for catch-up - skipping some reports", rep.Name)
		latestEndTime = sched.Next(furthestBackEndTime)
	}

	// Return the next set of jobs that should be started.
	var jobTimes []ReportJobTimes
	for endTime := sched.Next(latestEndTime); cc.canSchedule(endTime, now) && len(jobTimes) < maxJobs; endTime = sched.Next(endTime) {
		jobTimes = append(jobTimes, ReportJobTimes{
			Start: latestEndTime,
			End:   endTime,
		})
		latestEndTime = endTime
	}
	return jobTimes, nil
}

// Create a Job from the Pod template. The Job itself is not configurable.
func (cc *ComplianceController) getJobFromTemplate(rep *v3.GlobalReport, jt ReportJobTimes, pt *v1.PodTemplate) *batchv1.Job {
	// Deep copy the pod template so that we can use it without fear of it altering the one passed in.
	pt = pt.DeepCopy()

	// Name the pod deterministically to prevent duplicate runs. We use the end time of the rep for this since that
	// is what determines the scheduling.
	name := getJobName(cc.cfg.JobNamePrefix, rep.Name, jt.End)

	// Create the pod template for the Job from the stored pod template.
	template := v1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      pt.Template.Labels,
			Annotations: pt.Template.Annotations,
		},
		Spec: pt.Template.Spec,
	}

	// We expect there to be a container in the pod spec called "reporter". Locate it and add the additional report
	// specific environment variables. The pod template should otherwise have all of the required configuration. Note
	// that we have already checked the pod template has the correct container.
	container := getReportContainer(&template.Spec)
	container.Env = append(container.Env, []v1.EnvVar{
		{
			Name:  config.ReportNameEnv,
			Value: rep.Name,
		},
		{
			Name:  config.ReportStartEnv,
			Value: jt.Start.Format(time.RFC3339),
		},
		{
			Name:  config.ReportEndEnv,
			Value: jt.End.Format(time.RFC3339),
		},
	}...)

	// Make sure the restart policy is either Never or OnFailure. The pod restart policy tells Kubernetes when (if ever)
	// to restart a pod that has completed or failed. The report jobs are designed to be single shot, and by default we
	// use the job retry mechanism to retry a failed pod (which uses exponential back off timer and limits the number
	// of retries). We make it possible to also use the pod restart mechanism through modification of the pod template -
	// however pod restart has no retry limit so will retry forever if it is inherently broken. We therefore allow the
	// restart policy to be modified, but do not allow it to be set to RestartPolicyAlways because we do not want to
	// retry a successful job.
	if template.Spec.RestartPolicy != v1.RestartPolicyNever && template.Spec.RestartPolicy != v1.RestartPolicyOnFailure {
		template.Spec.RestartPolicy = v1.RestartPolicyNever
	}

	// Template could have an empty NodeSelector
	if template.Spec.NodeSelector == nil {
		template.Spec.NodeSelector = map[string]string{}
	}

	// Set the node selector if the node selection is not specified in the template.
	if template.Spec.NodeName == "" {
		for k, v := range rep.Spec.JobNodeSelector {
			// Check if the key already exists in the PodTemplate.
			if templateV, exists := template.Spec.NodeSelector[k]; exists {
				log.WithFields(log.Fields{"key": k, "templateValue": templateV, "reportValue": v}).Debug("key already exists in template - using value in template")
				continue
			}

			template.Spec.NodeSelector[k] = v
		}
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       cc.cfg.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rep, controllerKind)},
		},
		Spec: batchv1.JobSpec{
			// Each rep job should only have a single pod running since the work is not parallelized, and the job
			// is complete when that one pod is complete.
			Parallelism: int32Pointer(1),
			Completions: int32Pointer(1),

			// Set the number of restarts.
			BackoffLimit: int32Pointer(cc.cfg.MaxJobRetries),

			// The Pod spec. Note that the rep pod should have it's own keep alive to ensure it hasn't got stuck.
			// This seems preferable to guessing an active deadline time.
			Template: template,
		},
	}

	return job
}

// canSchedule returns true if the current time is at least JobStartDelay after ReportEnd.
func (cc *ComplianceController) canSchedule(reportEndTime, now time.Time) bool {
	return now.After(reportEndTime.Add(cc.cfg.JobStartDelay))
}

func getRef(object runtime.Object) (*v1.ObjectReference, error) {
	return ref.GetReference(scheme.Scheme, object)
}

type ReportJobTimes struct {
	Start time.Time
	End   time.Time
}

// Create a job name from the global report. The name should be deterministic because the name is used as
// a lock to prevent multiple identical jobs from being created at the same time.
func getJobName(prefix, report string, endTime time.Time) string {
	return hashutils.GetLengthLimitedName(fmt.Sprintf("%s%s-%d", prefix, report, endTime.Unix()), maxNameLen)
}
