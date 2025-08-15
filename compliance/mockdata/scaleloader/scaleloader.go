package scaleloader

import (
	"context"
	"fmt"
	"os"
	"time"

	logrus "github.com/sirupsen/logrus"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/lma/pkg/elastic"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/lma/pkg/list"
)

const (
	IndexTimeFormat = "20060102"
)

// filesystem:
//   playbook (scale point, scale by namespace)
//      pod (scale point, scale by pod name)
//        a (steps are churned/cycled through)
//          00-init (might not exist, only used at startup, adds to start list state)
//          01-CRUD (pod change)
//          02-CRUD (pod change)
//          03-CRUD (pod change)
//        b
//      np (steps are cycled through)
//        00-init (might not exist, only done at startup, adds to start list state)
//        01-CRUD
//        02-CRUD
//        03-CRUD

// Config:
// --playbook path,<playbookscale>,<podscale>,<churn per day>

// Scale out playbooks (namespace for each)
// Scale out playbook pods
// Load any starting list state
//  Including loading start state for each playbook, with one for each namespace
// Write snapshot to ES
//
// Select smallest step period from all playbooks
//  smallest-step = <...>
//
// start-time=<something>
// cur-time=start-time
// while cur-time < start-time+1 day:
//   for each playbook
//     if no steps:
//       grab set of pod steps
//       grab set of np steps
//     if playbook.nextsteptime > cur-time:
//       Select random step and run
//   cur-time += smallest-step

type PlaybookCfg struct {
	Name          string `yaml:"name"`
	path          string
	PlaybookScale int `yaml:"playbookscale"`
	instance      int
	PlayScale     int     `yaml:"playscale"`
	ChurnRate     float64 `yaml:"churnrate"`
}

func (pc *PlaybookCfg) String() string {
	return fmt.Sprintf("%s,%s,%d,%d,%f",
		pc.Name,
		pc.path,
		pc.PlaybookScale,
		pc.PlayScale,
		pc.ChurnRate)
}

type scaleloader struct {
	playbooks   []*Playbook
	indexSuffix string
}

func NewScaleLoader(base string, playbookCfg []PlaybookCfg) (*scaleloader, error) {
	sl := scaleloader{}
	for _, pc := range playbookCfg {
		pbs, err := NewPlaybooks(base, pc)
		if err != nil {
			return nil, fmt.Errorf("Failed to load playbook from config %s", pc.String())
		}
		sl.playbooks = append(sl.playbooks, pbs...)
	}

	clustName := os.Getenv("ELASTIC_INDEX_SUFFIX")
	if clustName == "" {
		clustName = lmak8s.DefaultCluster
	}
	sl.indexSuffix = clustName
	return &sl, nil
}

var DatastoreRevision int

func (sl *scaleloader) PopulateES(start time.Time, timeperiod time.Duration, es elastic.Client, store api.ComplianceStore) {
	DatastoreRevision = 100

	initResVer := 50

	sl.writeSnapshot(initResVer, start, store)

	// Initialize minimum timestep to a day
	timeStep := time.Hour * 24
	// Initialize timestamp for each playbook and select the smallest timestep
	for i := range sl.playbooks {
		t := sl.playbooks[i].InitializeTimestep(start)
		if t < timeStep {
			timeStep = t
		}
	}

	end := start.Add(timeperiod)
	logrus.WithFields(logrus.Fields{"time": start, "timestep": timeStep}).Info("Time used for start")
	for curTime := start; curTime.Before(end); curTime = curTime.Add(timeStep) {
		for i := range sl.playbooks {
			if sl.playbooks[i].nextsteptime.After(curTime) {
				sl.writeStep(sl.playbooks[i].GetNextStep(), es, curTime, logrus.WithField("time", curTime))
			}
		}
	}
	logrus.WithField("time", end).Info("Time used for end")
}

func (sl *scaleloader) writeSnapshot(resVer int, snapTime time.Time, store api.ComplianceStore) {
	// If you know how to make this function nicer please do.

	listItems := make(map[metav1.TypeMeta][]runtime.Object)

	for i := range sl.playbooks {
		for j := range sl.playbooks[i].plays {
			for _, item := range sl.playbooks[i].plays[j].init {
				item.namespace = sl.playbooks[i].plays[j].namespace
				item.playInstance = sl.playbooks[i].plays[j].playInstance
				// Update all ResourceVersion fields and all fields with
				// {{.Namespace}}.
				item.UpdateResource(resVer)

				listItems[item.GetTypeMeta()] = append(listItems[item.GetTypeMeta()], item.resource)
			}
		}
	}

	for _, rh := range resources.GetAllResourceHelpers() {
		rl := rh.NewResourceList()
		li := listItems[rh.TypeMeta()]
		err := meta.SetList(rl, li)
		if err != nil {
			logrus.WithFields(logrus.Fields{"error": err, "type": rh.TypeMeta()}).Fatalf("Unable to set list")
		}
		trl := &list.TimestampedResourceList{
			ResourceList:              rl,
			RequestStartedTimestamp:   metav1.Time{Time: snapTime},
			RequestCompletedTimestamp: metav1.Time{Time: snapTime},
		}

		if err := store.StoreList(rh.TypeMeta(), trl); err != nil {
			logrus.WithError(err).Fatalf("Failed to write snapshot for %s/%s", rh.TypeMeta().APIVersion, rh.TypeMeta().Kind)
		}
	}
}

const (
	maxRetriesPerIndex = 10
)

func (sl *scaleloader) writeStep(s Step, es elastic.Client, t time.Time, log *logrus.Entry) {
	msgRev := DatastoreRevision
	logrus.Debugf("Next step %d:%s", msgRev, s.String())
	timestamp := t.Format("2006-01-02T15:04:05.000000Z07:00")
	msg, err := s.GetMsg(msgRev, timestamp)
	DatastoreRevision++
	if err != nil {
		log.WithError(err).Error("Error generating Step msg")
		return
	}
	index := fmt.Sprintf("%s.%s.%s", s.GetIndex(), sl.indexSuffix, t.Format(IndexTimeFormat))
	for r := 0; ; r++ {
		res, err := es.Backend().Index().
			Index(index).
			BodyString(msg).
			Do(context.Background())
		if err == nil {
			log.WithFields(logrus.Fields{"result": res, "Rev": msgRev}).Debug("successfully indexed document")
			return
		}
		if r >= maxRetriesPerIndex {
			log.WithError(err).Fatalf("failed to index document: %s", msg)
		}
		log.WithError(err).Warn("failed to index document - retrying")
		time.Sleep(time.Second)
	}
}
