// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

package commands

import (
	"fmt"
	"maps"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/felixsyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// Restructuring like this should also be useful for a permanently running webserver variant too.
func NewEvalCmd(configFile string) (cbs *EvalCmd) {
	disp := dispatcher.NewDispatcher()
	cbs = &EvalCmd{
		configFile: configFile,
		dispatcher: disp,
		done:       make(chan bool),
		matches:    make(map[any][]string),
		rcc:        NewRemoteClusterHandler(),
		lock:       sync.Mutex{},
	}
	cbs.index = labelindex.NewInheritIndex(cbs.onMatchStarted, cbs.onMatchStopped)
	return cbs
}

func (cbs *EvalCmd) AddSelector(selectorName string, selectorExpression string) {
	if selectorExpression == "" {
		return
	}
	parsedSel, err := selector.Parse(selectorExpression)
	if err != nil {
		fmt.Printf("Invalid selector: %#v. %v.\n", selectorExpression, err)
		os.Exit(1)
	}

	if cbs.showSelectors {
		selectorName = fmt.Sprintf("%v; selector \"%v\"", selectorName, selectorExpression)
	}

	cbs.index.UpdateSelector(selectorName, parsedSel)
}

func (cbs *EvalCmd) AddPolicyRuleSelectors(policy *model.Policy, prefix string) {
	for direction, ruleSet := range map[string][]model.Rule{
		"inbound":  policy.InboundRules,
		"outbound": policy.OutboundRules,
	} {
		for i, rule := range ruleSet {
			cbs.AddSelector(fmt.Sprintf("%v%v rule %v source match", prefix, direction, i+1), rule.SrcSelector)
			cbs.AddSelector(fmt.Sprintf("%v%v rule %v destination match", prefix, direction, i+1), rule.DstSelector)
			cbs.AddSelector(fmt.Sprintf("%v%v rule %v !source match", prefix, direction, i+1), rule.NotSrcSelector)
			cbs.AddSelector(fmt.Sprintf("%v%v rule %v !destination match", prefix, direction, i+1), rule.NotDstSelector)
		}
	}
}

// Call this once you've AddSelector'ed the selectors you want to add.
// We'll always do checkValid, but allow insertion of an additional EP filter.
func (cbs *EvalCmd) Start(endpointFilter dispatcher.UpdateHandler) {
	checkValid := func(update api.Update) (filterOut bool) {
		if update.Value == nil {
			fmt.Printf("WARNING: failed to parse value of key %v; "+
				"ignoring.\n\n\n", update)
			return true
		}
		return false
	}

	cbs.dispatcher.Register(model.WorkloadEndpointKey{}, checkValid)
	cbs.dispatcher.Register(model.HostEndpointKey{}, checkValid)

	cbs.dispatcher.Register(model.WorkloadEndpointKey{}, endpointFilter)
	cbs.dispatcher.Register(model.HostEndpointKey{}, endpointFilter)

	cbs.dispatcher.Register(model.WorkloadEndpointKey{}, cbs.OnUpdate)
	cbs.dispatcher.Register(model.HostEndpointKey{}, cbs.OnUpdate)
	cbs.dispatcher.Register(model.ResourceKey{}, cbs.OnUpdate)
	cbs.dispatcher.Register(model.RemoteClusterStatusKey{}, cbs.rcc.OnUpdate)

	bclient, cfg := GetClient(cbs.configFile)
	syncer := felixsyncer.New(bclient, cfg.Spec, cbs, false, true)
	syncer.Start()
}

// For the final version of this we probably will want to be able to call AddSelector()
// while everything's running and join this function into that so you make the call and
// then a little bit later it returns the results.
// Ideally it probably wouldn't even have an AddSelector(), and this could just be accomplished
// with some custom filter functions on a single dispatcher.
// However solving that now would be more effort, so for this version everything must be
// added before Start()ing.
// Returns a map from endpoint key (model.Host/WorkloadEndpointKey) to a list of strings containing the
// names of the selectors that matched them.
func (cbs *EvalCmd) GetMatches() map[any][]string {
	<-cbs.done
	cbs.lock.Lock()
	// Copy the matches so they don't get updated while the caller is iterating through them
	matchesCopy := make(map[any][]string)
	maps.Copy(matchesCopy, cbs.matches)
	defer cbs.lock.Unlock()
	return matchesCopy
}

type EvalCmd struct {
	showSelectors bool
	configFile    string
	dispatcher    *dispatcher.Dispatcher
	index         *labelindex.InheritIndex
	matches       map[any][]string
	lock          sync.Mutex // Protect index and matches

	// Remote cluster handler is used to output errors associated with failures to connect to a configured
	// remote cluster.
	rcc *remoteClusterHandler

	done chan bool
}

func (cbs *EvalCmd) OnConfigLoaded(globalConfig map[string]string,
	hostConfig map[string]string) {
	// Ignore for now
}

func (cbs *EvalCmd) OnStatusUpdated(status api.SyncStatus) {
	if status == api.InSync {
		log.Info("Datamodel in sync, we're done.")
		cbs.done <- true
	}
}

func (cbs *EvalCmd) OnKeysUpdated(updates []api.Update) {
	log.Info("Update: ", updates)
	for _, update := range updates {
		// Also removed empty key handling: don't understand it.
		cbs.dispatcher.OnUpdate(update)
	}
}

func (cbs *EvalCmd) OnUpdate(update api.Update) (filterOut bool) {
	if update.Value == nil {
		return true
	}
	cbs.lock.Lock()
	defer cbs.lock.Unlock()
	switch k := update.Key.(type) {
	case model.WorkloadEndpointKey:
		v := update.Value.(*model.WorkloadEndpoint)
		cbs.index.UpdateLabels(update.Key, v.Labels, v.ProfileIDs)
	case model.HostEndpointKey:
		v := update.Value.(*model.HostEndpoint)
		cbs.index.UpdateLabels(update.Key, v.Labels, v.ProfileIDs)
	case model.ResourceKey:
		if k.Kind == apiv3.KindProfile {
			v := update.Value.(*apiv3.Profile).Spec.LabelsToApply
			cbs.index.UpdateParentLabels(k.Name, v)
		}
	default:
		log.Errorf("Unexpected update type: %#v", update)
		return true
	}
	return false
}

func (cbs *EvalCmd) OnUpdates(updates []api.Update) {
	log.Info("Update: ", updates)
	for _, update := range updates {
		// MATT: Removed some handling of empty key: don't understand how it can happen.
		cbs.dispatcher.OnUpdate(update)
	}
}

func (cbs *EvalCmd) onMatchStarted(selId, epId any) {
	if pols, ok := cbs.matches[epId]; ok {
		cbs.matches[epId] = append(pols, selId.(string))
	} else {
		cbs.matches[epId] = []string{selId.(string)}
	}
}

func (cbs *EvalCmd) onMatchStopped(selId, epId any) {
	log.Errorf("Unexpected match stopped event: %v, %v", selId, epId)
}
