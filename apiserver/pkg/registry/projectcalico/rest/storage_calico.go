// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rest

import (
	"fmt"

	calico "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	calicoalertexception "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/alertexception"
	calicoauthorizationreview "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizationreview"
	calicobfdconfiguration "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/bfdconfiguration"
	calicobgpconfiguration "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/bgpconfiguration"
	calicobgpfilter "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/bgpfilter"
	calicobgppeer "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/bgppeer"
	calicoblockaffinity "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/blockaffinity"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/caliconodestatus"
	calicoclusterinformation "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/clusterinformation"
	calicodeeppacketinspection "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/deeppacketinspection"
	calicoegressgatewaypolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/egressgatewaypolicy"
	calicoexternalnetwork "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/externalnetwork"
	calicofelixconfig "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/felixconfig"
	calicogalert "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/globalalert"
	calicogalerttemplate "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/globalalerttemplate"
	calicognetworkset "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/globalnetworkset"
	calicogpolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/globalpolicy"
	calicoglobalreport "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/globalreport"
	calicoglobalreporttype "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/globalreporttype"
	calicogthreatfeed "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/globalthreatfeed"
	calicohostendpoint "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/hostendpoint"
	calicoipamconfig "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/ipamconfig"
	calicoippool "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/ippool"
	calicoipreservation "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/ipreservation"
	calicokubecontrollersconfig "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/kubecontrollersconfig"
	calicolicensekey "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/licensekey"
	calicomanagedcluster "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/managedcluster"
	calicopolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/networkpolicy"
	caliconetworkset "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/networkset"
	calicopacketcapture "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/packetcapture"
	calicopolicyrecommendationscope "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/policyrecommendationscope"
	calicoprofile "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/profile"
	calicoremoteclusterconfig "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/remoteclusterconfig"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/securityeventwebhook"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
	calicostagedgpolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/stagedglobalnetworkpolicy"
	calicostagedk8spolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/stagedkubernetesnetworkpolicy"
	calicostagedpolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/stagednetworkpolicy"
	calicotier "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/tier"
	calicouisettings "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/uisettings"
	calicouisettingsgroup "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/uisettingsgroup"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/util"
	calicostorage "github.com/projectcalico/calico/apiserver/pkg/storage/calico"
	"github.com/projectcalico/calico/apiserver/pkg/storage/etcd"
	"github.com/projectcalico/calico/licensing/monitor"
)

// RESTStorageProvider provides a factory method to create a new APIGroupInfo for
// the calico API group. It implements (./pkg/apiserver).RESTStorageProvider
type RESTStorageProvider struct {
	StorageType server.StorageType
}

// NewV3Storage constructs v3 api storage.
func (p RESTStorageProvider) NewV3Storage(
	scheme *runtime.Scheme,
	restOptionsGetter generic.RESTOptionsGetter,
	authorizer authorizer.Authorizer,
	resources *calicostorage.ManagedClusterResources,
	calculator rbac.Calculator,
	licenseMonitor monitor.LicenseMonitor,
	calicoLister rbac.CalicoResourceLister,
	watchManager *util.WatchManager,
) (map[string]rest.Storage, error) {
	policyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("networkpolicies"), nil)
	if err != nil {
		return nil, err
	}
	policyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   policyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicopolicy.EmptyObject(),
			ScopeStrategy: calicopolicy.NewStrategy(scheme),
			NewListFunc:   calicopolicy.NewList,
			GetAttrsFunc:  calicopolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    policyRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"cnp", "caliconetworkpolicy", "caliconetworkpolicies"},
	)

	networksetRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("networksets"), nil)
	if err != nil {
		return nil, err
	}
	networksetOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   networksetRESTOptions,
			Capacity:      1000,
			ObjectType:    caliconetworkset.EmptyObject(),
			ScopeStrategy: caliconetworkset.NewStrategy(scheme),
			NewListFunc:   caliconetworkset.NewList,
			GetAttrsFunc:  caliconetworkset.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    networksetRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"netsets"},
	)

	stagedk8spolicyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("stagedkubernetesnetworkpolicies"), nil)
	if err != nil {
		return nil, err
	}
	stagedk8spolicyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   stagedk8spolicyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicostagedk8spolicy.EmptyObject(),
			ScopeStrategy: calicostagedk8spolicy.NewStrategy(scheme),
			NewListFunc:   calicostagedk8spolicy.NewList,
			GetAttrsFunc:  calicostagedk8spolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    stagedk8spolicyRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"sknp"},
	)

	stagedpolicyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("stagednetworkpolicies"), nil)
	if err != nil {
		return nil, err
	}
	stagedpolicyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   stagedpolicyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicostagedpolicy.EmptyObject(),
			ScopeStrategy: calicostagedpolicy.NewStrategy(scheme),
			NewListFunc:   calicostagedpolicy.NewList,
			GetAttrsFunc:  calicostagedpolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    stagedpolicyRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"snp"},
	)

	tierRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("tiers"), nil)
	if err != nil {
		return nil, err
	}
	tierOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   tierRESTOptions,
			Capacity:      1000,
			ObjectType:    calicotier.EmptyObject(),
			ScopeStrategy: calicotier.NewStrategy(scheme),
			NewListFunc:   calicotier.NewList,
			GetAttrsFunc:  calicotier.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    tierRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	gpolicyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalnetworkpolicies"), nil)
	if err != nil {
		return nil, err
	}
	gpolicyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   gpolicyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicogpolicy.EmptyObject(),
			ScopeStrategy: calicogpolicy.NewStrategy(scheme),
			NewListFunc:   calicogpolicy.NewList,
			GetAttrsFunc:  calicogpolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    gpolicyRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"gnp", "cgnp", "calicoglobalnetworkpolicies"},
	)

	stagedgpolicyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("stagedglobalnetworkpolicies"), nil)
	if err != nil {
		return nil, err
	}
	stagedgpolicyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   stagedgpolicyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicostagedgpolicy.EmptyObject(),
			ScopeStrategy: calicostagedgpolicy.NewStrategy(scheme),
			NewListFunc:   calicostagedgpolicy.NewList,
			GetAttrsFunc:  calicostagedgpolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    stagedgpolicyRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	policyRecommendationScopeRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("policyrecommendationscopes"), nil)
	if err != nil {
		return nil, err
	}

	sharedPolicyRecommendationScopeEtcdOpts := etcd.Options{
		RESTOptions:   policyRecommendationScopeRESTOptions,
		Capacity:      1000,
		ObjectType:    calicogthreatfeed.EmptyObject(),
		ScopeStrategy: calicogthreatfeed.NewStrategy(scheme),
		NewListFunc:   calicogthreatfeed.NewList,
		GetAttrsFunc:  calicogthreatfeed.GetAttrs,
		Trigger:       nil,
	}

	policyrecommendationscopeOpts := server.NewOptions(
		sharedPolicyRecommendationScopeEtcdOpts,
		calicostorage.Options{
			RESTOptions:    policyRecommendationScopeRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	policyRecommendationScopeStatusRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("policyrecommendationscopes/status"), nil)
	if err != nil {
		return nil, err
	}

	policyRecommendationScopeStatusStatusOpts := server.NewOptions(
		sharedPolicyRecommendationScopeEtcdOpts,
		calicostorage.Options{
			RESTOptions:    policyRecommendationScopeStatusRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"sgnp"},
	)

	gNetworkSetRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalnetworksets"), nil)
	if err != nil {
		return nil, err
	}
	gNetworkSetOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   gNetworkSetRESTOptions,
			Capacity:      1000,
			ObjectType:    calicognetworkset.EmptyObject(),
			ScopeStrategy: calicognetworkset.NewStrategy(scheme),
			NewListFunc:   calicognetworkset.NewList,
			GetAttrsFunc:  calicognetworkset.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    gNetworkSetRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	licenseKeyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("licensekeys"), nil)
	if err != nil {
		return nil, err
	}
	licenseKeysSetOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   licenseKeyRESTOptions,
			Capacity:      10,
			ObjectType:    calicolicensekey.EmptyObject(),
			ScopeStrategy: calicolicensekey.NewStrategy(scheme),
			NewListFunc:   calicolicensekey.NewList,
			GetAttrsFunc:  calicolicensekey.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    licenseKeyRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	gAlertExceptionRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("alertexceptions"), nil)
	if err != nil {
		return nil, err
	}
	gAlertExceptionOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   gAlertExceptionRESTOptions,
			Capacity:      1000,
			ObjectType:    calicogalert.EmptyObject(),
			ScopeStrategy: calicogalert.NewStrategy(scheme),
			NewListFunc:   calicogalert.NewList,
			GetAttrsFunc:  calicogalert.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    gAlertExceptionRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	gAlertRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalalerts"), nil)
	if err != nil {
		return nil, err
	}
	gAlertOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   gAlertRESTOptions,
			Capacity:      1000,
			ObjectType:    calicogalert.EmptyObject(),
			ScopeStrategy: calicogalert.NewStrategy(scheme),
			NewListFunc:   calicogalert.NewList,
			GetAttrsFunc:  calicogalert.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    gAlertRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	gAlertTemplateRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalalerttemplates"), nil)
	if err != nil {
		return nil, err
	}
	gAlertTemplateOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   gAlertTemplateRESTOptions,
			Capacity:      1000,
			ObjectType:    calicogalert.EmptyObject(),
			ScopeStrategy: calicogalert.NewStrategy(scheme),
			NewListFunc:   calicogalert.NewList,
			GetAttrsFunc:  calicogalert.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    gAlertTemplateRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	gThreatFeedRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalthreatfeeds"), nil)
	if err != nil {
		return nil, err
	}

	gThreatFeedStatusRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalthreatfeeds/status"), nil)
	if err != nil {
		return nil, err
	}

	sharedGlobalThreatFeedEtcdOpts := etcd.Options{
		RESTOptions:   gThreatFeedRESTOptions,
		Capacity:      1000,
		ObjectType:    calicogthreatfeed.EmptyObject(),
		ScopeStrategy: calicogthreatfeed.NewStrategy(scheme),
		NewListFunc:   calicogthreatfeed.NewList,
		GetAttrsFunc:  calicogthreatfeed.GetAttrs,
		Trigger:       nil,
	}

	gThreatFeedOpts := server.NewOptions(
		sharedGlobalThreatFeedEtcdOpts,
		calicostorage.Options{
			RESTOptions:    gThreatFeedRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	gThreatFeedStatusOpts := server.NewOptions(
		sharedGlobalThreatFeedEtcdOpts,
		calicostorage.Options{
			RESTOptions:    gThreatFeedStatusRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	hostEndpointRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("hostendpoints"), nil)
	if err != nil {
		return nil, err
	}
	hostEndpointOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   hostEndpointRESTOptions,
			Capacity:      1000,
			ObjectType:    calicohostendpoint.EmptyObject(),
			ScopeStrategy: calicohostendpoint.NewStrategy(scheme),
			NewListFunc:   calicohostendpoint.NewList,
			GetAttrsFunc:  calicohostendpoint.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    hostEndpointRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"hep", "heps"},
	)

	globalReportRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalreports"), nil)
	if err != nil {
		return nil, err
	}
	globalReportOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   globalReportRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoglobalreport.EmptyObject(),
			ScopeStrategy: calicoglobalreport.NewStrategy(scheme),
			NewListFunc:   calicoglobalreport.NewList,
			GetAttrsFunc:  calicoglobalreport.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    globalReportRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	globalReportTypeRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalreporttypes"), nil)
	if err != nil {
		return nil, err
	}
	globalReportTypeOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   globalReportTypeRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoglobalreporttype.EmptyObject(),
			ScopeStrategy: calicoglobalreporttype.NewStrategy(scheme),
			NewListFunc:   calicoglobalreporttype.NewList,
			GetAttrsFunc:  calicoglobalreporttype.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    globalReportTypeRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	ipPoolRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("ippools"), nil)
	if err != nil {
		return nil, err
	}
	ipPoolSetOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   ipPoolRESTOptions,
			Capacity:      10,
			ObjectType:    calicoippool.EmptyObject(),
			ScopeStrategy: calicoippool.NewStrategy(scheme),
			NewListFunc:   calicoippool.NewList,
			GetAttrsFunc:  calicoippool.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    ipPoolRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	ipReservationRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("ipreservations"), nil)
	if err != nil {
		return nil, err
	}
	ipReservationSetOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   ipReservationRESTOptions,
			Capacity:      10,
			ObjectType:    calicoipreservation.EmptyObject(),
			ScopeStrategy: calicoipreservation.NewStrategy(scheme),
			NewListFunc:   calicoipreservation.NewList,
			GetAttrsFunc:  calicoipreservation.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    ipReservationRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	bgpConfigurationRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("bgpconfigurations"), nil)
	if err != nil {
		return nil, err
	}
	bgpConfigurationOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   bgpConfigurationRESTOptions,
			Capacity:      1000,
			ObjectType:    calicobgpconfiguration.EmptyObject(),
			ScopeStrategy: calicobgpconfiguration.NewStrategy(scheme),
			NewListFunc:   calicobgpconfiguration.NewList,
			GetAttrsFunc:  calicobgpconfiguration.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    bgpConfigurationRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"bgpconfig", "bgpconfigs"},
	)

	bgpPeerRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("bgppeers"), nil)
	if err != nil {
		return nil, err
	}
	bgpPeerOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   bgpPeerRESTOptions,
			Capacity:      1000,
			ObjectType:    calicobgppeer.EmptyObject(),
			ScopeStrategy: calicobgppeer.NewStrategy(scheme),
			NewListFunc:   calicobgppeer.NewList,
			GetAttrsFunc:  calicobgppeer.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    bgpPeerRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	bgpFilterRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("bgpfilters"), nil)
	if err != nil {
		return nil, err
	}
	bgpFilterOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   bgpFilterRESTOptions,
			Capacity:      1000,
			ObjectType:    calicobgpfilter.EmptyObject(),
			ScopeStrategy: calicobgpfilter.NewStrategy(scheme),
			NewListFunc:   calicobgpfilter.NewList,
			GetAttrsFunc:  calicobgpfilter.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    bgpFilterRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	profileRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("profiles"), nil)
	if err != nil {
		return nil, err
	}
	profileOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   profileRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoprofile.EmptyObject(),
			ScopeStrategy: calicoprofile.NewStrategy(scheme),
			NewListFunc:   calicoprofile.NewList,
			GetAttrsFunc:  calicoprofile.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    profileRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	remoteclusterconfigRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("remoteclusterconfigurations"), nil)
	if err != nil {
		return nil, err
	}
	remoteclusterconfigOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   remoteclusterconfigRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoremoteclusterconfig.EmptyObject(),
			ScopeStrategy: calicoremoteclusterconfig.NewStrategy(scheme),
			NewListFunc:   calicoremoteclusterconfig.NewList,
			GetAttrsFunc:  calicoremoteclusterconfig.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    remoteclusterconfigRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	felixConfigRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("felixconfigurations"), nil)
	if err != nil {
		return nil, err
	}
	felixConfigOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   felixConfigRESTOptions,
			Capacity:      1000,
			ObjectType:    calicofelixconfig.EmptyObject(),
			ScopeStrategy: calicofelixconfig.NewStrategy(scheme),
			NewListFunc:   calicofelixconfig.NewList,
			GetAttrsFunc:  calicofelixconfig.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    felixConfigRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"felixconfig", "felixconfigs"},
	)

	kubeControllersConfigsRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("kubecontrollersconfigurations"), nil)
	if err != nil {
		return nil, err
	}
	kubeControllersConfigsOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   kubeControllersConfigsRESTOptions,
			Capacity:      1000,
			ObjectType:    calicokubecontrollersconfig.EmptyObject(),
			ScopeStrategy: calicokubecontrollersconfig.NewStrategy(scheme),
			NewListFunc:   calicokubecontrollersconfig.NewList,
			GetAttrsFunc:  calicokubecontrollersconfig.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    kubeControllersConfigsRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"kcconfig"},
	)

	managedClusterRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("managedclusters"), nil)
	if err != nil {
		return nil, err
	}
	managedClusterOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   managedClusterRESTOptions,
			Capacity:      1000,
			ObjectType:    calicomanagedcluster.EmptyObject(),
			ScopeStrategy: calicomanagedcluster.NewStrategy(scheme),
			NewListFunc:   calicomanagedcluster.NewList,
			GetAttrsFunc:  calicomanagedcluster.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:             managedClusterRESTOptions,
			ManagedClusterResources: resources,
			LicenseMonitor:          licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	clusterInformationRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("clusterinformations"), nil)
	if err != nil {
		return nil, err
	}
	clusterInformationOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   clusterInformationRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoclusterinformation.EmptyObject(),
			ScopeStrategy: calicoclusterinformation.NewStrategy(scheme),
			NewListFunc:   calicoclusterinformation.NewList,
			GetAttrsFunc:  calicoclusterinformation.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    clusterInformationRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"clusterinfo"},
	)

	packetCaptureRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("packetcaptures"), nil)
	if err != nil {
		return nil, err
	}
	packetCaptureOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   packetCaptureRESTOptions,
			Capacity:      1000,
			ObjectType:    calicopacketcapture.EmptyObject(),
			ScopeStrategy: calicopacketcapture.NewStrategy(scheme),
			NewListFunc:   calicopacketcapture.NewList,
			GetAttrsFunc:  calicopacketcapture.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    packetCaptureRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	deepPacketInspectionRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("deeppacketinspections"), nil)
	if err != nil {
		return nil, err
	}

	deepPacketInspectionStatusRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("deeppacketinspections/status"), nil)
	if err != nil {
		return nil, err
	}

	deepPacketInspectionEtcdOpts := etcd.Options{
		RESTOptions:   deepPacketInspectionRESTOptions,
		Capacity:      1000,
		ObjectType:    calicodeeppacketinspection.EmptyObject(),
		ScopeStrategy: calicodeeppacketinspection.NewStrategy(scheme),
		NewListFunc:   calicodeeppacketinspection.NewList,
		GetAttrsFunc:  calicodeeppacketinspection.GetAttrs,
		Trigger:       nil,
	}

	deepPacketInspectionOpts := server.NewOptions(
		deepPacketInspectionEtcdOpts,
		calicostorage.Options{
			RESTOptions:    deepPacketInspectionRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	deepPacketInspectionStatusOpts := server.NewOptions(
		deepPacketInspectionEtcdOpts,
		calicostorage.Options{
			RESTOptions:    deepPacketInspectionStatusRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	uiSettingsGroupRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("uisettingsgroups"), nil)
	if err != nil {
		return nil, err
	}
	uiSettingsGroupOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   uiSettingsGroupRESTOptions,
			Capacity:      1000,
			ObjectType:    calicouisettingsgroup.EmptyObject(),
			ScopeStrategy: calicouisettingsgroup.NewStrategy(scheme),
			NewListFunc:   calicouisettingsgroup.NewList,
			GetAttrsFunc:  calicouisettingsgroup.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    uiSettingsGroupRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	uiSettingsRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("uisettings"), nil)
	if err != nil {
		return nil, err
	}
	uiSettingsOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   uiSettingsRESTOptions,
			Capacity:      1000,
			ObjectType:    calicouisettings.EmptyObject(),
			ScopeStrategy: calicouisettings.NewStrategy(scheme),
			NewListFunc:   calicouisettings.NewList,
			GetAttrsFunc:  calicouisettings.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    uiSettingsRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	caliconodestatusRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("caliconodestatuses"), nil)
	if err != nil {
		return nil, err
	}
	caliconodestatusOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   caliconodestatusRESTOptions,
			Capacity:      1000,
			ObjectType:    caliconodestatus.EmptyObject(),
			ScopeStrategy: caliconodestatus.NewStrategy(scheme),
			NewListFunc:   caliconodestatus.NewList,
			GetAttrsFunc:  caliconodestatus.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    caliconodestatusRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"caliconodestatus"},
	)

	ipamconfigRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("ipamconfigurations"), nil)
	if err != nil {
		return nil, err
	}
	ipamconfigOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   ipamconfigRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoipamconfig.EmptyObject(),
			ScopeStrategy: calicoipamconfig.NewStrategy(scheme),
			NewListFunc:   calicoipamconfig.NewList,
			GetAttrsFunc:  calicoipamconfig.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    ipamconfigRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"ipamconfig"},
	)

	securityeventRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("securityeventwebhooks"), nil)
	if err != nil {
		return nil, err
	}
	securityeventwebhookOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   securityeventRESTOptions,
			Capacity:      1000,
			ObjectType:    securityeventwebhook.EmptyObject(),
			ScopeStrategy: securityeventwebhook.NewStrategy(scheme),
			NewListFunc:   securityeventwebhook.NewList,
			GetAttrsFunc:  securityeventwebhook.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    securityeventRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"securityeventwebhook"},
	)

	blockAffinityRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("blockaffinities"), nil)
	if err != nil {
		return nil, err
	}
	blockAffinityOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   blockAffinityRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoblockaffinity.EmptyObject(),
			ScopeStrategy: calicoblockaffinity.NewStrategy(scheme),
			NewListFunc:   calicoblockaffinity.NewList,
			GetAttrsFunc:  calicoblockaffinity.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    blockAffinityRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"blockaffinity", "affinity", "affinities"},
	)

	externalnetworkRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("externalnetworks"), nil)
	if err != nil {
		return nil, err
	}
	externalnetworkOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   externalnetworkRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoexternalnetwork.EmptyObject(),
			ScopeStrategy: calicoexternalnetwork.NewStrategy(scheme),
			NewListFunc:   calicoexternalnetwork.NewList,
			GetAttrsFunc:  calicoexternalnetwork.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    externalnetworkRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"externalnetwork"},
	)

	egressGatewayPolicyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("egressgatewaypolicies"), nil)
	if err != nil {
		return nil, err
	}
	egressGatewayPolicyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   egressGatewayPolicyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoegressgatewaypolicy.EmptyObject(),
			ScopeStrategy: calicoegressgatewaypolicy.NewStrategy(scheme),
			NewListFunc:   calicoegressgatewaypolicy.NewList,
			GetAttrsFunc:  calicoegressgatewaypolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    egressGatewayPolicyRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"egresspolicy"},
	)

	bfdConfigurationRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("bfdconfigurations"), nil)
	if err != nil {
		return nil, err
	}
	bfdConfigurationOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   bfdConfigurationRESTOptions,
			Capacity:      1000,
			ObjectType:    calicobfdconfiguration.EmptyObject(),
			ScopeStrategy: calicobfdconfiguration.NewStrategy(scheme),
			NewListFunc:   calicobfdconfiguration.NewList,
			GetAttrsFunc:  calicobfdconfiguration.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions:    bfdConfigurationRESTOptions,
			LicenseMonitor: licenseMonitor,
		},
		p.StorageType,
		authorizer,
		[]string{"bfdconfig", "bfdconfigs"},
	)

	storage := map[string]rest.Storage{}
	storage["tiers"] = rESTInPeace(calicotier.NewREST(scheme, *tierOpts))
	storage["networkpolicies"] = rESTInPeace(calicopolicy.NewREST(scheme, *policyOpts, calicoLister, watchManager))
	storage["stagednetworkpolicies"] = rESTInPeace(calicostagedpolicy.NewREST(scheme, *stagedpolicyOpts, calicoLister, watchManager))
	storage["stagedkubernetesnetworkpolicies"] = rESTInPeace(calicostagedk8spolicy.NewREST(scheme, *stagedk8spolicyOpts))
	storage["tiers"] = rESTInPeace(calicotier.NewREST(scheme, *tierOpts))
	storage["globalnetworkpolicies"] = rESTInPeace(calicogpolicy.NewREST(scheme, *gpolicyOpts, calicoLister, watchManager))
	storage["stagedglobalnetworkpolicies"] = rESTInPeace(calicostagedgpolicy.NewREST(scheme, *stagedgpolicyOpts, calicoLister, watchManager))

	policyRecommendationScopeStorage, policyRecommendationScopeStatusStorage, err := calicopolicyrecommendationscope.NewREST(
		scheme,
		*policyrecommendationscopeOpts,
		*policyRecommendationScopeStatusStatusOpts,
	)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	storage["policyrecommendationscopes"] = policyRecommendationScopeStorage
	storage["policyrecommendationscopes/status"] = policyRecommendationScopeStatusStorage

	storage["globalnetworksets"] = rESTInPeace(calicognetworkset.NewREST(scheme, *gNetworkSetOpts))
	storage["networksets"] = rESTInPeace(caliconetworkset.NewREST(scheme, *networksetOpts))
	storage["uisettingsgroups"] = rESTInPeace(calicouisettingsgroup.NewREST(scheme, *uiSettingsGroupOpts))
	storage["uisettings"] = rESTInPeace(calicouisettings.NewREST(scheme, *uiSettingsOpts))
	licenseStorage, licenseStatusStorage, err := calicolicensekey.NewREST(scheme, *licenseKeysSetOpts)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}

	storage["licensekeys"] = licenseStorage
	storage["licensekeys/status"] = licenseStatusStorage

	alertExceptionStorage, alertExceptionStatusStorage, err := calicoalertexception.NewREST(scheme, *gAlertExceptionOpts)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	storage["alertexceptions"] = alertExceptionStorage
	storage["alertexceptions/status"] = alertExceptionStatusStorage

	globalAlertsStorage, globalAlertsStatusStorage, err := calicogalert.NewREST(scheme, *gAlertOpts)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	storage["globalalerts"] = globalAlertsStorage
	storage["globalalerts/status"] = globalAlertsStatusStorage

	storage["globalalerttemplates"] = rESTInPeace(calicogalerttemplate.NewREST(scheme, *gAlertTemplateOpts))

	globalThreatFeedsStorage, globalThreatFeedsStatusStorage, err := calicogthreatfeed.NewREST(scheme, *gThreatFeedOpts, *gThreatFeedStatusOpts)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	storage["globalthreatfeeds"] = globalThreatFeedsStorage
	storage["globalthreatfeeds/status"] = globalThreatFeedsStatusStorage

	storage["hostendpoints"] = rESTInPeace(calicohostendpoint.NewREST(scheme, *hostEndpointOpts))

	globalReportsStorage, globalReportsStatusStorage, err := calicoglobalreport.NewREST(scheme, *globalReportOpts)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	storage["globalreports"] = globalReportsStorage
	storage["globalreports/status"] = globalReportsStatusStorage

	storage["globalreporttypes"] = rESTInPeace(calicoglobalreporttype.NewREST(scheme, *globalReportTypeOpts))
	storage["ippools"] = rESTInPeace(calicoippool.NewREST(scheme, *ipPoolSetOpts))
	storage["ipreservations"] = rESTInPeace(calicoipreservation.NewREST(scheme, *ipReservationSetOpts))
	storage["bgpconfigurations"] = rESTInPeace(calicobgpconfiguration.NewREST(scheme, *bgpConfigurationOpts))
	storage["bgppeers"] = rESTInPeace(calicobgppeer.NewREST(scheme, *bgpPeerOpts))
	storage["bgpfilters"] = rESTInPeace(calicobgpfilter.NewREST(scheme, *bgpFilterOpts))
	storage["profiles"] = rESTInPeace(calicoprofile.NewREST(scheme, *profileOpts))
	storage["remoteclusterconfigurations"] = rESTInPeace(calicoremoteclusterconfig.NewREST(scheme, *remoteclusterconfigOpts))
	storage["felixconfigurations"] = rESTInPeace(calicofelixconfig.NewREST(scheme, *felixConfigOpts))
	storage["caliconodestatuses"] = rESTInPeace(caliconodestatus.NewREST(scheme, *caliconodestatusOpts))
	storage["ipamconfigurations"] = rESTInPeace(calicoipamconfig.NewREST(scheme, *ipamconfigOpts))
	storage["blockaffinities"] = rESTInPeace(calicoblockaffinity.NewREST(scheme, *blockAffinityOpts))
	storage["externalnetworks"] = rESTInPeace(calicoexternalnetwork.NewREST(scheme, *externalnetworkOpts))
	storage["egressgatewaypolicies"] = rESTInPeace(calicoegressgatewaypolicy.NewREST(scheme, *egressGatewayPolicyOpts))
	storage["securityeventwebhooks"] = rESTInPeace(securityeventwebhook.NewREST(scheme, *securityeventwebhookOpts))
	storage["bfdconfigurations"] = rESTInPeace(calicobfdconfiguration.NewREST(scheme, *bfdConfigurationOpts))

	kubeControllersConfigsStorage, kubeControllersConfigsStatusStorage, err := calicokubecontrollersconfig.NewREST(scheme, *kubeControllersConfigsOpts)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	storage["kubecontrollersconfigurations"] = kubeControllersConfigsStorage
	storage["kubecontrollersconfigurations/status"] = kubeControllersConfigsStatusStorage

	managedClusterStorage, managedClusterStatusStorage, err := calicomanagedcluster.NewREST(scheme, *managedClusterOpts)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	storage["managedclusters"] = managedClusterStorage
	storage["managedclusters/status"] = managedClusterStatusStorage

	storage["clusterinformations"] = rESTInPeace(calicoclusterinformation.NewREST(scheme, *clusterInformationOpts))
	storage["authorizationreviews"] = calicoauthorizationreview.NewREST(calculator)

	packetCaptureStorage, packetCaptureStatusStorage, err := calicopacketcapture.NewREST(scheme, *packetCaptureOpts)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	storage["packetcaptures"] = packetCaptureStorage
	storage["packetcaptures/status"] = packetCaptureStatusStorage

	deepPacketInspectionStorage, deepPacketInspectionStatusStorage, err := calicodeeppacketinspection.NewREST(scheme, *deepPacketInspectionOpts, *deepPacketInspectionStatusOpts)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	storage["deeppacketinspections"] = deepPacketInspectionStorage
	storage["deeppacketinspections/status"] = deepPacketInspectionStatusStorage

	return storage, nil
}

// GroupName returns the API group name.
func (p RESTStorageProvider) GroupName() string {
	return calico.GroupName
}

// rESTInPeace is just a simple function that panics on error.
// Otherwise returns the given storage object. It is meant to be
// a wrapper for projectcalico registries.
func rESTInPeace(storage rest.Storage, err error) rest.Storage {
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	return storage
}
