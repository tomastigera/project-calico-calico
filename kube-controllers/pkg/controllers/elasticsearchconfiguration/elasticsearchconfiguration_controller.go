// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.

package elasticsearchconfiguration

import (
	"fmt"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/worker"
	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
	relasticsearch "github.com/projectcalico/calico/kube-controllers/pkg/resource/elasticsearch"
)

const (
	UserChangeHashLabel        = "tigera-change-hash"
	ElasticsearchUserNameLabel = "tigera-elasticsearch-user"
)

// esConfigController is responsible managing the elasticsearch configuration for a particular cluster (management, standalone,
// managed). In this controller, we have the notion of a managed cluster and a management cluster. The management cluster
// can be treated like a managed cluster by using the kube config for the management cluster in the  managedK8sCli. In this
// case the "management" flag should be set, as the elasticsearch configuration that needs to be created / copied differs
// between a management (same as standalone) and a managed cluster. Depending on if the management flag is set, this controller
// does the following:
//
// If the management flag is false:
//   - Creates the elasticsearch users and roles in elasticsearch for the components in the the managed cluster and stores
//     them in secrets in the managed cluster. There are certain components that only run in the management cluster, like
//     the Manager and the ComplianceServer, and those users and roles will not be created
//   - Copies over the Secret in the management cluster that contains the elasticsearch tls certificate
//   - Copies the ConfigMap that has other elasticsearch related configuration that a managed cluster needs
//
// If the management flag is true:
//   - Creates the elasticsearch users and roles in elasticsearch for the components in the the management cluster and stores
//     them in secrets in the management cluster. There are certain components that only run in the management cluster, like
//     the Manager and the ComplianceServer, and those users and roles will be created
//
// A note on when the Reconcile function is run:
// Regardless of whether the management flag is true or false, we add watches using the managedK8sCli to watch the component
// user secrets created, the Elasticsearch tls secret, and the Elasticsearch config map. If the the management flag is set
// to true, we also add a watch for changes in Elasticsearch. If the management flag is set to false, it is assumed that
// this controller is being used to reconcile a managed cluster, and in this case the ManagedCluster controller watches
// elasticsearch in the management cluster and restarts the ElasticsearchConfiguration controllers for the managed clusters
// if there is a significant change in elasticsearch.
//
// When this controller starts it runs the Reconcile function of the reconciler in this package, which creates / updates
// everything that the components in the managed cluster need to access / update elasticsearch. Watches are added to the
// k8s components created in the managed cluster, and if any of them change then the reconcilers Reconcile function is run
// and the changed components are likely updated.
//
// Note that this controller does not react to changes in the management cluster (unless, of course, the managedK8sCLI points
// to the management cluster). If something changes in the management cluster, this controller should just be recreated
// and re run.
type esConfigController struct {
	clusterName string
	r           *reconciler
	worker      worker.Worker
	cfg         config.ElasticsearchCfgControllerCfg
}

func New(
	clusterName string,
	ownerReference string,
	managedK8sCLI kubernetes.Interface,
	managementK8sCLI kubernetes.Interface,
	esK8sCLI relasticsearch.RESTClient,
	esClientBuilder elasticsearch.ClientBuilder,
	management bool,
	cfg config.ElasticsearchCfgControllerCfg,
	restartChan chan<- string,
) controller.Controller {
	logCtx := log.WithField("cluster", clusterName)
	r := &reconciler{
		clusterName:      clusterName,
		ownerReference:   ownerReference,
		managementK8sCLI: managementK8sCLI,
		managedK8sCLI:    managedK8sCLI,
		esK8sCLI:         esK8sCLI,
		esClientBuilder:  esClientBuilder,
		management:       management,
		restartChan:      restartChan,
	}

	// The high requeue attempts is because it's unlikely we would receive an event after failure to re trigger a
	// reconcile, meaning a temporary service disruption could lead to Elasticsearch credentials not being propagated.
	w := worker.New(r, worker.WithMaxRequeueAttempts(20))

	utils.AddWatchForActiveOperator(w, r.managedK8sCLI)

	// We need to get the operator namespace because we need to watch secrets in that namespace.
	// If we are unable to successfully read the namespace assume the default operator namespace.
	// We also setup a watch for the ConfigMap with the namespace so if our assumption is wrong we
	// will be triggered when it is available or updated and a Reconcile will trigger a restart so
	// this controller can be restarted and pick up the correct namespace.
	var err error
	r.managedOperatorNamespace, err = utils.FetchOperatorNamespace(r.managedK8sCLI)
	if err != nil {
		r.managedOperatorNamespace = utils.DefaultTigeraOperatorNamespace
		logCtx.WithField("cluster", clusterName).WithField("message", err.Error()).Info("unable to fetch operator namespace, assuming active operator in tigera-operator namespace")
	}

	w.AddWatch(
		cache.NewFilteredListWatchFromClient(managedK8sCLI.CoreV1().RESTClient(), "secrets", r.managedOperatorNamespace, func(options *metav1.ListOptions) {
			options.LabelSelector = ElasticsearchUserNameLabel
		}),
		&corev1.Secret{},
		worker.ResourceWatchUpdate, worker.ResourceWatchDelete,
	)

	w.AddWatch(
		cache.NewFilteredListWatchFromClient(managementK8sCLI.CoreV1().RESTClient(), "secrets", resource.TigeraElasticsearchNamespace, func(options *metav1.ListOptions) {
			options.LabelSelector = "esgateway.tigera.io/secrets"
		}),
		&corev1.Secret{},
		worker.ResourceWatchUpdate, worker.ResourceWatchDelete,
	)

	notifications := []worker.ResourceWatch{worker.ResourceWatchUpdate, worker.ResourceWatchDelete, worker.ResourceWatchAdd}

	w.AddWatch(
		cache.NewListWatchFromClient(managedK8sCLI.CoreV1().RESTClient(), "secrets", r.managedOperatorNamespace,
			fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", resource.ElasticsearchCertSecret))),
		&corev1.Secret{},
		notifications...,
	)

	w.AddWatch(
		cache.NewListWatchFromClient(managedK8sCLI.CoreV1().RESTClient(), "secrets", r.managedOperatorNamespace,
			fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", resource.ESGatewayCertSecret))),
		&corev1.Secret{},
		notifications...,
	)

	w.AddWatch(
		cache.NewListWatchFromClient(managedK8sCLI.CoreV1().RESTClient(), "secrets", r.managedOperatorNamespace,
			fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", resource.VoltronLinseedPublicCert))),
		&corev1.Secret{},
		notifications...,
	)

	w.AddWatch(
		cache.NewListWatchFromClient(managedK8sCLI.CoreV1().RESTClient(), "configmaps", r.managedOperatorNamespace,
			fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", resource.ElasticsearchConfigMapName))),
		&corev1.ConfigMap{},
		notifications...,
	)

	if enableElasticsearchWatch {
		w.AddWatch(
			cache.NewListWatchFromClient(esK8sCLI, "elasticsearches", resource.TigeraElasticsearchNamespace,
				fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", resource.DefaultTSEEInstanceName))),
			&esv1.Elasticsearch{},
		)
	}

	// This is a managed cluster and we need to watch some Elasticsearch secrets and config maps we know when to copy
	// them over to the managed clusters.
	if !management {
		utils.AddWatchForActiveOperator(w, r.managementK8sCLI)
		// We need to get the operator namespace because we need to watch secrets in that namespace.
		// If we are unable to successfully read the namespace assume the default operator namespace.
		// We also setup a watch for the ConfigMap with the namespace so if our assumption is wrong we
		// will be triggered when it is available or updated and a Reconcile will trigger a restart so
		// this controller can be restarted and pick up the correct namespace.
		r.managementOperatorNamespace, err = utils.FetchOperatorNamespace(r.managementK8sCLI)
		if err != nil {
			r.managementOperatorNamespace = utils.DefaultTigeraOperatorNamespace
			logCtx.WithField("cluster", "management").WithField("message", err.Error()).Info("unable to fetch operator namespace, assuming active operator namespace is tigera-operator")
		}

		logCtx.Info("Watching for management cluster configuration changes.")

		w.AddWatch(
			cache.NewListWatchFromClient(managementK8sCLI.CoreV1().RESTClient(), "configmaps", r.managementOperatorNamespace,
				fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", resource.ElasticsearchConfigMapName))),
			&corev1.ConfigMap{},
			notifications...,
		)

		w.AddWatch(
			cache.NewListWatchFromClient(managementK8sCLI.CoreV1().RESTClient(), "secrets", r.managementOperatorNamespace,
				fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", resource.ElasticsearchCertSecret))),
			&corev1.Secret{},
			notifications...,
		)

		w.AddWatch(
			cache.NewListWatchFromClient(managementK8sCLI.CoreV1().RESTClient(), "secrets", r.managementOperatorNamespace,
				fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", resource.ESGatewayCertSecret))),
			&corev1.Secret{},
			notifications...,
		)
		w.AddWatch(
			cache.NewListWatchFromClient(managementK8sCLI.CoreV1().RESTClient(), "secrets", r.managementOperatorNamespace,
				fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", resource.VoltronLinseedPublicCert))),
			&corev1.Secret{},
			notifications...,
		)
	}

	return &esConfigController{
		clusterName: clusterName,
		r:           r,
		worker:      w,
		cfg:         cfg,
	}
}

func (c *esConfigController) Run(stop chan struct{}) {
	log.WithField("cluster", c.clusterName).Info("Starting Elasticsearch configuration controller")

	go c.worker.Run(c.cfg.NumberOfWorkers, stop)

	<-stop
}
