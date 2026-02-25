package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	log "github.com/sirupsen/logrus"
	calicov3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"go.yaml.in/yaml/v3"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	yaml2 "sigs.k8s.io/yaml"
)

var managedKubeconfig = os.Getenv("MANAGED_KUBECONFIG")
var managementKubeconfig = os.Getenv("MANAGEMENT_KUBECONFIG")
var tenantID = os.Getenv("TENANT_ID")
var tenantNamespace = "cc-tenant-" + tenantID

var logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

func main() {
	err := run(50, 0)
	if err != nil {
		log.Fatal(err)
	}

}

func run(clusterCount int, startAt int) error {
	ctx := context.Background()

	managementClient, err := newControllerRuntimeClient(managementKubeconfig)
	if err != nil {
		return err
	}

	managedClient, err := newControllerRuntimeClient(managedKubeconfig)
	if err != nil {
		return err
	}

	secretsNamespace := "fake-guardian"
	if err = managedClient.Get(ctx, client.ObjectKey{Name: secretsNamespace}, &v1.Namespace{}); err != nil {
		if errors.IsNotFound(err) {
			if err = managedClient.Create(ctx, &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretsNamespace,
				},
			}); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	for i := range clusterCount {
		err = configureFakeCluster(ctx, startAt+i, managementClient, managedClient, tenantNamespace, secretsNamespace)
		if err != nil {
			return err
		}
	}

	return nil
}

func configureFakeCluster(
	ctx context.Context,
	id int,
	managementClient client.Client,
	managedClient client.Client,
	tenantNamespace string,
	secretsNamespace string,
) error {

	fakeClusterName := fmt.Sprintf("fake-cluster-%03d", id)
	resourceName := client.ObjectKey{Namespace: tenantNamespace, Name: fakeClusterName}

	logger.Info("Creating fake cluster", slog.String("name", fakeClusterName))

	if err := managementClient.Get(ctx, resourceName, &calicov3.ManagedCluster{}); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	} else if err = managementClient.Delete(ctx, &calicov3.ManagedCluster{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: resourceName.Namespace,
			Name:      resourceName.Name,
		},
	}); err != nil {
		return err
	}

	resource := calicov3.ManagedCluster{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: resourceName.Namespace,
			Name:      resourceName.Name,
		},
	}
	if err := managementClient.Create(ctx, &resource); err != nil {
		return err
	}

	mcc := ManagementClusterConnection{}
	sec := v1.Secret{}
	if err := decodeYamlMulti(resource.Spec.InstallationManifest, &mcc, &sec); err != nil {
		return err
	}
	sec.Data["voltron-url"] = []byte(mcc.Spec.ManagementClusterAddr)
	sec.Name = fakeClusterName
	sec.Namespace = secretsNamespace

	if err := managedClient.Delete(ctx, &sec); err != nil && !errors.IsNotFound(err) {
		return err
	}
	if err := managedClient.Create(ctx, &sec); err != nil {
		return err
	}

	return nil
}

// ManagementClusterConnection represents a link between a managed cluster and a management cluster. At most one instance of this resource is supported. It must be named “tigera-secure”.
type ManagementClusterConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              ManagementClusterConnectionSpec `json:"spec"`
}

// ManagementClusterConnectionSpec defines the desired state of ManagementClusterConnection.
type ManagementClusterConnectionSpec struct {
	ManagementClusterAddr string                `json:"managementClusterAddr,omitempty"`
	TLS                   *ManagementClusterTLS `json:"tls,omitempty"`
}

type ManagementClusterTLS struct {
	CA string `json:"ca,omitempty"`
}

func decodeYamlMulti(doc string, tgts ...any) error {
	decoder := yaml.NewDecoder(bytes.NewReader([]byte(doc)))

	for _, tgt := range tgts {
		var raw any
		err := decoder.Decode(&raw)
		if err != nil {
			return err
		}
		out, err := yaml.Marshal(raw)
		if err != nil {
			return err
		}
		jsonBytes, err := yaml2.YAMLToJSON(out)
		if err != nil {
			return err
		}

		err = json.Unmarshal(jsonBytes, tgt)
		if err != nil {
			return err
		}
	}

	return nil
}

func newControllerRuntimeClient(kubeconfig string) (client.Client, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()
	if err := v1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := calicov3.AddToScheme(scheme); err != nil {
		return nil, err
	}

	return client.New(cfg, client.Options{
		Scheme: scheme,
	})
}
