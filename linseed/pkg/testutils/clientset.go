package testutils

import (
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	projectcalicov3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	"k8s.io/client-go/kubernetes"
)

type ClientSetSet struct {
	kubernetes.Interface
	Calico clientset.Interface
}

func (c *ClientSetSet) ProjectcalicoV3() projectcalicov3.ProjectcalicoV3Interface {
	return c.Calico.ProjectcalicoV3()
}
