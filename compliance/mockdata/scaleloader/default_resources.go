package scaleloader

import (
	yaml "sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

var (
	defaultPodJson = `{"kind":"Pod","apiVersion":"v1","metadata":{"selfLink":"/api/v1/namespaces/compliance-testing/pods/database-74656f569f-kjbhl","uid":"7bd389e8-564b-11e9-8550-42010a800036","resourceVersion":"239854","creationTimestamp":"2019-04-03T20:03:01Z","deletionTimestamp":"2019-04-03T20:05:49Z","deletionGracePeriodSeconds":0,"labels":{"app":"database","pod-template-hash":"74656f569f","version":"v2"},"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"database-74656f569f","uid":"7bd0c8c0-564b-11e9-8550-42010a800036","controller":true,"blockOwnerDeletion":true}]},"spec":{"volumes":[{"name":"database-token-fsjbn","secret":{"secretName":"database-token-fsjbn","defaultMode":420}}],"containers":[{"name":"database","image":"mysql","ports":[{"containerPort":3307,"protocol":"TCP"}],"resources":{},"volumeMounts":[{"name":"database-token-fsjbn","readOnly":true,"mountPath":"/var/run/secrets/kubernetes.io/serviceaccount"}],"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","imagePullPolicy":"Always"}],"restartPolicy":"Always","terminationGracePeriodSeconds":30,"dnsPolicy":"ClusterFirst","serviceAccountName":"database","serviceAccount":"database","nodeName":"bkim-kadm-ms","securityContext":{},"schedulerName":"default-scheduler","tolerations":[{"key":"node.kubernetes.io/not-ready","operator":"Exists","effect":"NoExecute","tolerationSeconds":300},{"key":"node.kubernetes.io/unreachable","operator":"Exists","effect":"NoExecute","tolerationSeconds":300}],"priority":0,"enableServiceLinks":true},"status":{"phase":"Running","conditions":[{"type":"Initialized","status":"True","lastProbeTime":null,"lastTransitionTime":"2019-04-03T20:03:01Z"},{"type":"Ready","status":"False","lastProbeTime":null,"lastTransitionTime":"2019-04-03T20:03:46Z","reason":"ContainersNotReady","message":"containers with unready status: [database]"},{"type":"ContainersReady","status":"False","lastProbeTime":null,"lastTransitionTime":"2019-04-03T20:03:46Z","reason":"ContainersNotReady","message":"containers with unready status: [database]"},{"type":"PodScheduled","status":"True","lastProbeTime":null,"lastTransitionTime":"2019-04-03T20:03:01Z"}],"startTime":"2019-04-03T20:03:01Z","containerStatuses":[{"name":"database","state":{"terminated":{"exitCode":0,"startedAt":null,"finishedAt":null}},"lastState":{"terminated":{"exitCode":1,"reason":"Error","startedAt":"2019-04-03T20:04:32Z","finishedAt":"2019-04-03T20:04:33Z","containerID":"docker://b65e01f413f2db5e3222b29b22bd995b36dd9a8084a9fc1ef9059461afdbd421"}},"ready":false,"restartCount":4,"image":"mysql:latest","imageID":"docker-pullable://mysql@sha256:a7cf659a764732a27963429a87eccc8457e6d4af0ee9d5140a3b56e74986eed7","containerID":"docker://b65e01f413f2db5e3222b29b22bd995b36dd9a8084a9fc1ef9059461afdbd421"}],"qosClass":"BestEffort"}}`
)

func getDefaultResource(r resources.ResourceHelper) resources.Resource {
	if r.TypeMeta() == resources.TypeK8sPods {
		res := r.NewResource()
		if err := yaml.Unmarshal([]byte(defaultPodJson), res); err != nil {
			panic(err)
		}
		return res
	}

	return r.NewResource()
}
