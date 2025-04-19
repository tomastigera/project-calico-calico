## queryserver API Documentation

This API documentation is not meant for external/public consumption and is
targeted at internal use (manager/webapp only).

### Available APIS

* [Version](#version)
* [Summary](#summary)
* [Policies](#policies)
* [Endpoints](#endpoints)
* [Nodes](#nodes)
* [License](#license)

### General API Principles

1. All APIs are read-only and *only* support the GET method.
1. Pagination is available on all query URLs.  The query parameters are:
- `page`
  - page number
  - defaults to 0 if not specified
- `maxItems`
  - max number of items to return per page
  - defaults to 100
  - a value of `all` may be used to return all items at once.
- `sortBy`
  - name of the field to sort by
  - see tables to see which fields are sortable, the query will error if the field is not 
    a valid SortableBy field.
  - tables indicate default sort field by (*) or (*1)... in the SortableBy column (number indicates sort order)
  - multiple sortBy entries may be specified, the default sort field is always added as the
    final sort field.
- `reverseSort`
  - set to `true` to reverse the sort order.

### Version

Returns the version of `queryserver`.

#### URL

```
https://host:port/base/version
```

#### Query Parameters

None supported.

#### Response

Returns a JSON object with the following fields.

| Field | Description | Scheme |
| ----- | ----------- | ------ |
| version | The version | string |
| buildDate | The build date | string |
| gitTagRef | The git tag reference | string |
| gitCommit | The git commit hash | string |

#### Examples

```
{
  "version": "v2.0.0-cnx-rc1-33-g0fa9177-dirty",
  "buildDate": "2018-03-07T19:44:50+0000",
  "gitTagRef": "v2.0.0-cnx-rc1-33-g0fa9177",
  "gitCommit": "0fa9177"
}
```

### Summary

Retrieve a statistics summary of policies, endpoints, and nodes.

UI Req:
1. Intended to be used from the dashboard view. In addition to the
packet/connection statistics, the dashboard contains a panel to show total
policies/endpoints and nodes.

#### URL

```
https://host:port/base/summary
```

TODO(doublek/rlb):
1. Include unused policy count and denying policy count.

#### Query Parameters

There are currently no supported query parameters for the `summary` API.

#### Response

Returns a JSON object with the following fields.

| Field | Description | Scheme |
| ----- | ----------- | ------ |
| numGlobalNetworkPolicies | Count of GlobalNetworkPolicy resources | number |
| numNetworkPolicies | Count of (namespaced) NetworkPolicy resources | number |
| numHostEndpoints | Count of HostEndpoint resources | number |
| numWorkloadEndpoints | Count of WorkloadEndpoint resources | number |
| numUnmatchedGlobalNetworkPolicies | Count of GlobalNetworkPolicies that do not match any endpoints | number |
| numUnmatchedNetworkPolicies | Count of NetworkPolicies that do not match any endpoints | number |
| numUnlabelledWorkloadEndpoints | Count of WorkloadEndpoint resources that do not have any explicitly configured labels | number |
| numUnlabelledHostEndpoints | Count of host endpoints that do not have any explicitly configured labels | number |
| numUnprotectedWorkloadEndpoints | Count of WorkloadEndpoint resources that do not have any policies applied on them | number |
| numUnprotectedHostEndpoints | Count of HostEndpoints that do not have any policies applied on them | number |
| numNodes | Count of Nodes | number |
| numNodesWithNoEndpoints | Count of Nodes that do not have any HostEndpoint or WorkloadEndpoint resources configured | number |
| numNodesWithNoWorkloadEndpoints | Count of Nodes that do not have any WorkloadEndpoint resources configured | number |
| numNodesWithNoHostEndpoints | Count of Nodes that do not have any HostEndpoint resources configured | number |
| namespaceCounts | Summary counts of namespaced resources grouped by namespace | [namespace summary](#namespace-summary) |

NOTE:
1. To get the total endpoint count to for this policy, sum `numWorkloadEndpoints` and `numHostEndpoints`.
1. `numNodesWithNoHostEndpoints` is loosely equivalent to "Unprotected Nodes"

##### Namespace summary

| Field | Description | Scheme |
| ----- | ----------- | ------ |
| numNetworkPolicies | Count of NetworkPolicy resources in the namespace | number |
| numWorkloadEndpoints | Count of WorkloadEndpoint resources in the namespace | number |
| numUnmatchedNetworkPolicies | Count of NetworkPolicies in the namespace that do not match any endpoints | number |
| numUnlabelledWorkloadEndpoints | Count of WorkloadEndpoint resources in the namespace that do not have any explicitly configured labels | number |
| numUnprotectedWorkloadEndpoints | Count of WorkloadEndpoint resources in the namespace that do not have any policies applied on them | number |

#### Examples Response

```
{
  "numGlobalNetworkPolicies": 1,
  "numNetworkPolicies": 3,
  "numHostEndpoints": 3,
  "numWorkloadEndpoints": 5,
  "numUnmatchedGlobalNetworkPolicies": 0,
  "numUnmatchedNetworkPolicies": 1,
  "numUnlabelledWorkloadEndpoints": 1,
  "numUnlabelledHostEndpoints": 1,
  "numUnprotectedWorkloadEndpoints": 0,
  "numUnprotectedHostEndpoints": 0,
  "numNodes": 4,
  "numNodesWithNoEndpoints": 1,
  "numNodesWithNoWorkloadEndpoints": 2,
  "numNodesWithNoHostEndpoints": 2
  "namespaceCounts": {
                  "namespace-1": {
                      numNetworkPolicies: 1,
                      numWorkloadEndpoints: 2,
                      numUnmatchedNetworkPolicies: 1,
                      numUnlabelledWorkloadEndpoints: 0,
                      numUnprotectedWorkloadEndpoints: 2,
                  },
                  "namespace-2": {
                      numNetworkPolicies: 1,
                      numWorkloadEndpoints: 2,
                      numUnmatchedNetworkPolicies: 0,
                      numUnlabelledWorkloadEndpoints: 1,
                      numUnprotectedWorkloadEndpoints: 0,
                  },
              },
}
```

### Policies

UI Req:
1. Intented to be used in the policies view. The web UI currently has a policy
view. In this view there is a choice of "trello" style lists, or a tabular view.
Both the views show endpoint counts per policy. The tabular view can expand a
policy to show some additional details about the policy. Most of the information
is already obtained from the Tigera apiserver and for each policy, this API should
provide the number of endpoints and nodes.
1. Intended to be used in a policy details view. This view shows a single policy
and other fields of a policy including ingress and egress rules. This view shows
the connection statistics and endpoint statistics. This API should provice the
number of endpoints matching a policy and number of endpoints matching each
rule.
1. For both the above requirements, the data provided is not based on actual
traffic seen by the system but by examining policy selectors and such.

Design Note:
1. A single endpoint is used to query both NetworkPolicy and GlobalNetworkPolicy resources.

#### URL: exact get for GlobalNetworkPolicy

```
https://host:port/base/policies/{name}
```

No query parameters supported for this URL format.

#### URL: exact get for (namespaced) NetworkPolicy

```
https://host:port/base/policies/{namespace}/{name}
```

No query parameters supported for this URL format.

#### URL: query

```
https://host:port/base/policies
```

#### Query Parameters

| Name | Description | Type | Repeated | Required |
| ---- | ----------- | ---- | -------- | -------- |
| tier | Get policies that are in a tier | string | no | no |
| unmatched | Get policies whose selectors do not match any endpoints | boolean | no | no |
| endpoint | Get policies that match an endpoint | [endpoint name](#endpoint-name) | no | no |
| label_* | Get policies that match a set of labels | [labels](#labels) | yes | no |
| networkset | Get policies whose rules match a networkset | [networkset name](#networkset-name) | no | no |

- When no query parameter is provided, data for all policies across all tiers will be returned.
- Multiple query parameters can be combined together (read exceptions below) and
  they will be treated as a logical AND. Results matching all the query
  parameters should be returned.
- The `endpoint` and `unmatched` query parameters cannot be combined in a single query.
- When the `tier` is specified, results will be limited to the specified `tier`.

##### Endpoint name

The name of an endpoint may be specified as a query parameter. Policies whose main selector
matches that endpoint.

For a WorkloadEndpoint use the name format `{namespace}/{name}`.

##### Labels

It is possible to query the policies whose main selector will match a set of labels. Specify each label as a
separate query parameter prefixed with `label_`.

If labels are specified in addition to an endpoint, the set of policies returned will be
those that match both the endpoint and match the supplied set of labels.

Use the label `projectcalico.org/namespace` and `projectcalico.org/orchestrator` to specify the 
namespace and orchestrator of the endpoint being emulated by the set of labels.

##### Networkset name

The name of a networkset may be specified as a query parameter. Used to select policies whose rule
selectors match the labels on the networkset.

#### Response

Returns a JSON object with the following fields.

| Field | Description | Scheme |
| ----- | ----------- | ------ |
| count | Count of policies matching the request | number |
| items | A list of policies that match the query | list of [policy response objects](#policy-response-object)|

Items will be sorted by the tier and policy `Order` parameter, i.e. in the order the policy is applied to the
endpoints.

##### Policy Response Object

| Field | Description | Scheme | SortableBy |
| ----- | ----------- | ------ | ---------- |
| index | The relative index the policies are applied in within the scope of the query | int | true (*) |
| kind | The kind of policy | GlobalNetworkPolicy or NetworkPolicy | true |
| name | The name of the policy | string | true |
| namespace | The namespace (only for NetworkPolicy) | string | true |
| tier | The Tier the policy is in | string | true |
| numWorkloadEndpoints | The number of WorkloadEndpoint resources matching the policy | number | true |
| numHostEndpoints | The number of HostEndpoint resources matching the policy | number | true |
| ingressRules | List of ingress rules | list of [rule](#rule-response-object) | false |
| egressRules | List of egress rules | list of [rule](#rule-response-object) | false |

NOTE:
1. The `name` parameter is exactly the same as in the v3 client.
   - It is prefixed with the tier name.
1. To get the total endpoint count to for this policy, sum
   `numWorkloadEndpoints` and `numHostEndpoints`.
1. You can use `numEndpoints` as a sort field to sort on the total endpoint count.
   
TODO(rlb):  Need numNodes that policy is applied to.

TODO(rlb):  Maybe need indication of whether actual policy will apply to an endpoint (e.g. if there are
            multiple matching policies within the same tier, or if none of the rules in the previous tier 
            have a pass action)

##### Rule Response Object

| Field | Description | Scheme |
| ----- | ----------- | ------ |
| source | The source entity | [rule entity](#rule-endpoints-object) |
| destination | The destination entity | [rule entity](#rule-endpoints-object) |

##### Rule Endpoints Object

| Field | Description | Scheme |
| ----- | ----------- | ------ |
| numWorkloadEndpoints | The number of WorkloadEndpoint resources matching the rule selector(s) | number |
| numHostEndpoints | The number of HostEndpoint resources matching the rule selector(s) | number |

#### Example

```
# Query by endpoint, filtering on tier, page 0, 1 item per page.
curl "localhost:8080/policies?endpoint=namespace1/rack1--host1-k8s-pod.name-eth0&tier=tier2&page=0&maxItems=1"
{
  "count": 1,
  "items": [
    {
      "kind": "NetworkPolicy",
      "name": "tier2.sad-pandas",
      "namespace": "namespace1",
      "tier": "tier2",
      "numWorkloadEndpoints": 1,
      "numHostEndpoints": 0,
      "ingressRules": [
        {
          "source": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          },
          "destination": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          }
        }
      ],
      "egressRules": [
        {
          "source": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          },
          "destination": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          }
        }
      ]
    }
  ]
}

# Query by labels
curl "localhost:8080/policies?label_panda=reallyverysad&label_projectcalico.org/namespace=namespace1"
{
  "count": 1,
  "items": [
    {
      "kind": "NetworkPolicy",
      "name": "tier3.another-sad-panda",
      "namespace": "namespace1",
      "tier": "tier3",
      "numWorkloadEndpoints": 1,
      "numHostEndpoints": 0,
      "ingressRules": [
        {
          "source": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          },
          "destination": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          }
        }
      ],
      "egressRules": [
        {
          "source": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          },
          "destination": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          }
        }
      ]
    }
  ]
}

# Query a specific GlobalNetworkPolicy resource
curl "localhost:8080/policies/tier1.host-eps"
{
  "count": 1,
  "items": [
    {
      "kind": "GlobalNetworkPolicy",
      "name": "tier1.host-eps",
      "tier": "tier1",
      "numWorkloadEndpoints": 0,
      "numHostEndpoints": 2,
      "ingressRules": [
        {
          "source": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          },
          "destination": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          }
        }
      ],
      "egressRules": [
        {
          "source": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          },
          "destination": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          }
        }
      ]
    }
  ]
}

# Query a specific (namespaced) NetworkPolicy resource
curl "localhost:8080/policies/namespace1/tier3.very-sad-pandas"
{
  "count": 1,
  "items": [
    {
      "kind": "NetworkPolicy",
      "name": "tier3.very-sad-pandas",
      "namespace": "namespace1",
      "tier": "tier3",
      "numWorkloadEndpoints": 0,
      "numHostEndpoints": 0,
      "ingressRules": [
        {
          "source": {
            "numWorkloadEndpoints": 1,
            "numHostEndpoints": 0
          },
          "destination": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          }
        }
      ],
      "egressRules": [
        {
          "source": {
            "numWorkloadEndpoints": 1,
            "numHostEndpoints": 0
          },
          "destination": {
            "numWorkloadEndpoints": 5,
            "numHostEndpoints": 3
          }
        }
      ]
    }
  ]
}
```

### Endpoints

UI Req:
1. Intended to be used in a endpoints view, which displays a list of endpoints (both host
and workload). This API should list all endpoints, with the ability to filter by label or
filter by a policy.
1. Clicking on an endpoint expands the row in the table and displays some detailed information
about the endpoint such as IP addresses, labels and all policies that apply to this endpoint.

Design Note:
1. A single endpoint is used to query both HostEndpoint and WorkloadEndpoint resources.

#### URL: exact get for HostEndpoint

```
https://host:port/base/endpoints/{name}
```

No query parameters supported for this URL format.

#### URL: exact get for (namespaced) WorkloadEndpoint

```
https://host:port/base/endpoints/{namespace}/{name}
```

No query parameters supported for this URL format.

#### URL: query

```
https://host:port/base/endpoints
```

#### Query Parameters

| Name | Description | Schema | Repeated | Required |
| ---- | ----------- | ---- | -------- | -------- |
| node | Filter endpoints that are on a specific node. | string | no | no |
| policy | Get endpoints that the policy applies to. | string | no | no |
| unprotected | Get endpoints that do not have any policies applied on them. | boolean | no | no |
| unlabelled | Get endpoints that do not have any explicitly configured labels. | boolean | no | no |
| ruleDirection | Specify the direction of the rule whose selector you want to enumerate. Only valid when policy is specified, all other rule options should also be specified. | ingress or egress | no | no |
| ruleIndex | Specify the direction of the rule whose selector you want to enumerate. Only valid when policy is specified, all other rule options should also be specified. | int | no | no |
| ruleEntity | Specify the entity of the rule whose selector you want to enumerate. Only valid when policy is specified, all other rule options should also be specified. | source or destination | no | no |
| ruleNegatedSelector | Specify when the enumerate the selector or negated selector of the specified rule. Only valid when policy is specified, all other rule options should also be specified. | string | no | no |
| selector | Get endpoints that match a selector | [selector expression](#selectors) | no | no |

- When no query parameter is provided, results should be returned for all namespaces.
- A selector may not be specified if the policy or policy rule are specified.
- A selector or policy should not be specified when requesting `unprotected` endpoints.
- To enumerate the endpoints associated with a specific policy rule, include each of the rule* query parameters to index the actual
  rule selector that you are enumerating.
- `namespaceSelector` is meant to be used when dealing with `NetworkPolicy` rules.

TODO (rlb): Add namespace option

TODO (rlb): Add namespace selector option

TODO (rlb): Maybe add multiple nodes options

TODO (rlb): Rather than specifying the rule selector by indexing into the policy rules, we could just use the Namespace, NamespaceSelector, Selector etc.
  to calculate the effective selector.

#### Response

Returns a JSON object with the following fields.

| Field | Description | Scheme |
| ----- | ----------- | ------ |
| count | Count of endpoints matching the request | number |
| items | A list of endpoints that match the query | list of [endpoint response objects](#endpoint-response-object) |

Items will be sorted by name and then namespace.

##### Endpoint Response Object

| Field | Description | Scheme | SortableBy |
|-------|-------------|--------|------------|
| kind | The kind of endpoint | HostEndpoint or WorkloadEndpoint | true |
| name | The name of the endpoint | string | true (*1) |
| namespace | The namespace (only for WorkloadEndpoint) | string | true (*2) |
| node | The node that the endpoint resides in | string | true |
| numGlobalNetworkPolicies | The number of GlobalNetworkPolicies that match the endpoint | number | true |
| numNetworkPolicies | The number of NetworkPolicies that match the endpoint | number | true |
| workload | The name of the workload to which this endpoint belongs | string | true |
| orchestrator | The orchestrator that created this endpoint | string | true |
| pod | The kubernetes pod name (if orchestrator value is `k8s`) | string | true |
| ipNetworks | List of CIDRs assigned to this endpoint. For HostEndpoints, this is the expected list of IP Addresses if configured. | list of strings | true |
| labels | List of labels that applies to this endpoint | map of key-value pairs | false |
| interfaceName | The name of the interface attached to this endpoint | string | true |

Notes:
1. You can use `numPolicies` as a sort field to sort on the total policy count.

#### Example

```
# Query the endpoints that match the main policy selector for the Network Policy tier2.sad-pandas
curl "localhost:8080/endpoints?policy=namespace1/tier2.sad-pandas"
{
  "count": 1,
  "items": [
    {
      "kind": "WorkloadEndpoint",
      "name": "rack1--host1-k8s-pod.name-eth0",
      "namespace": "namespace1",
      "node": "rack1-host1",
      "workload": "default.frontend-m33p",
      "orchestrator": "k8s",
      "pod": "pod.name",
      "interfaceName": "cali0ef24ba",
      "ipNetworks": [
        "192.168.9.0/32"
      ],
      "labels": {
        "app": "frontend",
        "projectcalico.org/namespace": "namespace1",
        "projectcalico.org/orchestrator": "k8s"
      },
      "numGlobalNetworkPolicies": 0,
      "numNetworkPolicies": 1
    }
  ]
}

# Return the endpoints that match the (non-negated) selector in the policy tier2.sad-pandas, in the first egress source 
# rule. Return a max of two results (out of a total of 8)
curl "localhost:8080/endpoints?policy=namespace1/tier2.sad-pandas&ruleDirection=egress&ruleIndex=0&ruleEntity=source&negatedSelector=false&maxItems=2"
{
  "count": 8,
  "items": [
    {
      "kind": "HostEndpoint",
      "name": "rack1--host1-endpoint1",
      "node": "rack1-host1",
      "workload": "",
      "orchestrator": "",
      "pod": "",
      "interfaceName": "eth0",
      "ipNetworks": [
        "1.2.3.4"
      ],
      "labels": {
        "host": ""
      },
      "numGlobalNetworkPolicies": 1,
      "numNetworkPolicies": 0
    },
    {
      "kind": "WorkloadEndpoint",
      "name": "rack1--host1-k8s-pod.name-eth0",
      "namespace": "namespace1",
      "node": "rack1-host1",
      "workload": "default.frontend-m33p",
      "orchestrator": "k8s",
      "pod": "pod.name",
      "interfaceName": "cali0ef24ba",
      "ipNetworks": [
        "192.168.9.0/32"
      ],
      "labels": {
        "app": "frontend",
        "projectcalico.org/namespace": "namespace1",
        "projectcalico.org/orchestrator": "k8s"
      },
      "numGlobalNetworkPolicies": 0,
      "numNetworkPolicies": 1
    }
  ]
}

# Return endpoints matching the selector "has(host)"
curl localhost:8080/endpoints?selector=has\(host\)
{
  "count": 2,
  "items": [
    {
      "kind": "HostEndpoint",
      "name": "rack1--host1-endpoint1",
      "node": "rack1-host1",
      "workload": "",
      "orchestrator": "",
      "pod": "",
      "interfaceName": "eth0",
      "ipNetworks": [
        "1.2.3.4"
      ],
      "labels": {
        "host": ""
      },
      "numGlobalNetworkPolicies": 1,
      "numNetworkPolicies": 0
    },
    {
      "kind": "HostEndpoint",
      "name": "rack1--host2-endpoint1",
      "node": "rack1-host2",
      "workload": "",
      "orchestrator": "",
      "pod": "",
      "interfaceName": "eth0",
      "ipNetworks": [
        "1.2.3.5"
      ],
      "labels": {
        "host": ""
      },
      "numGlobalNetworkPolicies": 1,
      "numNetworkPolicies": 0
    }
  ]
}

# Return a specific WorkloadEndpoint
curl localhost:8080/endpoints/namespace1/rack1--host1-k8s-pod.name-eth0
{
  "count": 1,
  "items": [
    {
      "kind": "WorkloadEndpoint",
      "name": "rack1--host1-k8s-pod.name-eth0",
      "namespace": "namespace1",
      "node": "rack1-host1",
      "workload": "default.frontend-m33p",
      "orchestrator": "k8s",
      "pod": "pod.name",
      "interfaceName": "cali0ef24ba",
      "ipNetworks": [
        "192.168.9.0/32"
      ],
      "labels": {
        "app": "frontend",
        "projectcalico.org/namespace": "namespace1",
        "projectcalico.org/orchestrator": "k8s"
      },
      "numGlobalNetworkPolicies": 0,
      "numNetworkPolicies": 1
    }
  ]
}

# Return a specific HostEndpoint
curl localhost:8080/endpoints/rack1--host2-endpoint1
{
  "count": 1,
  "items": [
    {
      "kind": "HostEndpoint",
      "name": "rack1--host2-endpoint1",
      "node": "rack1-host2",
      "workload": "",
      "orchestrator": "",
      "pod": "",
      "interfaceName": "eth0",
      "ipNetworks": [
        "1.2.3.5"
      ],
      "labels": {
        "host": ""
      },
      "numGlobalNetworkPolicies": 1,
      "numNetworkPolicies": 0
    }
  ]
}
```

### Nodes

UI Req:
1. Intended to be used in the nodes view, which displays a list of nodes. This API should
list all nodes, with the ability to filter by policies that are applied to endpoints on a
node.
1. Each node contains the number of endpoints that reside on each node.

Design Note:
1. The webapp could get a list of nodes via the Kubernetes API, and simply use
   the calicoq API for filling in counts? (TBD)
1. Clicking on a node, expands to provide additional details about the node
   such as endpoints and IP addresses. On this event, the web client is
   expected to issue [endpoints](#endpoints) query with the appropriate
   `node` query parameter filled in.

#### URL: exact get for Node

```
https://host:port/base/nodes/{name}
```

#### URL: query

```
https://host:port/base/nodes
```

#### Query Parameters

The only supported query parameters are the paging parameters.

#### Response

Returns a JSON object with the following fields.

| Field | Description | Scheme |
| ----- | ----------- | ------ |
| count | Count of nodes matching the request | number |
| items | A list of nodes that match the query | list of [node response objects](#node-response-object) |

##### Node Response Object

| Field | Description | Scheme | SortableBy |
| ----- | ----------- | ------ |------------|
| name | Name of the node | string | true (*) |
| bgpIPAddresses | The configured BGP IP addresses for this node | list of string | true |
| addresses |  List of addresses that a client can reach the node | list of string | true |
| numWorkloadEndpoints | The number of workload endpoints residing on this node | number | true |
| numHostEndpoints | The number of host endpoints present on this node | number | true |

Notes:
1. You can use `numEndpoints` as a sort field to sort on the total endpoint count.

#### Example

```
# Query all nodes, max 2 per page, second page (indexing starts at 0).
curl "localhost:8080/nodes?maxItems=2&page=1"
{
  "count": 4,
  "items": [
    {
      "name": "rack1-host3",
      "bgpIPAddresses": [
        "1.2.3.4",
        "aa:bb:cc::"
      ],
      "addresses": [
        "1.2.3.4",
        "aa:bb:cc::"
      ]
      "numWorkloadEndpoints": 0,
      "numHostEndpoints": 0
    },
    {
      "name": "rack2-host1",
      "bgpIPAddresses": null,
      "addresses": null,
      "numWorkloadEndpoints": 3,
      "numHostEndpoints": 0
    }
  ]
}

# Query specific node
curl localhost:8080/nodes/rack1-host1
{
  "count": 1,
  "items": [
    {
      "name": "rack1-host1",
      "bgpIPAddresses": null,
      "addresses": null,
      "numWorkloadEndpoints": 2,
      "numHostEndpoints": 1
    }
  ]
}

```

### License

Returns the status of Calico Enterprise cluster license.
There are 5 different possible scenarios:
1. License not applied
2. License applied, and valid
3. License applied, but expired (but still in the grace period)
4. License applied, but really expired (out of the grace period)
5. License applied, but is corrupted

`is_valid` will be `false` for all except case #2
`warning` will be populated when `is_valid` is `false` else it won't exist. 
`expiry` will be populated for all cases except when license is not found or is corrupted.

#### URL

```
https://host:port/base/license
```

#### Query Parameters

None supported.

#### Response

Returns a JSON object with the following fields.

| Field | Description | Scheme |
| ----- | ----------- | ------ |
| is_valid | If the license is valid or not | boolean |
| warning | Warning message if the license is not valid | string |
| expiry  | License expiry date, time and timezone if the license is found and not corrupted | string |

#### Examples

1. License not applied

```
{
  "is_valid": false,
  "warning": "No valid license was found for your environment. Please contact Tigera support",
}
```

2. License applied, and valid

```
{
  "is_valid": true,
  "expiry": "Sun Mar 15 06:59:59 UTC 2020"
}

```

3. License applied, but expired (but still in the grace period)
 AND 
4. License applied, but really expired (out of the grace period)
(For Calico Enterprise v2.1 both cases 3 and 4 are the same)

```
{
  "is_valid": false,
  "warning": "LicenseKey expired or invalid. Please contact Tigera support to avoid traffic disruptions",
  "expiry": "Sun Mar 15 06:59:59 UTC 2020"
}
```

5. License applied, but is corrupted

```
{
  "is_valid": false,
  "warning": "License corrupted. Please contact Tigera support",
}
```
