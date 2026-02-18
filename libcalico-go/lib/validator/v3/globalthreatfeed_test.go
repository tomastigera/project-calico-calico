// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package v3

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	k8sv1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = DescribeTable("GlobalThreatFeed Validator",
	func(input interface{}, valid bool) {
		if valid {
			Expect(Validate(input)).NotTo(HaveOccurred(),
				"expected value to be valid")
		} else {
			Expect(Validate(input)).To(HaveOccurred(),
				"expected value to be invalid")
		}
	},

	// GlobalThreatFeed
	Entry("disallow GlobalThreatFeed with invalid K8s name",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "~gtf"},
			Spec:       api.GlobalThreatFeedSpec{Content: api.ThreatFeedContentIPset},
		},
		false,
	),
	Entry("allow GlobalThreatFeed with valid K8s name",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content:     api.ThreatFeedContentIPset,
				Description: "test",
			},
		},
		true,
	),
	Entry("allow GlobalThreatFeed with missing Content",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Description: "test",
			},
		},
		true,
	),
	Entry("disallow GlobalThreatFeed with invalid Content",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec:       api.GlobalThreatFeedSpec{Content: "arandocontent"},
		},
		false,
	),
	Entry("allow GlobalThreatFeed with Content DomainNameSet",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content:     api.ThreatFeedContentDomainNameSet,
				Description: "test",
			},
		},
		true,
	),
	Entry("allow GlobalThreatFeed with gns labels",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content:     api.ThreatFeedContentIPset,
				Description: "test",
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
			},
		},
		true,
	),
	Entry("allow GlobalThreatFeed with valid max length description",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Description: "this global threat feed description is valid because the maximum number of characters is acceptable repeat this global threat feed description is valid because the maximum number of characters is acceptable repeat again and again and again and again finish",
			},
		},
		true,
	),
	Entry("disallow GlobalThreatFeed with invalid max length description",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Description: "this global threat feed description is valid because the maximum number of characters is unacceptable repeat this global threat feed description is valid because the maximum number of characters is acceptable repeat again and again and again and again complete",
			},
		},
		false,
	),
	Entry("disallow GlobalThreatFeed with invalid gns labels",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{",,foo": "bar", "biz": "~baz"},
				},
			},
		},
		false,
	),
	Entry("disallow GlobalThreatFeed DomainNameSet with GlobalNetworkSet",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentDomainNameSet,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
			},
		},
		false,
	),
	Entry("allow GlobalThreatFeed with Pull stanza",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content:     api.ThreatFeedContentIPset,
				Description: "test",
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
					},
				},
			},
		},
		true,
	),
	Entry("allow GlobalThreatFeed without Pull.Period",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content:     api.ThreatFeedContentIPset,
				Description: "test",
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
					},
				},
			},
		},
		true,
	),
	Entry("disallow GlobalThreatFeed with too short of period",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "4m",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
					},
				},
			},
		},
		false,
	),
	Entry("disallow GlobalThreatFeed with invalid period",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "twenty hours",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
					},
				},
			},
		},
		false,
	),
	Entry("disallow GlobalThreatFeed without pull URI",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
					},
				},
			},
		},
		false,
	),
	Entry("disallow GlobalThreatFeed with invalid URL",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "somethingdotcom",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
					},
				},
			},
		},
		false,
	),

	// Formats
	Entry("allow GlobalThreatFeed with missing format",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content:     api.ThreatFeedContentIPset,
				Description: "test",
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
					},
				},
			},
		},
		true,
	),
	Entry("allow ThreatFeedFormat with empty format",
		api.ThreatFeedFormat{},
		true,
	),
	Entry("disallow ThreatFeedFormat with NewlineDelimited and JSON format",
		api.ThreatFeedFormat{
			NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
			JSON: &api.ThreatFeedFormatJSON{
				Path: "$.x",
			},
		},
		false,
	),
	Entry("disallow ThreatFeedFormat with NewlineDelimited and CSV format",
		api.ThreatFeedFormat{
			NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum: new(uint),
			},
		},
		false,
	),
	Entry("disallow ThreatFeedFormat with JSON and CSV format",
		api.ThreatFeedFormat{
			JSON: &api.ThreatFeedFormatJSON{
				Path: "$.x",
			},
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum: new(uint),
			},
		},
		false,
	),
	Entry("disallow ThreatFeedFormat with all 3 formats",
		api.ThreatFeedFormat{
			NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
			JSON: &api.ThreatFeedFormatJSON{
				Path: "$.x",
			},
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum: new(uint),
			},
		},
		false,
	),
	Entry("allow ThreatFeedFormat NewlineDelimited format",
		api.ThreatFeedFormat{
			NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
		},
		true,
	),
	Entry("allow ThreatFeedFormat JSON format with valid path",
		api.ThreatFeedFormat{
			JSON: &api.ThreatFeedFormatJSON{
				Path: "$.x",
			},
		},
		true,
	),
	Entry("disallow JSON format with missing path",
		api.ThreatFeedFormat{
			JSON: &api.ThreatFeedFormatJSON{},
		},
		false,
	),
	Entry("disallow JSON format with invalid path",
		api.ThreatFeedFormat{
			JSON: &api.ThreatFeedFormatJSON{
				Path: ".",
			},
		},
		false,
	),
	Entry("disallow empty CSV format",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{},
		},
		false,
	),
	Entry("allow CSV format with field number",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum: new(uint),
			},
		},
		true,
	),
	Entry("allow CSV format with field name",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldName: "x",
				Header:    true,
			},
		},
		true,
	),
	Entry("disallow CSV format with field name and header=false",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldName: "x",
				Header:    false,
			},
		},
		false,
	),
	Entry("allow CSV format with alternate delimiter",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:        new(uint),
				ColumnDelimiter: "|",
			},
		},
		true,
	),
	Entry("disallow CSV format with invalid delimiter",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:        new(uint),
				ColumnDelimiter: "\n",
			},
		},
		false,
	),
	Entry("disallow CSV format with delimiter too long",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:        new(uint),
				ColumnDelimiter: "abc",
			},
		},
		false,
	),
	Entry("allow CSV format with comment",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:         new(uint),
				CommentDelimiter: "#",
			},
		},
		true,
	),
	Entry("disallow CSV format with invalid comment",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:         new(uint),
				CommentDelimiter: "\n",
			},
		},
		false,
	),
	Entry("disallow CSV format with comment too long",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:         new(uint),
				CommentDelimiter: "abc",
			},
		},
		false,
	),
	Entry("disallow CSV format with comment matching default delimiter",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:         new(uint),
				CommentDelimiter: ",",
			},
		},
		false,
	),
	Entry("disallow CSV format with comment matching delimiter",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:         new(uint),
				ColumnDelimiter:  "|",
				CommentDelimiter: "|",
			},
		},
		false,
	),
	Entry("allow CSV format with comma comment where delimiter differs",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:         new(uint),
				ColumnDelimiter:  "|",
				CommentDelimiter: ",",
			},
		},
		true,
	),
	Entry("disallow CSV format with both recordSize and disableRecordSizeValidation set",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:                    new(uint),
				RecordSize:                  1,
				DisableRecordSizeValidation: true,
			},
		},
		false,
	),
	Entry("allow CSV format with positive recordSize",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:   new(uint),
				RecordSize: 1,
			},
		},
		true,
	),
	Entry("disallow CSV format with negative recordSize",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:   new(uint),
				RecordSize: -1,
			},
		},
		false,
	),
	Entry("disallow CSV format with disableRecordSizeValidation set",
		api.ThreatFeedFormat{
			CSV: &api.ThreatFeedFormatCSV{
				FieldNum:                    new(uint),
				DisableRecordSizeValidation: true,
			},
		},
		true,
	),

	// Headers
	Entry("allow GlobalThreatFeed with HTTP Headers",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content:     api.ThreatFeedContentIPset,
				Description: "test",
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
						Headers: []api.HTTPHeader{
							{Name: "Key", Value: "opensesame"},
						},
					},
				},
			},
		},
		true,
	),
	Entry("disallow GlobalThreatFeed with invalid HTTP Headers",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
						Headers: []api.HTTPHeader{
							{Name: "Key\xbd", Value: "zoo"},
						},
					},
				},
			},
		},
		false,
	),
	Entry("disallow GlobalThreatFeed with unicode HTTP Headers",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
						Headers: []api.HTTPHeader{
							{Name: "Frappé", Value: "yum"},
						},
					},
				},
			},
		},
		false,
	),
	Entry("allow GlobalThreatFeed with HTTP Header value from configmap",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content:     api.ThreatFeedContentIPset,
				Description: "test",
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
						Headers: []api.HTTPHeader{
							{Name: "Key", ValueFrom: &api.HTTPHeaderSource{
								ConfigMapKeyRef: &k8sv1.ConfigMapKeySelector{
									LocalObjectReference: k8sv1.LocalObjectReference{Name: api.SecretConfigMapNamePrefix + "-sandwiches-configo"},
									Key:                  "my-key",
								},
							}},
						},
					},
				},
			},
		},
		true,
	),
	Entry("disallow GlobalThreatFeed with HTTP Header Value and ValueFrom",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
						Headers: []api.HTTPHeader{
							{
								Name:  "Key",
								Value: "opensesame",
								ValueFrom: &api.HTTPHeaderSource{
									ConfigMapKeyRef: &k8sv1.ConfigMapKeySelector{
										LocalObjectReference: k8sv1.LocalObjectReference{Name: "configo"},
										Key:                  "my-key",
									},
								}},
						},
					},
				},
			},
		},
		false,
	),
	Entry("disallow GlobalThreatFeed with bad config-map name",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
						Headers: []api.HTTPHeader{
							{Name: "Key", ValueFrom: &api.HTTPHeaderSource{
								ConfigMapKeyRef: &k8sv1.ConfigMapKeySelector{
									LocalObjectReference: k8sv1.LocalObjectReference{Name: "~configo"},
									Key:                  "my-key",
								},
							}},
						},
					},
				},
			},
		},
		false,
	),
	Entry("disallow GlobalThreatFeed with bad config-map key",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
						Headers: []api.HTTPHeader{
							{Name: "Key", ValueFrom: &api.HTTPHeaderSource{
								ConfigMapKeyRef: &k8sv1.ConfigMapKeySelector{
									LocalObjectReference: k8sv1.LocalObjectReference{Name: "configo"},
									Key:                  "$$$my-key",
								},
							}},
						},
					},
				},
			},
		},
		false,
	),
	Entry("allow GlobalThreatFeed with correct ConfigMap name",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "juve"},
			Spec: api.GlobalThreatFeedSpec{
				Content:     api.ThreatFeedContentIPset,
				Description: "test",
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
						Headers: []api.HTTPHeader{
							{Name: "Key", ValueFrom: &api.HTTPHeaderSource{
								ConfigMapKeyRef: &k8sv1.ConfigMapKeySelector{
									LocalObjectReference: k8sv1.LocalObjectReference{Name: api.SecretConfigMapNamePrefix + "-juve-champion"},
									Key:                  "my-key",
								},
							}},
						},
					},
				},
			},
		},
		true,
	),
	Entry("disallow GlobalThreatFeed with incorrect ConfigMap name",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "juve"},
			Spec: api.GlobalThreatFeedSpec{
				Content: api.ThreatFeedContentIPset,
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
						Headers: []api.HTTPHeader{
							{Name: "Key", ValueFrom: &api.HTTPHeaderSource{
								ConfigMapKeyRef: &k8sv1.ConfigMapKeySelector{
									LocalObjectReference: k8sv1.LocalObjectReference{Name: "juve"},
									Key:                  "my-key",
								},
							}},
						},
					},
				},
			},
		},
		false,
	),
	Entry("allow GlobalThreatFeed with HTTP Header value from secret",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Content:     api.ThreatFeedContentIPset,
				Description: "test",
				GlobalNetworkSet: &api.GlobalNetworkSetSync{
					Labels: map[string]string{"foo": "bar", "biz": "baz"},
				},
				Pull: &api.Pull{
					Period: "12h",
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Format: api.ThreatFeedFormat{
							NewlineDelimited: &api.ThreatFeedFormatNewlineDelimited{},
						},
						Headers: []api.HTTPHeader{
							{Name: "Key", ValueFrom: &api.HTTPHeaderSource{
								SecretKeyRef: &k8sv1.SecretKeySelector{
									LocalObjectReference: k8sv1.LocalObjectReference{Name: api.SecretConfigMapNamePrefix + "-sandwiches-configo"},
									Key:                  "my-key",
								},
							}},
						},
					},
				},
			},
		},
		true,
	),
	Entry("disallow GlobalThreatFeed with bad secret name",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Pull: &api.Pull{
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Headers: []api.HTTPHeader{
							{Name: "Key", ValueFrom: &api.HTTPHeaderSource{
								SecretKeyRef: &k8sv1.SecretKeySelector{
									LocalObjectReference: k8sv1.LocalObjectReference{Name: "~configo"},
									Key:                  "my-key",
								},
							}},
						},
					},
				},
			},
		},
		false,
	),
	Entry("disallow GlobalThreatFeed with bad secret key",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "sandwiches"},
			Spec: api.GlobalThreatFeedSpec{
				Pull: &api.Pull{
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Headers: []api.HTTPHeader{
							{Name: "Key", ValueFrom: &api.HTTPHeaderSource{
								SecretKeyRef: &k8sv1.SecretKeySelector{
									LocalObjectReference: k8sv1.LocalObjectReference{Name: "configo"},
									Key:                  "$$$my-key",
								},
							}},
						},
					},
				},
			},
		},
		false,
	),
	Entry("allow GlobalThreatFeed with correct secret name",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "juve"},
			Spec: api.GlobalThreatFeedSpec{
				Description: "test",
				Pull: &api.Pull{
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Headers: []api.HTTPHeader{
							{Name: "Key", ValueFrom: &api.HTTPHeaderSource{
								SecretKeyRef: &k8sv1.SecretKeySelector{
									LocalObjectReference: k8sv1.LocalObjectReference{Name: api.SecretConfigMapNamePrefix + "-juve-champion"},
									Key:                  "my-key",
								},
							}},
						},
					},
				},
			},
		},
		true,
	),
	Entry("disallow GlobalThreatFeed with bad secret name",
		&api.GlobalThreatFeed{
			ObjectMeta: v1.ObjectMeta{Name: "juve"},
			Spec: api.GlobalThreatFeedSpec{
				Pull: &api.Pull{
					HTTP: &api.HTTPPull{
						URL: "http://tigera.io/threats",
						Headers: []api.HTTPHeader{
							{Name: "Key", ValueFrom: &api.HTTPHeaderSource{
								SecretKeyRef: &k8sv1.SecretKeySelector{
									LocalObjectReference: k8sv1.LocalObjectReference{Name: "juve"},
								},
							}},
						},
					},
				},
			},
		},
		false,
	),
)
