// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package elasticsearch_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
)

var esAdminName = "any"
var esAdminPassword = "any"
var token = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", esAdminName, esAdminPassword)))
var esUser = elasticsearch.User{
	Username: "anyUser",
}
var role = elasticsearch.Role{Name: "anyRole"}

type mockReq struct {
	statusCode int
	hasBody    bool
	body       string
}

type expected struct {
	error        bool
	errorMessage string
	method       string
	url          []string
}

type mockES struct {
	interceptedRequests []*http.Request
	es                  *httptest.Server
}

func configureESMock(req mockReq) *mockES {
	var mock = mockES{}

	// Configure ES mock
	mock.es = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/" {
			// This is a version check. See elasticsearch.go's genuineCheckHeader stuff.
			writer.Header().Add("X-Elastic-Product", "Elasticsearch")
			writer.WriteHeader(http.StatusOK)
		} else {
			mock.interceptedRequests = append(mock.interceptedRequests, request)
			writer.WriteHeader(req.statusCode)
		}

		if req.hasBody {
			_, _ = writer.Write([]byte(req.body))
		}
	}))

	return &mock
}

func assertResponse(expected expected, err error, mockES *mockES) {
	if expected.error {
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal(expected.errorMessage))
	} else {
		Expect(err).NotTo(HaveOccurred())

		var interceptedRequests = mockES.interceptedRequests
		Expect(len(interceptedRequests)).To(Equal(len(expected.url)))

		var URLs []string
		for _, request := range interceptedRequests {
			Expect(request.Method).To(Equal(expected.method), fmt.Sprintf("%s requests should be issued", expected.method))
			Expect(request.Header.Get("Authorization")).To(Equal(fmt.Sprintf("Basic %s", token)),
				"Authorization tokens should be part of the requests")
			URLs = append(URLs, request.URL.Path)
		}

		Expect(URLs).To(Equal(expected.url))
	}
}

var _ = Describe("Elasticsearch", func() {
	DescribeTable("DeleteUser",
		func(mock mockReq, expected expected) {
			// Configure ES to return a specific response
			var es = configureESMock(mock)
			defer es.es.Close()

			// Configure ES client
			var client, err = elasticsearch.NewClient(es.es.URL, esAdminName, esAdminPassword, nil)
			Expect(err).NotTo(HaveOccurred())

			// Invoke Delete
			err = client.DeleteUser(esUser)

			assertResponse(expected, err, es)

			es.es.Close()
		},
		Entry("Delete API returns 200",
			mockReq{200, false, ""},
			expected{false, "", "DELETE", []string{"/_security/user/anyUser"}}),
		Entry("Delete API returns 404",
			mockReq{404, false, ""},
			expected{false, "", "DELETE", []string{"/_security/user/anyUser"}}),
		Entry("Delete API returns 400",
			mockReq{400, true, "Fail to delete an user"},
			expected{true, "Fail to delete an user", "DELETE", nil}),
		Entry("Delete API returns 503 ",
			mockReq{503, true, "Fail to delete an user"},
			expected{true, "Fail to delete an user", "DELETE", nil}),
	)

	DescribeTable("DeleteRole",
		func(mock mockReq, expected expected) {
			// Configure ES to return a specific response
			var es = configureESMock(mock)
			defer es.es.Close()

			// Configure ES client
			var client, err = elasticsearch.NewClient(es.es.URL, esAdminName, esAdminPassword, nil)
			Expect(err).NotTo(HaveOccurred())

			// Invoke Delete
			err = client.DeleteRole(role)

			assertResponse(expected, err, es)
		},
		Entry("Delete API returns 200",
			mockReq{200, false, ""},
			expected{false, "", "DELETE", []string{"/_security/role/anyRole"}}),
		Entry("Delete API returns 404",
			mockReq{404, false, ""},
			expected{false, "", "DELETE", []string{"/_security/role/anyRole"}}),
		Entry("Delete API returns 400",
			mockReq{400, true, "Fail to delete a role"},
			expected{true, "Fail to delete a role", "DELETE", nil}),
		Entry("Delete API returns 503 ",
			mockReq{503, true, "Fail to delete a role"},
			expected{true, "Fail to delete a role", "DELETE", nil},
		),
	)

	DescribeTable("GetUsers",
		func(mock mockReq, expected expected, expectedUsers []elasticsearch.User) {
			// Configure ES to return a specific response
			var es = configureESMock(mock)
			defer es.es.Close()

			// Configure ES client
			var client, err = elasticsearch.NewClient(es.es.URL, esAdminName, esAdminPassword, nil)
			Expect(err).NotTo(HaveOccurred())

			// Invoke GetUser
			var users []elasticsearch.User
			users, err = client.GetUsers()

			sort.Slice(expectedUsers, func(i, j int) bool {
				return expectedUsers[i].Username < expectedUsers[j].Username
			})
			sort.Slice(users, func(i, j int) bool {
				return users[i].Username < users[j].Username
			})

			assertResponse(expected, err, es)
			Expect(users).To(Equal(expectedUsers))
		},
		Entry("GET API returns 400",
			mockReq{400, true, "Fail to get an user"},
			expected{true, "Fail to get an user", "GET", nil},
			nil),
		Entry("GET API returns 503",
			mockReq{503, true, "Fail to get an user"},
			expected{true, "Fail to get an user", "GET", nil},
			nil),
		Entry("GET API returns 200 and malformed response",
			mockReq{200, true, "$adf#"},
			expected{true, "invalid character '$' looking for beginning of value", "GET", nil},
			nil),
		Entry("GET API returns 200 and no users",
			mockReq{200, true, "{}"},
			expected{false, "", "GET", []string{"/_security/user"}},
			[]elasticsearch.User{}),
		Entry("GET API returns an empty user",
			mockReq{200, true, "{\"emptyUser\":{}}"},
			expected{false, "", "GET", []string{"/_security/user"}},
			[]elasticsearch.User{{Username: "emptyUser"}}),
		Entry("GET API returns multiple users",
			mockReq{200, true,
				"{\n  \"tigera-ee-compliance-snapshotter\" : {\n    \"username\" : \"tigera-ee-compliance-snapshotter\",\n    \"roles\" : [\n      \"tigera-ee-compliance-snapshotter\"\n    ],\n    \"full_name\" : null,\n    \"email\" : null,\n    \"metadata\" : { },\n    \"enabled\" : true\n  },\n  \"tigera-ee-compliance-controller\" : {\n    \"username\" : \"tigera-ee-compliance-controller\",\n    \"roles\" : [\n      \"tigera-ee-compliance-controller\"\n    ],\n    \"full_name\" : null,\n    \"email\" : null,\n    \"metadata\" : { },\n    \"enabled\" : true\n  }\n}"},
			expected{false, "", "GET", []string{"/_security/user"}},
			[]elasticsearch.User{
				{
					Username: "tigera-ee-compliance-snapshotter",
					Roles: []elasticsearch.Role{
						{
							Name: "tigera-ee-compliance-snapshotter",
						},
					},
				},
				{
					Username: "tigera-ee-compliance-controller",
					Roles: []elasticsearch.Role{
						{
							Name: "tigera-ee-compliance-controller",
						},
					},
				},
			}),
	)
})
