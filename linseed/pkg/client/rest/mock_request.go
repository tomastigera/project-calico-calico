package rest

import (
	"context"
	"net/http"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
)

// Produce a new mock request, used to mock request results from Linseed.
func NewMockRequest(c RESTClient, result *MockResult) Request {
	return &MockRequest{
		realRequest: NewRequest(c).(*request),
		Result:      result,
	}
}

type MockRequest struct {
	// Wrap a real request so that we can rely on its logic where needed.
	realRequest *request

	// Mock Result to return on call to Do()
	Result *MockResult
}

func (m *MockRequest) GetParams() any {
	return m.realRequest.params
}

func (m *MockRequest) GetBody() any {
	return m.realRequest.body
}

func (m *MockRequest) Verb(v string) Request {
	m.realRequest.Verb(v)
	return m
}

func (m *MockRequest) Params(p any) Request {
	m.realRequest.Params(p)
	return m
}

func (m *MockRequest) BodyJSON(b any) Request {
	m.realRequest.BodyJSON(b)
	return m
}

func (m *MockRequest) Path(p string) Request {
	m.realRequest.Path(p)
	return m
}

func (m *MockRequest) Cluster(c string) Request {
	m.realRequest.Cluster(c)
	return m
}

func (m *MockRequest) ContentType(t string) Request {
	m.realRequest.ContentType(t)
	return m
}

// This is where the magic happens. Do() simulates a
// real response from Linseed. The mock client stack provides a
// hook for callers to return custom results here.
func (m *MockRequest) Do(ctx context.Context) *Result {
	// Populate metadata about the request.
	m.Result.Called = true
	m.Result.Path = m.realRequest.path
	m.Result.Verb = m.realRequest.verb
	return &Result{
		err:        m.Result.Err,
		body:       m.Result.body(),
		statusCode: m.Result.statusCode(),
		path:       "/mock/request",
	}
}

type MockResult struct {
	Err        error
	Body       any
	StatusCode int

	// Metadata about the call that was made. Will be populated
	// by the client as calls are made.
	Called bool
	Verb   string
	Path   string
}

func (m *MockResult) body() []byte {
	if bs, ok := m.Body.([]byte); ok {
		return bs
	}
	bs, err := json.Marshal(m.Body)
	if err != nil {
		panic(err)
	}
	return bs
}

func (m *MockResult) statusCode() int {
	if m.StatusCode != 0 {
		return m.StatusCode
	}
	return http.StatusOK
}
