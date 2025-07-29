package metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security/fake"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/pkg/types"
)

func TestMetadataService(t *testing.T) {

	logger := logging.New("TestMetadataService")

	var serverRequest http.Request
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError := func(err error) bool {
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(err.Error()))
				return true
			}
			return false
		}

		requestBody, err := io.ReadAll(r.Body)
		if writeError(err) {
			return
		}
		err = r.Body.Close()
		if writeError(err) {
			return
		}

		serverRequest = *r
		if len(requestBody) == 0 {
			r.Body = http.NoBody
			serverRequest.Body = http.NoBody
		} else {
			r.Body = io.NopCloser(bytes.NewBuffer(requestBody))
			serverRequest.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}

		switch serverRequest.Method {
		case http.MethodGet:
			var err error
			if strings.HasSuffix(r.URL.Path, "/server-path") {
				err = writeJson(w, &client.DashboardListResponse{})
			} else {
				err = writeJson(w, &client.Dashboard{
					ID: client.DashboardID(strings.TrimPrefix(r.URL.Path, "/server-path/")),
				})
			}
			if writeError(err) {
				return
			}
		case http.MethodPost:
			createReq := &client.DashboardCreateRequest{}
			err = json.NewDecoder(bytes.NewBuffer(requestBody)).Decode(createReq)
			if writeError(err) {
				return
			}

			err = writeJson(w, &client.Dashboard{
				ID:             "fake-create-dashboard-id",
				Title:          createReq.Title,
				Cards:          createReq.Cards,
				Layout:         createReq.Layout,
				DefaultFilters: createReq.DefaultFilters,
			})
			if writeError(err) {
				return
			}
		case http.MethodPut:
			updateReq := &client.DashboardUpdateRequest{}
			err = json.NewDecoder(bytes.NewBuffer(requestBody)).Decode(updateReq)
			if writeError(err) {
				return
			}

			err = writeJson(w, &client.Dashboard{
				ID:             "fake-update-dashboard-id",
				Title:          updateReq.Title,
				Cards:          updateReq.Cards,
				Layout:         updateReq.Layout,
				DefaultFilters: updateReq.DefaultFilters,
			})
			if writeError(err) {
				return
			}
		}
	}))

	t.Cleanup(httpServer.Close)

	fakeDashboardID := types.DashboardID("fake-dashboard-id")

	subject := NewMetadataService(logger, httpServer.URL+"/server-path")

	ctx := security.NewUserAuthContext(
		context.Background(),
		&user.DefaultInfo{Name: "fake-user"},
		fake.NewAuthorizer(true),
		k8sfake.NewSimpleClientset(),
		"Bearer fake-token",
	)

	t.Run("authorization", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			_, err := subject.List(ctx, types.ProjectIDDefault)
			require.NoError(t, err)

			require.Equal(t, "Bearer fake-token", serverRequest.Header.Get("Authorization"))
		})

		t.Run("unauthorized", func(t *testing.T) {
			ctx := security.NewUserAuthContext(
				context.Background(),
				&user.DefaultInfo{Name: "fake-user"},
				fake.NewAuthorizer(false),
				k8sfake.NewSimpleClientset(),
				"Bearer fake-token",
			)

			_, err := subject.List(ctx, types.ProjectIDDefault)
			require.Equal(t, httpreply.ReplyAccessDenied, err)
		})
	})

	t.Run("list", func(t *testing.T) {
		_, err := subject.List(ctx, types.ProjectIDDefault)
		require.NoError(t, err)

		require.Equal(t, "/server-path", serverRequest.URL.Path)
		require.Equal(t, http.MethodGet, serverRequest.Method)
	})

	t.Run("get", func(t *testing.T) {
		dashboard, err := subject.Get(ctx, types.ProjectIDDefault, fakeDashboardID)
		require.NoError(t, err)

		require.Equal(t, "/server-path/fake-dashboard-id", serverRequest.URL.Path)
		require.Equal(t, http.MethodGet, serverRequest.Method)
		require.Equal(t, client.Dashboard{
			ID: "fake-dashboard-id",
		}, dashboard)
	})

	t.Run("create", func(t *testing.T) {
		dashboard, err := subject.Create(ctx, types.ProjectIDDefault, client.DashboardCreateRequest{
			Title: "fake-dashboard-title-create",
		})
		require.NoError(t, err)

		require.Equal(t, "/server-path", serverRequest.URL.Path)
		require.Equal(t, http.MethodPost, serverRequest.Method)
		require.Equal(t, client.Dashboard{
			ID:    "fake-create-dashboard-id",
			Title: "fake-dashboard-title-create",
		}, dashboard)
	})

	t.Run("update", func(t *testing.T) {
		dashboard, err := subject.Update(ctx, types.ProjectIDDefault, "fake-update-dashboard-id", client.DashboardUpdateRequest{
			Title: "fake-dashboard-title-update",
		})
		require.NoError(t, err)

		require.Equal(t, "/server-path/fake-update-dashboard-id", serverRequest.URL.Path)
		require.Equal(t, http.MethodPut, serverRequest.Method)
		require.Equal(t, client.Dashboard{
			ID:    "fake-update-dashboard-id",
			Title: "fake-dashboard-title-update",
		}, dashboard)
	})

	t.Run("delete", func(t *testing.T) {
		err := subject.Delete(ctx, types.ProjectIDDefault, fakeDashboardID)
		require.NoError(t, err)

		require.Equal(t, "/server-path/fake-dashboard-id", serverRequest.URL.Path)
		require.Equal(t, http.MethodDelete, serverRequest.Method)
		require.Equal(t, http.NoBody, serverRequest.Body)
	})
}

func writeJson(w http.ResponseWriter, object any) error {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")

	b, err := json.Marshal(object)
	if err != nil {
		return err
	}

	_, err = w.Write(b)
	if err != nil {
		return err
	}

	return nil
}
