package staticmetadata

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tigera/tds-apiserver/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/testutils"
)

func TestStaticMetadataService(t *testing.T) {
	ctx := security.NewUserAuthContext(
		context.Background(),
		&user.DefaultInfo{Name: "fake-user"},
		nil,
		nil,
		"Bearer fake-token",
		nil,
		"fake-tenant",
		nil,
	)

	subject, err := NewStaticMetadataService()
	require.NoError(t, err)

	dashboards, err := subject.List(ctx, types.ProjectIDDefault)
	require.NoError(t, err)
	testutils.ExpectMatchesGoldenYaml(t, "dashboard-list-static", dashboards)
}
