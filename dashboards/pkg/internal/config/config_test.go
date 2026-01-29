package config

import (
	"testing"

	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	t.Run("decode", func(t *testing.T) {
		t.Setenv("DISABLED_DASHBOARDS", `key1:v1,v2 , v3;key2:v4`)
		cfg := &Config{}
		err := envconfig.Process("", cfg)
		require.NoError(t, err)
		require.Equal(t, stringSliceMapConfig{
			"key1": {"v1", "v2", "v3"},
			"key2": {"v4"},
		}, cfg.DisabledDashboards)
	})
}
