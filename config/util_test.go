package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: STK-REQ-034, SYS-REQ-122, SW-REQ-109
// SYS-REQ-122:nominal:nominal
// SW-REQ-109:nominal:nominal
// SW-REQ-109:boundary:nominal
// SW-REQ-109:error_handling:nominal
// SW-REQ-109:error_handling:negative
// STK-REQ-034:error_handling:negative
// MCDC SYS-REQ-122: configuration_utility_operation_requested=F, configuration_utility_result_determined=F => TRUE
// MCDC SYS-REQ-122: configuration_utility_operation_requested=T, configuration_utility_result_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-122: configuration_utility_operation_requested=T, configuration_utility_result_determined=F => FALSE -- violation row is the negation of the local configuration utility guarantee; these tests assert requested utility operations either discover config files, fall back to env defaults, clone defaults with env overrides, assemble host addresses, or return explicit local errors [category: defensive] [reviewed: agent:codex]
func TestConfigNew(t *testing.T) {
	t.Run("loads discovered config file", func(t *testing.T) {
		conf, err := New()

		require.NoError(t, err)
		require.NotNil(t, conf)
		require.NotEmpty(t, conf.Private.OriginalPath)
		require.Equal(t, "tyk.conf", filepath.Base(conf.Private.OriginalPath))
	})

	t.Run("falls back to environment when config file is missing", func(t *testing.T) {
		repoConfigPath := filepath.Clean(filepath.Join("..", "tyk.conf"))
		hiddenConfigPath := repoConfigPath + ".reqproof-hidden"

		require.FileExists(t, repoConfigPath)
		require.NoFileExists(t, hiddenConfigPath)
		require.NoError(t, os.Rename(repoConfigPath, hiddenConfigPath))
		t.Cleanup(func() {
			require.NoError(t, os.Rename(hiddenConfigPath, repoConfigPath))
		})
		t.Setenv("TYK_GW_LISTENPORT", "9091")

		conf, err := New()

		require.NoError(t, err)
		require.NotNil(t, conf)
		assert.Equal(t, 9091, conf.ListenPort)
	})
}

// Verifies: STK-REQ-034, SYS-REQ-122, SW-REQ-109
// SW-REQ-109:nominal:nominal
func TestNewDefaultWithEnv(t *testing.T) {
	t.Setenv("TYK_GW_LISTENPORT", "9092")
	t.Setenv("TYK_GW_DNSCACHE_ENABLED", "true")

	conf, err := NewDefaultWithEnv()

	require.NoError(t, err)
	require.NotNil(t, conf)
	assert.Equal(t, 9092, conf.ListenPort)
	assert.True(t, conf.DnsCache.Enabled)
	assert.Equal(t, 8080, Default.ListenPort)
	assert.False(t, Default.DnsCache.Enabled)
}

// Verifies: STK-REQ-034, SYS-REQ-122, SW-REQ-109
// SW-REQ-109:nominal:nominal
// SW-REQ-109:error_handling:negative
func TestFindFile(t *testing.T) {
	t.Run("finds config in parent directories", func(t *testing.T) {
		got, err := findFile("tyk.conf")

		require.NoError(t, err)
		assert.Equal(t, "tyk.conf", filepath.Base(got))
	})

	t.Run("returns not exist for missing file", func(t *testing.T) {
		_, err := findFile("definitely-not-present-reqproof.conf")

		require.Error(t, err)
		assert.True(t, errors.Is(err, os.ErrNotExist))
	})
}

// Verifies: STK-REQ-034, SYS-REQ-122, SW-REQ-109
// SW-REQ-109:nominal:nominal
// SW-REQ-109:boundary:nominal
func TestHostAddrs(t *testing.T) {
	tests := []struct {
		name   string
		config StorageOptionsConf
		want   []string
	}{
		{
			name:   "empty",
			config: StorageOptionsConf{},
		},
		{
			name: "addrs",
			config: StorageOptionsConf{
				Addrs: []string{"host1:1234", "host2:5678"},
			},
			want: []string{"host1:1234", "host2:5678"},
		},
		{
			name: "hosts map",
			config: StorageOptionsConf{
				Hosts: map[string]string{
					"host1": "1234",
					"host2": "5678",
				},
			},
			want: []string{"host1:1234", "host2:5678"},
		},
		{
			name: "addrs and host maps",
			config: StorageOptionsConf{
				Addrs: []string{"host1:1234", "host2:5678"},
				Hosts: map[string]string{
					"host3": "1234",
					"host4": "5678",
				},
			},
			want: []string{"host1:1234", "host2:5678"},
		},
		{
			name: "host and port",
			config: StorageOptionsConf{
				Host: "localhost",
				Port: 6379,
			},
			want: []string{"localhost:6379"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.HostAddrs()
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}
