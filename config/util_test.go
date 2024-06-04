package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
