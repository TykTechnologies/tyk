package netutil

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetIpAddress(t *testing.T) {
	defer func() { netInterfaceAddrs = net.InterfaceAddrs }()

	tests := []struct {
		name              string
		netInterfaceAddrs func() ([]net.Addr, error)
		want              []string
		wantErr           bool
	}{
		{
			name:              "fail",
			netInterfaceAddrs: func() ([]net.Addr, error) { return nil, fmt.Errorf("failed to get IP addresses") },
			want:              nil,
			wantErr:           true,
		},
		{
			name: "local-ip",
			netInterfaceAddrs: func() ([]net.Addr, error) {
				return []net.Addr{
					&net.IPNet{IP: net.ParseIP("192.168.1.100"), Mask: net.IPv4Mask(255, 255, 255, 0)},     // IPv4 Address
					&net.IPNet{IP: net.ParseIP("fe80::100f:a1dc:ce82:4acd"), Mask: net.CIDRMask(128, 128)}, // IPv6 address
					&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.IPv4Mask(255, 255, 255, 0)},         // IPv4 loopback address
					&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},                       // IPv6 loopback address
				}, nil
			},
			want:    []string{"192.168.1.100", "fe80::100f:a1dc:ce82:4acd"},
			wantErr: false,
		},
		{
			name: "docker-container-ip",
			netInterfaceAddrs: func() ([]net.Addr, error) {
				return []net.Addr{
					&net.IPNet{IP: net.ParseIP("172.17.0.3"), Mask: net.IPv4Mask(255, 255, 255, 0)},
					&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}, // loopback address
				}, nil
			},
			want:    []string{"172.17.0.3"},
			wantErr: false,
		},
		{
			name: "pod-ip",
			netInterfaceAddrs: func() ([]net.Addr, error) {
				return []net.Addr{
					&net.IPNet{IP: net.ParseIP("10.42.1.117"), Mask: net.IPv4Mask(255, 255, 255, 0)},
					&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}, // loopback address
				}, nil
			},
			want:    []string{"10.42.1.117"},
			wantErr: false,
		},
		{
			name: "loopback-only",
			netInterfaceAddrs: func() ([]net.Addr, error) {
				return []net.Addr{
					&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}, // loopback address
				}, nil
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// use mocked net.InterfaceAddrs
			netInterfaceAddrs = tt.netInterfaceAddrs

			got, err := GetIpAddress()
			if tt.wantErr {
				assert.Error(t, err, "getIpAddress() should return an error")
			} else {
				assert.NoError(t, err, "getIpAddress() should not return an error")
				assert.Equal(t, tt.want, got, "getIpAddress() should return the correct IP address")
			}
		})
	}
}
