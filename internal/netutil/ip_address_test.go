package netutil

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

type fakeAddr string

func (f fakeAddr) Network() string { return string(f) }
func (f fakeAddr) String() string  { return string(f) }

// Verifies: SYS-REQ-095, SYS-REQ-096, SYS-REQ-097, SW-REQ-005
// SYS-REQ-095:nominal:nominal
// SYS-REQ-095:boundary:nominal
// SYS-REQ-095:determinism:nominal
// SYS-REQ-096:nominal:nominal
// SYS-REQ-096:boundary:nominal
// SYS-REQ-096:malformed_input:nominal
// SYS-REQ-096:malformed_input:negative
// SYS-REQ-097:nominal:nominal
// SYS-REQ-097:error_handling:nominal
// SYS-REQ-097:error_handling:negative
// SW-REQ-005:nominal:nominal
// SW-REQ-005:boundary:nominal
// SW-REQ-005:malformed_input:nominal
// SW-REQ-005:malformed_input:negative
// SW-REQ-005:error_handling:nominal
// SW-REQ-005:error_handling:negative
// SW-REQ-005:determinism:nominal
// MCDC SYS-REQ-095: usable_node_address_discovery_requested=F, usable_node_addresses_reported=F => TRUE
// MCDC SYS-REQ-095: usable_node_address_discovery_requested=T, usable_node_addresses_reported=T => TRUE
// MCDC SYS-REQ-096: unusable_node_address_record_present=F, unusable_node_address_record_excluded=F => TRUE
// MCDC SYS-REQ-096: unusable_node_address_record_present=T, unusable_node_address_record_excluded=T => TRUE
// MCDC SYS-REQ-097: node_interface_enumeration_failed=F, node_interface_error_returned=F => TRUE
// MCDC SYS-REQ-097: node_interface_enumeration_failed=T, node_interface_error_returned=T => TRUE
// MCDC SW-REQ-005: netutil_address_lookup_requested=F, netutil_address_lookup_result_returned=F => TRUE
// MCDC SW-REQ-005: netutil_address_lookup_requested=T, netutil_address_lookup_result_returned=T => TRUE
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
		{
			name: "non-ipnet-and-malformed-addresses",
			netInterfaceAddrs: func() ([]net.Addr, error) {
				return []net.Addr{
					fakeAddr("not-ipnet"),
					&net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(24, 32)},
					&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.IPv4Mask(255, 255, 255, 0)},
				}, nil
			},
			want:    []string{"10.0.0.5"},
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
