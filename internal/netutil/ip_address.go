package netutil

import "net"

var (
	netInterfaceAddrs = net.InterfaceAddrs // used to allow mocking in tests
)

// GetIpAddress returns the list of non-loopback IP address (IPv4 and IPv6) found.
// Returns error if it fails to get the list of addresses, empty if there's no valid IP addresses.
func GetIpAddress() ([]string, error) {
	var (
		ips        []string
		addrs, err = netInterfaceAddrs()
	)

	if err != nil {
		return []string{}, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipAdrr := ipnet.IP.To16(); ipAdrr != nil {
				ips = append(ips, ipAdrr.String())
			}
		}
	}

	return ips, nil
}
