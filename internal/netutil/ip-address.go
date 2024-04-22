package netutil

import "net"

// getIpAddress returns the first non-loopback IPv4 address found. Returns error if it fails
// to get the list of addresses. Returns empty if there's no valid IP addresses.
// netInterfaceAddrs is used to allow mocking in the tests
var (
	netInterfaceAddrs = net.InterfaceAddrs
)

func GetIpAddress() ([]string, error) {
	var ips []string
	// Get the IP address
	addrs, err := netInterfaceAddrs()
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
