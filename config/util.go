package config

import (
	"strconv"
)

// HostAddrs returns a sanitized list of hosts to connect to.
func (config *StorageOptionsConf) HostAddrs() (addrs []string) {
	if len(config.Addrs) != 0 {
		addrs = config.Addrs
	} else {
		for h, p := range config.Hosts {
			addr := h + ":" + p
			addrs = append(addrs, addr)
		}
	}

	if len(addrs) == 0 && config.Port != 0 {
		addr := config.Host + ":" + strconv.Itoa(config.Port)
		addrs = append(addrs, addr)
	}

	return addrs
}
