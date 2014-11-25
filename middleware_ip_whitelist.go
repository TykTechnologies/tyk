package main

import (
	"errors"
	"net/http"
	"net"
	"strings"
)


// IPWhiteListMiddleware lets you define a list of IPs to allow upstream
type IPWhiteListMiddleware struct {
	TykMiddleware
}

// New lets you do any initialisations for the object can be done here
func (i *IPWhiteListMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (i *IPWhiteListMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (i *IPWhiteListMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	ipConfig := i.TykMiddleware.Spec

	// Disabled, pass through
	if !ipConfig.EnableIpWhiteListing {
		return nil, 200
	}

	var remoteIP net.IP

	// Enabled, check incoming IP address
	for _, ip := range(ipConfig.AllowedIPs) {
		allowedIP := net.ParseIP(ip)
		splitIP := strings.Split(r.RemoteAddr, ":")
		remoteIPString := splitIP[0]
		if len(splitIP) > 2 {
			// Might be an IPv6 address, don't mess with it
			remoteIPString = r.RemoteAddr
		}
		remoteIP = net.ParseIP(remoteIPString)

		// We parse the IP to manage IPv4 and IPv6 easily
		if allowedIP.String() == remoteIP.String() {
			// matched, pass through
			return nil, 200
		}
	}

	// Fire Authfailed Event
	AuthFailed(i.TykMiddleware, r, remoteIP.String())

	// Not matched, fail
	return errors.New("Access from this IP has been disallowed"), 403
}


