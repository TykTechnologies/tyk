package main

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

// IPWhiteListMiddleware lets you define a list of IPs to allow upstream
type IPWhiteListMiddleware struct {
	*TykMiddleware
}

func (mw *IPWhiteListMiddleware) GetName() string {
	return "IPWhiteListMiddleware"
}

// New lets you do any initialisations for the object can be done here
func (i *IPWhiteListMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (i *IPWhiteListMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

func (i *IPWhiteListMiddleware) IsEnabledForSpec() bool {
	if !i.TykMiddleware.Spec.EnableIpWhiteListing {
		return false
	}

	if len(i.TykMiddleware.Spec.AllowedIPs) == 0 {
		return false
	}

	return true
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (i *IPWhiteListMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	// Disabled, pass through
	if !i.TykMiddleware.Spec.EnableIpWhiteListing {
		return nil, 200
	}

	var remoteIP net.IP

	// Enabled, check incoming IP address
	for _, ip := range i.TykMiddleware.Spec.AllowedIPs {
		// Might be CIDR, try this one first then fallback to IP parsing later
		allowedIP, allowedNet, err := net.ParseCIDR(ip)
		if err != nil {
			allowedIP = net.ParseIP(ip)
		}

		splitIP := strings.Split(r.RemoteAddr, ":")
		remoteIPString := splitIP[0]

		// If X-Forwarded-For is set, override remoteIPString
		forwarded := r.Header.Get("X-Forwarded-For")
		if forwarded != "" {
			ips := strings.Split(forwarded, ", ")
			remoteIPString = ips[0]
			log.Info("X-Forwarded-For set, remote IP: ", remoteIPString)
		}

		if len(splitIP) > 2 {
			// Might be an IPv6 address, don't mess with it
			remoteIPString = r.RemoteAddr
		}
		remoteIP = net.ParseIP(remoteIPString)

		// Check CIDR if possible
		if allowedNet != nil && allowedNet.Contains(remoteIP) {
			// matched, pass through
			return nil, 200
		}

		// We parse the IP to manage IPv4 and IPv6 easily
		if allowedIP.Equal(remoteIP) {
			// matched, pass through
			return nil, 200
		}
	}

	// Fire Authfailed Event
	AuthFailed(i.TykMiddleware, r, remoteIP.String())
	// Report in health check
	ReportHealthCheckValue(i.Spec.Health, KeyFailure, "-1")

	// Not matched, fail
	return errors.New("Access from this IP has been disallowed"), 403
}
