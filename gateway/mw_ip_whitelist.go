package gateway

import (
	"errors"
	"net"
	"net/http"

	"github.com/TykTechnologies/tyk/v3/request"
)

// IPWhiteListMiddleware lets you define a list of IPs to allow upstream
type IPWhiteListMiddleware struct {
	BaseMiddleware
}

func (i *IPWhiteListMiddleware) Name() string {
	return "IPWhiteListMiddleware"
}

func (i *IPWhiteListMiddleware) EnabledForSpec() bool {
	return i.Spec.EnableIpWhiteListing && len(i.Spec.AllowedIPs) > 0
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (i *IPWhiteListMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	remoteIP := net.ParseIP(request.RealIP(r))

	// Enabled, check incoming IP address
	for _, ip := range i.Spec.AllowedIPs {
		// Might be CIDR, try this one first then fallback to IP parsing later
		allowedIP, allowedNet, err := net.ParseCIDR(ip)
		if err != nil {
			allowedIP = net.ParseIP(ip)
		}

		// Check CIDR if possible
		if allowedNet != nil && allowedNet.Contains(remoteIP) {
			// matched, pass through
			return nil, http.StatusOK
		}

		// We parse the IP to manage IPv4 and IPv6 easily
		if allowedIP.Equal(remoteIP) {
			// matched, pass through
			return nil, http.StatusOK
		}
	}

	// Fire Authfailed Event
	AuthFailed(i, r, remoteIP.String())
	// Report in health check
	reportHealthValue(i.Spec, KeyFailure, "-1")

	// Not matched, fail
	return errors.New("access from this IP has been disallowed"), http.StatusForbidden
}
