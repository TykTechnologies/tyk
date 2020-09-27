package gateway

import (
	"errors"
	"net"
	"net/http"

	"github.com/TykTechnologies/tyk/v3/request"
)

// IPBlackListMiddleware lets you define a list of IPs to block from upstream
type IPBlackListMiddleware struct {
	BaseMiddleware
}

func (i *IPBlackListMiddleware) Name() string {
	return "IPBlackListMiddleware"
}

func (i *IPBlackListMiddleware) EnabledForSpec() bool {
	return i.Spec.EnableIpBlacklisting && len(i.Spec.BlacklistedIPs) > 0
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (i *IPBlackListMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	remoteIP := net.ParseIP(request.RealIP(r))

	// Enabled, check incoming IP address
	for _, ip := range i.Spec.BlacklistedIPs {
		// Might be CIDR, try this one first then fallback to IP parsing later
		blockedIP, blockedNet, err := net.ParseCIDR(ip)
		if err != nil {
			blockedIP = net.ParseIP(ip)
		}

		// Check CIDR if possible
		if blockedNet != nil && blockedNet.Contains(remoteIP) {

			return i.handleError(r, remoteIP.String())
		}

		// We parse the IP to manage IPv4 and IPv6 easily
		if blockedIP.Equal(remoteIP) {

			return i.handleError(r, remoteIP.String())
		}
	}

	return nil, http.StatusOK
}

func (i *IPBlackListMiddleware) handleError(r *http.Request, blacklistedIP string) (error, int) {

	// Fire Authfailed Event
	AuthFailed(i, r, blacklistedIP)
	// Report in health check
	reportHealthValue(i.Spec, KeyFailure, "-1")
	return errors.New("access from this IP has been disallowed"), http.StatusForbidden
}
