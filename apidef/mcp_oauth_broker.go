package apidef

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	internalhttputil "github.com/TykTechnologies/tyk/internal/httputil"
)

// Validate validates the fixed identities used by an enabled MCP OAuth
// broker. When listenPath is supplied, the public resource must be the exact
// concatenation of the configured origin and listen path.
func (c *MCPOAuthBrokerConfig) Validate(listenPath string) error {
	if c == nil || !c.Enabled {
		return nil
	}
	if err := validateMCPBrokerURL("public origin", c.PublicOrigin, true, c.AllowInsecureLoopback); err != nil {
		return err
	}
	canonicalOrigin, err := internalhttputil.CanonicalOrigin(c.PublicOrigin)
	if err != nil || canonicalOrigin != c.PublicOrigin {
		return fmt.Errorf("MCP OAuth broker public origin must use its exact canonical form")
	}
	if err := validateMCPBrokerURL("public resource", c.PublicResource, false, c.AllowInsecureLoopback); err != nil {
		return err
	}
	if err := validateMCPBrokerURL("upstream resource", c.UpstreamResource, false, c.AllowInsecureLoopback); err != nil {
		return err
	}
	if listenPath != "" {
		if !strings.HasPrefix(listenPath, "/") {
			return fmt.Errorf("MCP OAuth broker listen path must start with /")
		}
		if c.PublicResource != c.PublicOrigin+listenPath {
			return fmt.Errorf("MCP OAuth broker public resource must equal public origin plus listen path")
		}
	}
	return nil
}

func validateMCPBrokerURL(name, value string, originOnly, allowInsecureLoopback bool) error {
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("MCP OAuth broker %s must be an absolute HTTP(S) URL without userinfo, query, or fragment", name)
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || !allowInsecureLoopback || !isLoopbackHostname(u.Hostname()) {
			return fmt.Errorf("MCP OAuth broker %s must use HTTPS", name)
		}
	}
	if originOnly && (u.Path != "" || u.RawPath != "") {
		return fmt.Errorf("MCP OAuth broker public origin must not contain a path")
	}
	return nil
}

func isLoopbackHostname(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
