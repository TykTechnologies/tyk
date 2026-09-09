package mcp

import "strings"

// HostRootDiscoveryPrefixes lists the well-known paths that MCP/OAuth clients
// expect to find at the host root of an upstream server, regardless of the
// resource path. See RFC 9728 (Protected Resource Metadata) and RFC 8414
// (Authorization Server Metadata).
var HostRootDiscoveryPrefixes = []string{
	"/.well-known/oauth-protected-resource",
	"/.well-known/oauth-authorization-server",
	"/.well-known/openid-configuration",
}

// IsHostRootDiscoveryPath reports whether the given request path is a
// well-known OAuth/OIDC discovery probe that must be served at the upstream
// host root, ignoring any path component embedded in the configured upstream
// URL.
//
// Match rules:
//   - Leading slash is optional.
//   - The path may carry a suffix (e.g. /.well-known/oauth-protected-resource/v1/mcp)
//     per the path-suffix variant in RFC 9728 §3.1.
func IsHostRootDiscoveryPath(p string) bool {
	if p == "" {
		return false
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for _, prefix := range HostRootDiscoveryPrefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}
