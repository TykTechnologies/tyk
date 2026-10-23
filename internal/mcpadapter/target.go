package mcpadapter

import "strings"

const (
	// LoopPath is the default tyk:// path used to address the REST-as-MCP
	// adapter paired with the REST API in the URL host.
	LoopPath = "/mcp"

	// APIIDSuffix is appended to a REST APIID to form the fallback synthetic
	// adapter host when the source API already owns /mcp.
	APIIDSuffix = "__mcp-server"
)

// IsLoopPath reports whether a tyk:// URL path addresses a REST-as-MCP
// adapter.
func IsLoopPath(path string) bool {
	return path == LoopPath || path == LoopPath+"/"
}

// IsAPIID reports whether id is a fallback synthetic adapter APIID.
func IsAPIID(id string) bool {
	return strings.HasSuffix(id, APIIDSuffix) && len(id) > len(APIIDSuffix)
}

// SourceAPIID returns the REST APIID corresponding to a fallback synthetic
// adapter APIID, or "" if id is not an adapter ID.
func SourceAPIID(id string) string {
	if !IsAPIID(id) {
		return ""
	}
	return strings.TrimSuffix(id, APIIDSuffix)
}

// ParseTarget extracts the host and path from a tyk:// adapter target. It
// accepts the legacy id: host prefix and ignores query and fragment components.
func ParseTarget(target string) (host, path string, ok bool) {
	target = strings.TrimSpace(target)
	const scheme = "tyk://"
	if !strings.HasPrefix(target, scheme) {
		return "", "", false
	}

	rest := strings.TrimPrefix(target, scheme)
	rest = strings.TrimPrefix(rest, "id:")
	if rest == "" {
		return "", "", false
	}

	hostEnd := len(rest)
	if i := strings.IndexAny(rest, "/?#"); i != -1 {
		hostEnd = i
	}
	host = rest[:hostEnd]
	if host == "" {
		return "", "", false
	}

	if hostEnd < len(rest) && rest[hostEnd] == '/' {
		pathEnd := len(rest)
		if i := strings.IndexAny(rest[hostEnd:], "?#"); i != -1 {
			pathEnd = hostEnd + i
		}
		path = rest[hostEnd:pathEnd]
	}

	return host, path, true
}
