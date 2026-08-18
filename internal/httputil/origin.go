package httputil

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// CanonicalOrigin validates and canonicalizes a concrete HTTP(S) origin.
// Paths, credentials, queries, fragments, wildcards, and opaque origins are
// deliberately rejected.
func CanonicalOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" || strings.Contains(raw, "*") {
		return "", fmt.Errorf("invalid origin %q", raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid origin %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("origin %q must use http or https", raw)
	}
	if u.Opaque != "" || u.User != nil || u.Host == "" || u.Path != "" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("origin %q must contain only scheme, host, and optional port", raw)
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" || strings.ContainsAny(hostname, " /?#@") {
		return "", fmt.Errorf("origin %q has an invalid host", raw)
	}
	if addr, parseErr := netip.ParseAddr(hostname); parseErr == nil {
		hostname = addr.String()
	}

	port := u.Port()
	if port != "" {
		portNumber, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || portNumber == 0 {
			return "", fmt.Errorf("origin %q has an invalid port", raw)
		}
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			port = ""
		}
	}

	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	return scheme + "://" + host, nil
}

// CanonicalOrigins validates origins and returns their canonical forms.
func CanonicalOrigins(origins []string) ([]string, error) {
	canonical := make([]string, 0, len(origins))
	seen := make(map[string]struct{}, len(origins))
	for index, origin := range origins {
		value, err := CanonicalOrigin(origin)
		if err != nil {
			return nil, fmt.Errorf("trusted origin %d: %w", index, err)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		canonical = append(canonical, value)
	}
	return canonical, nil
}

// ParseTrustedProxyCIDRs validates trusted proxy networks.
func ParseTrustedProxyCIDRs(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for index, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("trusted proxy CIDR %d %q: %w", index, cidr, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

// ExternalOrigin returns the canonical origin visible to the requester. Proxy
// headers are considered only when the immediate network peer is trusted.
func ExternalOrigin(r *http.Request, trustedProxyCIDRs []string) (string, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host

	prefixes, err := ParseTrustedProxyCIDRs(trustedProxyCIDRs)
	if err != nil {
		return "", err
	}
	if peerIsTrusted(r.RemoteAddr, prefixes) {
		forwardedProto, forwardedHost := rightmostForwarded(r.Header.Values("Forwarded"))
		if forwardedProto != "" {
			scheme = forwardedProto
		} else if value := rightmostHeaderValue(r.Header.Values("X-Forwarded-Proto")); value != "" {
			scheme = value
		}
		if forwardedHost != "" {
			host = forwardedHost
		} else if value := rightmostHeaderValue(r.Header.Values("X-Forwarded-Host")); value != "" {
			host = value
		}
	}

	return CanonicalOrigin(scheme + "://" + strings.TrimSpace(host))
}

func peerIsTrusted(remoteAddr string, prefixes []netip.Prefix) bool {
	if len(prefixes) == 0 {
		return false
	}
	host := remoteAddr
	if splitHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = splitHost
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func rightmostHeaderValue(values []string) string {
	parts := splitHeaderList(strings.Join(values, ","), ',')
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}

func rightmostForwarded(values []string) (proto, host string) {
	element := rightmostHeaderValue(values)
	if element == "" {
		return "", ""
	}
	for _, parameter := range splitHeaderList(element, ';') {
		key, value, ok := strings.Cut(parameter, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "\"") {
			unquoted, err := strconv.Unquote(value)
			if err != nil {
				continue
			}
			value = unquoted
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "proto":
			proto = value
		case "host":
			host = value
		}
	}
	return proto, host
}

func splitHeaderList(value string, separator byte) []string {
	var parts []string
	start := 0
	quoted := false
	escaped := false
	for index := 0; index < len(value); index++ {
		switch {
		case escaped:
			escaped = false
		case quoted && value[index] == '\\':
			escaped = true
		case value[index] == '"':
			quoted = !quoted
		case !quoted && value[index] == separator:
			parts = append(parts, value[start:index])
			start = index + 1
		}
	}
	parts = append(parts, value[start:])
	return parts
}
