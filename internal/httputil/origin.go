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
	if hostname == "" || strings.ContainsAny(hostname, " /?#@,;\\") || strings.HasSuffix(u.Host, ":") {
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
		port = strconv.FormatUint(portNumber, 10)
		if (scheme == "http" && portNumber == 80) || (scheme == "https" && portNumber == 443) {
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
	prefixes, err := ParseTrustedProxyCIDRs(trustedProxyCIDRs)
	if err != nil {
		return "", err
	}
	return ExternalOriginWithTrustedProxies(r, prefixes)
}

// ExternalOriginWithTrustedProxies is ExternalOrigin's request-path form for
// callers that parsed their immutable proxy configuration at load time.
func ExternalOriginWithTrustedProxies(r *http.Request, trustedProxyPrefixes []netip.Prefix) (string, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host

	if peerIsTrusted(r.RemoteAddr, trustedProxyPrefixes) {
		forwardedProto, forwardedHost, err := validatedForwarded(r.Header.Values("Forwarded"))
		if err != nil {
			return "", err
		}
		xproto, err := validatedProxyHeader(r.Header.Values("X-Forwarded-Proto"), true)
		if err != nil {
			return "", err
		}
		xhost, err := validatedProxyHeader(r.Header.Values("X-Forwarded-Host"), false)
		if err != nil {
			return "", err
		}
		if forwardedProto != "" {
			scheme = forwardedProto
		} else if value := xproto; value != "" {
			scheme = value
		}
		if forwardedHost != "" {
			host = forwardedHost
		} else if value := xhost; value != "" {
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

// Validate every supplied hop; use the last value supplied by the immediate
// trusted proxy. Malformed trusted headers must never silently fall back.
func validatedProxyHeader(values []string, protocol bool) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	var last string
	for _, value := range strings.Split(strings.Join(values, ","), ",") {
		value = strings.TrimSpace(value)
		if protocol {
			if value != "http" && value != "https" {
				return "", fmt.Errorf("invalid forwarded protocol")
			}
		} else {
			if _, err := CanonicalOrigin("http://" + value); err != nil {
				return "", fmt.Errorf("invalid forwarded host")
			}
		}
		last = value
	}
	return last, nil
}

func validatedForwarded(values []string) (proto, host string, err error) {
	if len(values) == 0 {
		return "", "", nil
	}
	for _, element := range splitHeaderList(strings.Join(values, ","), ',') {
		proto, host = "", ""
		seen := map[string]bool{}
		for _, parameter := range splitHeaderList(element, ';') {
			key, value, ok := strings.Cut(parameter, "=")
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			if !ok || key == "" || value == "" || seen[key] {
				return "", "", fmt.Errorf("invalid Forwarded header")
			}
			seen[key] = true
			if strings.HasPrefix(value, `"`) {
				value, err = strconv.Unquote(value)
				if err != nil {
					return "", "", fmt.Errorf("invalid Forwarded quoting")
				}
			} else if strings.ContainsAny(value, " \t\"\\") {
				return "", "", fmt.Errorf("invalid Forwarded value")
			}
			switch key {
			case "proto":
				proto, err = validatedProxyHeader([]string{value}, true)
			case "host":
				host, err = validatedProxyHeader([]string{value}, false)
			}
			if err != nil {
				return "", "", err
			}
		}
	}
	return proto, host, nil
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
