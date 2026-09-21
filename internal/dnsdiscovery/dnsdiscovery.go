package dnsdiscovery

import (
	"errors"
	"net"
	"sort"
	"strings"
)

// Outcome records what a resolution established about a name.
type Outcome uint8

const (
	// Resolved means the name answered with at least one address.
	Resolved Outcome = iota

	// Empty means no records: a Service with no ready endpoints.
	Empty

	// NotFound means an authoritative NXDOMAIN.
	NotFound

	// Unreachable means the last good set is older than the stale TTL.
	Unreachable
)

// String implements fmt.Stringer.
func (o Outcome) String() string {
	switch o {
	case Resolved:
		return "resolved"
	case Empty:
		return "empty"
	case NotFound:
		return "not_found"
	case Unreachable:
		return "unreachable"
	default:
		return "unknown"
	}
}

// State is one published address set, swapped in atomically and never mutated.
// Version lets a subscriber cache what it renders.
type State struct {
	Version uint64
	Addrs   []string
	Outcome Outcome
}

// Usable reports whether this state carries addresses to use.
func (s *State) Usable() bool {
	return s != nil && len(s.Addrs) > 0
}

// ErrNoHost is returned by Subscribe when the configuration names no host.
var ErrNoHost = errors.New("dnsdiscovery: Host is required")

// Normalise sorts and de-duplicates. CoreDNS shuffles, so without the sort
// every refresh looks like a membership change.
func Normalise(addrs []string) []string {
	if len(addrs) == 0 {
		return nil
	}

	out := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	sort.Strings(out)
	return out
}

// Resolvable excludes IP literals and localhost, whose membership cannot
// change.
func Resolvable(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return !strings.EqualFold(host, "localhost")
}

// Removed returns members of was absent from now. Both must be normalised.
func Removed(was, now []string) []string {
	if len(was) == 0 {
		return nil
	}

	current := make(map[string]struct{}, len(now))
	for _, addr := range now {
		current[addr] = struct{}{}
	}

	var gone []string
	for _, addr := range was {
		if _, ok := current[addr]; !ok {
			gone = append(gone, addr)
		}
	}
	return gone
}

func equalAddrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
