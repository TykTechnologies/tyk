package dnsdiscovery

import (
	"errors"
	"net"
	"sort"
	"strings"
)

// Outcome is what a resolution established about a name. It travels with every
// published state, because the reasons a name yields no addresses are not
// interchangeable.
type Outcome uint8

const (
	// Resolved means the name answered with at least one address.
	Resolved Outcome = iota

	// Empty means the resolver answered successfully with no records. For a
	// Kubernetes Service that is information: it has no ready endpoints.
	Empty

	// NotFound means the resolver answered authoritatively that the name does
	// not exist.
	NotFound

	// Unreachable means the resolver could not be reached, and the last known
	// good set has gone unconfirmed for longer than the stale TTL.
	Unreachable
)

// String implements fmt.Stringer, for logs and test failures.
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

// State is one published address set for a name. Published by atomic pointer
// swap and never mutated afterwards, so a request path reads it without a lock,
// and Version lets a subscriber cache what it renders from Addrs.
type State struct {
	Version uint64
	Addrs   []string
	Outcome Outcome
}

// Usable reports whether this state carries addresses to use. A state that is
// not usable carries the reason in Outcome.
func (s *State) Usable() bool {
	return s != nil && len(s.Addrs) > 0
}

// ErrNoHost is returned by Subscribe when the configuration names no host.
var ErrNoHost = errors.New("dnsdiscovery: Host is required")

// Normalise sorts and de-duplicates an address set. CoreDNS shuffles its answers
// by default, so without the sort every refresh would look like a membership
// change.
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

// Resolvable reports whether a host is a DNS name whose membership can change.
// An IP literal resolves to itself and localhost is not a Service.
func Resolvable(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return !strings.EqualFold(host, "localhost")
}

// Removed returns the members of was that are absent from now. Both sets must be
// normalised. Subscribers holding a resource per address use it to work out what
// to retire.
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

// equalAddrs reports whether two normalised address sets hold the same members.
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
