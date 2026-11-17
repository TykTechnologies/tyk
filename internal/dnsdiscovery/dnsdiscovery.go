package dnsdiscovery

import (
	"errors"
	"net"
	"sort"
	"strings"
	"time"
)

type Outcome uint8

const (
	Resolved Outcome = iota
	Empty
	NotFound
	Unresolved
)

func (o Outcome) String() string {
	switch o {
	case Resolved:
		return "resolved"
	case Empty:
		return "empty"
	case NotFound:
		return "not_found"
	case Unresolved:
		return "unresolved"
	default:
		return "unknown"
	}
}

type State struct {
	Version uint64
	Addrs   []string
	Outcome Outcome

	Confirmed time.Time
	Failing   bool
}

func (s *State) Usable() bool {
	return s != nil && len(s.Addrs) > 0
}

func (s *State) Selectable(staleTTL time.Duration, now func() time.Time) bool {
	if !s.Usable() {
		return false
	}
	if !s.Failing || staleTTL <= 0 {
		return true
	}
	return now().Sub(s.Confirmed) < staleTTL
}

var ErrNoHost = errors.New("dnsdiscovery: Host is required")

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

func Resolvable(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return !strings.EqualFold(host, "localhost")
}

func Removed(was, now []string) []string {
	return difference(was, now)
}

func Added(was, now []string) []string {
	return difference(now, was)
}

func difference(from, against []string) []string {
	if len(from) == 0 {
		return nil
	}

	current := make(map[string]struct{}, len(against))
	for _, addr := range against {
		current[addr] = struct{}{}
	}

	var diff []string
	for _, addr := range from {
		if _, ok := current[addr]; !ok {
			diff = append(diff, addr)
		}
	}
	return diff
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
