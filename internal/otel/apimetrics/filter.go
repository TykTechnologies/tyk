package apimetrics

import (
	"strconv"
	"strings"
)

// statusCodeMatcher matches a single status code pattern.
type statusCodeMatcher struct {
	exact int    // non-zero means exact match (e.g., 200)
	class string // non-empty means class match (e.g., "2xx")
}

// matches returns true if the status code matches this matcher.
func (m statusCodeMatcher) matches(code int) bool {
	if m.exact != 0 {
		return code == m.exact
	}
	if m.class != "" {
		// Class pattern: first digit must match.
		classDigit := m.class[0] - '0'
		return code/100 == int(classDigit)
	}
	return false
}

// CompiledFilter evaluates whether a request should be recorded by an instrument.
// A nil CompiledFilter means "record everything".
type CompiledFilter struct {
	apiIDs      map[string]bool     // nil = all APIs
	methods     map[string]bool     // nil = all methods (stored uppercase)
	statusCodes []statusCodeMatcher // nil = all codes
}

// CompileFilter creates a CompiledFilter from config.
// Returns nil if the input is nil (record everything).
func CompileFilter(f *MetricFilters) *CompiledFilter {
	if f == nil {
		return nil
	}

	cf := &CompiledFilter{}

	if len(f.APIIDs) > 0 {
		cf.apiIDs = make(map[string]bool, len(f.APIIDs))
		for _, id := range f.APIIDs {
			cf.apiIDs[id] = true
		}
	}

	if len(f.Methods) > 0 {
		cf.methods = make(map[string]bool, len(f.Methods))
		for _, m := range f.Methods {
			cf.methods[strings.ToUpper(m)] = true
		}
	}

	if len(f.StatusCodes) > 0 {
		cf.statusCodes = make([]statusCodeMatcher, 0, len(f.StatusCodes))
		for _, sc := range f.StatusCodes {
			if code, err := strconv.Atoi(sc); err == nil {
				cf.statusCodes = append(cf.statusCodes, statusCodeMatcher{exact: code})
			} else {
				// Class pattern like "2xx", "4xx", "5xx"
				cf.statusCodes = append(cf.statusCodes, statusCodeMatcher{class: strings.ToLower(sc)})
			}
		}
	}

	return cf
}

// Match returns true if the request should be recorded by this instrument.
// A nil receiver matches everything.
func (f *CompiledFilter) Match(apiID, method string, statusCode int) bool {
	if f == nil {
		return true
	}

	// AND logic between fields: all non-nil fields must match.
	if f.apiIDs != nil && !f.apiIDs[apiID] {
		return false
	}

	// Methods are stored uppercase at compile time; HTTP methods from net/http are already uppercase.
	if f.methods != nil && !f.methods[method] {
		return false
	}

	if f.statusCodes != nil {
		matched := false
		for _, m := range f.statusCodes {
			if m.matches(statusCode) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}
