package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/user"
)

// Access conditions reuse apidef.RoutingTriggerOptions as their configuration
// shape, but they are deliberately not evaluated by the URL Rewrite trigger
// code. A rewrite trigger decides whether to apply a transformation, so leaning
// towards firing is harmless; an access condition decides whether to let a
// request through, so it has to lean the other way. The two differ in three
// ways that matter:
//
//  1. Absence is expressible. With Reverse set, a name that is not present at
//     all satisfies the matcher, which is how a policy says "this parameter must
//     not be supplied". The rewrite matchers only ever look at values that are
//     present, so they cannot express it.
//
//  2. Every supplied value has to match, not just one of them. Otherwise a
//     caller widens their own access by repeating a parameter with an extra
//     value the pattern does not allow.
//
//  3. Matchers are counted per configured name, not per matching value, so
//     repeating one name can never stand in for a different name that an "all"
//     condition also requires.
//
// Anything that cannot be evaluated - an uncompilable pattern, a condition with
// no options - denies access rather than granting it.
//
// Evaluation is free of side effects: unlike the rewrite triggers, it does not
// record matches in the request context data, so it cannot disturb the trigger
// numbering that a later URL Rewrite middleware relies on.

// conditionsMatch reports whether the request satisfies every condition on the
// access spec. Conditions combine with AND, so an "any of" rule is expressed as
// a single condition with several options and On set to apidef.Any.
//
// A spec without conditions matches on URL and method alone, as before.
func (m *GranularAccessMiddleware) conditionsMatch(r *http.Request, accessSpec user.AccessSpec) bool {
	if len(accessSpec.Conditions) == 0 {
		return true
	}

	for index, condition := range accessSpec.Conditions {
		if !m.conditionMatch(r, condition) {
			m.Logger().WithField("url", accessSpec.URL).WithField("condition", index).
				Debug("Granular access condition not satisfied")
			return false
		}
	}

	return true
}

// conditionMatch evaluates a single condition. On decides how the configured
// option groups combine: apidef.Any is satisfied by one group, anything else
// requires all of them.
func (m *GranularAccessMiddleware) conditionMatch(r *http.Request, condition user.AccessCondition) bool {
	checkAny := condition.On == apidef.Any
	options := condition.Options

	// Parsed lazily and only once, however many option groups need them.
	var query map[string][]string

	// total counts the configured option groups, satisfied the ones that passed.
	total, satisfied := 0, 0

	// group evaluates one option group and reports whether it settles the
	// condition, and if so with what answer: under "any" the first satisfied
	// group settles it, under "all" the first unsatisfied one does.
	//
	// Stopping early is not only about speed. The groups are evaluated cheapest
	// first, with the payload last, so short circuiting is what stops a request
	// whose header or query condition has already failed from having its whole
	// body read into memory.
	group := func(configured bool, eval func() bool) (settled, granted bool) {
		if !configured {
			return false, false
		}

		total++

		if !eval() {
			// Under "all" one unsatisfied group is the whole answer. Under
			// "any" there may still be a later group that passes.
			return !checkAny, false
		}

		if checkAny {
			return true, true
		}

		satisfied++

		return false, false
	}

	if settled, granted := group(len(options.HeaderMatches) > 0, func() bool {
		return matchNamedValues(options.HeaderMatches, checkAny, func(name string) ([]string, bool) {
			values, ok := r.Header[textproto.CanonicalMIMEHeaderKey(name)]
			return values, ok
		})
	}); settled {
		return granted
	}

	if settled, granted := group(len(options.QueryValMatches) > 0, func() bool {
		if query == nil {
			query = r.URL.Query()
		}

		return matchNamedValues(options.QueryValMatches, checkAny, func(name string) ([]string, bool) {
			values, ok := query[name]
			return values, ok
		})
	}); settled {
		return granted
	}

	if settled, granted := group(len(options.PathPartMatches) > 0, func() bool {
		parts := strings.Split(r.URL.Path, "/")

		// Every part is a candidate, so the matcher sees them as the values
		// supplied for that name: a plain pattern is satisfied when some part
		// matches, a reversed one when no part does.
		return matchNamedValues(options.PathPartMatches, checkAny, func(string) ([]string, bool) {
			return parts, true
		}, matchAnyValue)
	}); settled {
		return granted
	}

	if settled, granted := group(len(options.SessionMetaMatches) > 0, func() bool {
		session := ctxGetSession(r)

		return matchNamedValues(options.SessionMetaMatches, checkAny, func(name string) ([]string, bool) {
			if session == nil {
				return nil, false
			}

			return stringValue(session.MetaData[name])
		})
	}); settled {
		return granted
	}

	if settled, granted := group(len(options.RequestContextMatches) > 0, func() bool {
		contextData := ctxGetData(r)

		return matchNamedValues(options.RequestContextMatches, checkAny, func(name string) ([]string, bool) {
			return stringValue(contextData[name])
		})
	}); settled {
		return granted
	}

	if settled, granted := group(options.PayloadMatches.MatchPattern != "", func() bool {
		body, err := readRequestBody(r)
		if err != nil {
			m.Logger().WithError(err).Error("Could not read request body to evaluate access condition")
			return false
		}

		return matchValues(options.PayloadMatches, []string{body}, true, matchAnyValue)
	}); settled {
		return granted
	}

	if checkAny {
		return false
	}

	// A condition that configures nothing constrains nothing, which for an
	// access decision is a misconfiguration rather than a licence to pass.
	if total == 0 {
		return false
	}

	return total == satisfied
}

// valueLookup returns the values supplied for a name and whether the name was
// supplied at all. The two are distinct: a name can be present with an empty
// value, which is not the same as being absent.
type valueLookup func(name string) (values []string, present bool)

// valueMatcher decides whether a set of supplied values satisfies a pattern.
type valueMatcher func(re *regexp.Regexp, values []string) bool

// matchNamedValues evaluates every configured matcher against the values the
// request supplied for that name. With checkAny set one satisfied matcher is
// enough, otherwise all of them have to be satisfied.
//
// The optional match argument overrides how multiple values are treated; it
// defaults to matchAllValues.
func matchNamedValues(options map[string]apidef.StringRegexMap, checkAny bool, lookup valueLookup, match ...valueMatcher) bool {
	for name, option := range options {
		values, present := lookup(name)

		if matchValues(option, values, present, match...) {
			if checkAny {
				return true
			}

			continue
		}

		if !checkAny {
			return false
		}
	}

	return !checkAny
}

// matchValues applies one matcher to the values supplied for a single name.
func matchValues(option apidef.StringRegexMap, values []string, present bool, match ...valueMatcher) bool {
	// A pattern that does not compile denies access. Compilation is cached by
	// the regexp package, so this is a map lookup after the first request.
	re, err := regexp.Compile(option.MatchPattern)
	if err != nil {
		log.WithError(err).WithField("MatchPattern", option.MatchPattern).
			Error("Could not compile access condition pattern, denying access")
		return false
	}

	matches := matchAllValues
	if len(match) > 0 {
		matches = match[0]
	}

	if option.Reverse {
		// "must not match": an absent name satisfies it, and so does a present
		// one whose values all fail the pattern.
		return !matchAnyValue(re, values)
	}

	if !present || len(values) == 0 {
		return false
	}

	return matches(re, values)
}

// matchAllValues requires every supplied value to match, so a caller cannot
// widen their access by repeating a name with an extra value.
func matchAllValues(re *regexp.Regexp, values []string) bool {
	for _, value := range values {
		if !re.MatchString(value) {
			return false
		}
	}

	return len(values) > 0
}

// matchAnyValue is satisfied by a single matching value. It is used where the
// values are candidates rather than a set the caller controls, such as the
// parts of the request path.
func matchAnyValue(re *regexp.Regexp, values []string) bool {
	for _, value := range values {
		if re.MatchString(value) {
			return true
		}
	}

	return false
}

// stringValue adapts a single metadata value to the lookup contract. A value
// that is not a string counts as absent, as it cannot be matched by pattern.
func stringValue(raw interface{}) ([]string, bool) {
	value, ok := raw.(string)
	if !ok {
		return nil, false
	}

	return []string{value}, true
}

// readRequestBody reads the body and restores it so later middleware still see
// it.
func readRequestBody(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	nopCloseRequestBody(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}

	r.Body = io.NopCloser(bytes.NewBuffer(body))

	return string(body), nil
}
