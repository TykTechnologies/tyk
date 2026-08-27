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

// accessConditionGroup is one group of options within a condition, paired with
// the test that decides whether the request satisfies it.
type accessConditionGroup struct {
	// configured reports whether the operator set this group at all. A group
	// nobody configured constrains nothing and does not count either way.
	configured bool
	// match is called only for a configured group, and only until the outcome
	// is settled. That is what keeps the expensive groups from running.
	match func() bool
}

// conditionGroups returns a condition's option groups in the order they should
// be evaluated: cheapest first, with the payload last, because matching against
// it reads the whole request body into memory.
func (m *GranularAccessMiddleware) conditionGroups(r *http.Request, condition user.AccessCondition) []accessConditionGroup {
	options := condition.Options
	checkAny := condition.On == apidef.Any

	return []accessConditionGroup{
		{
			configured: len(options.HeaderMatches) > 0,
			match:      func() bool { return matchHeaders(r, options.HeaderMatches, checkAny) },
		},
		{
			configured: len(options.QueryValMatches) > 0,
			match:      func() bool { return matchQueryValues(r, options.QueryValMatches, checkAny) },
		},
		{
			configured: len(options.PathPartMatches) > 0,
			match:      func() bool { return matchPathParts(r, options.PathPartMatches, checkAny) },
		},
		{
			configured: len(options.SessionMetaMatches) > 0,
			match:      func() bool { return matchSessionMeta(r, options.SessionMetaMatches, checkAny) },
		},
		{
			configured: len(options.RequestContextMatches) > 0,
			match:      func() bool { return matchRequestContext(r, options.RequestContextMatches, checkAny) },
		},
		{
			configured: options.PayloadMatches.MatchPattern != "",
			match:      func() bool { return m.matchPayload(r, options.PayloadMatches) },
		},
	}
}

// conditionMatch evaluates a single condition. On decides how the configured
// option groups combine: apidef.Any is satisfied by one group, anything else
// requires all of them.
//
// Evaluation stops as soon as the answer is settled - under "any" at the first
// satisfied group, under "all" at the first unsatisfied one. That is not only
// about speed: it is what stops a request whose header or query condition has
// already failed from having its whole body read for a payload match.
func (m *GranularAccessMiddleware) conditionMatch(r *http.Request, condition user.AccessCondition) bool {
	checkAny := condition.On == apidef.Any

	// total counts the configured option groups, satisfied the ones that passed.
	total, satisfied := 0, 0

	for _, group := range m.conditionGroups(r, condition) {
		if !group.configured {
			continue
		}

		total++

		if group.match() {
			if checkAny {
				return true
			}

			satisfied++

			continue
		}

		// Under "all" one unsatisfied group is the whole answer. Under "any"
		// a later group may still pass.
		if !checkAny {
			return false
		}
	}

	// Reaching here under "any" means nothing matched. A condition that
	// configures nothing constrains nothing, which for an access decision is a
	// misconfiguration rather than a licence to pass.
	if checkAny || total == 0 {
		return false
	}

	return total == satisfied
}

// matchHeaders evaluates the header matches. Header names are canonicalised, so
// they are matched case insensitively as HTTP requires.
func matchHeaders(r *http.Request, options map[string]apidef.StringRegexMap, checkAny bool) bool {
	return matchNamedValues(options, checkAny, func(name string) ([]string, bool) {
		values, ok := r.Header[textproto.CanonicalMIMEHeaderKey(name)]
		return values, ok
	})
}

// matchQueryValues evaluates the query string matches. Parameter names are case
// sensitive, and the order they appear in makes no difference.
func matchQueryValues(r *http.Request, options map[string]apidef.StringRegexMap, checkAny bool) bool {
	query := r.URL.Query()

	return matchNamedValues(options, checkAny, func(name string) ([]string, bool) {
		values, ok := query[name]
		return values, ok
	})
}

// matchPathParts evaluates the path part matches. Every part is a candidate, so
// the matcher sees them as the values supplied for that name: a plain pattern is
// satisfied when some part matches, a reversed one when no part does.
func matchPathParts(r *http.Request, options map[string]apidef.StringRegexMap, checkAny bool) bool {
	parts := strings.Split(r.URL.Path, "/")

	return matchNamedValues(options, checkAny, func(string) ([]string, bool) {
		return parts, true
	}, matchAnyValue)
}

// matchSessionMeta evaluates the matches against the session's metadata. A
// request with no session supplies no values, so a plain pattern cannot be
// satisfied and a reversed one is.
func matchSessionMeta(r *http.Request, options map[string]apidef.StringRegexMap, checkAny bool) bool {
	session := ctxGetSession(r)

	return matchNamedValues(options, checkAny, func(name string) ([]string, bool) {
		if session == nil {
			return nil, false
		}

		return stringValue(session.MetaData[name])
	})
}

// matchRequestContext evaluates the matches against values earlier middleware
// recorded on the request.
//
// Unlike the URL Rewrite middleware this deliberately does not force the context
// data into existence: an access check must not have side effects on the trigger
// numbering a later rewrite relies on. Reading from the resulting nil map is
// defined in Go and yields the zero value, so a request with no context data is
// read as supplying no values.
func matchRequestContext(r *http.Request, options map[string]apidef.StringRegexMap, checkAny bool) bool {
	contextData := ctxGetData(r)

	return matchNamedValues(options, checkAny, func(name string) ([]string, bool) {
		return stringValue(contextData[name])
	})
}

// matchPayload evaluates the match against the request body. A body that cannot
// be read fails the match rather than passing it.
func (m *GranularAccessMiddleware) matchPayload(r *http.Request, option apidef.StringRegexMap) bool {
	body, err := readRequestBody(r)
	if err != nil {
		m.Logger().WithError(err).Error("Could not read request body to evaluate access condition")
		return false
	}

	return matchValues(option, []string{body}, true, matchAnyValue)
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
