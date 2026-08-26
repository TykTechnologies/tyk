package gateway

import (
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

// evalCondition runs a condition against a request built from method, target
// and headers, without needing a running gateway.
func evalCondition(t *testing.T, condition user.AccessCondition, target string, headers map[string]string, body string) bool {
	t.Helper()

	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}

	r, err := http.NewRequest(http.MethodGet, target, reader)
	assert.NoError(t, err)

	for name, value := range headers {
		r.Header.Set(name, value)
	}

	m := &GranularAccessMiddleware{BaseMiddleware: &BaseMiddleware{}}

	return m.conditionsMatch(r, user.AccessSpec{
		URL:        "/connections",
		Methods:    []string{http.MethodGet},
		Conditions: []user.AccessCondition{condition},
	})
}

func queryCond(on apidef.RoutingTriggerOnType, matches map[string]apidef.StringRegexMap) user.AccessCondition {
	return user.AccessCondition{On: on, Options: apidef.RoutingTriggerOptions{QueryValMatches: matches}}
}

// A query parameter can be required to be absent, which is what lets a policy
// grant the bare endpoint while refusing the privileged variants of it.
func TestAccessConditions_RequireParameterAbsent(t *testing.T) {
	// "persnbr must not be supplied"
	condition := queryCond(apidef.All, map[string]apidef.StringRegexMap{
		"persnbr": {MatchPattern: ".*", Reverse: true},
	})

	t.Run("absent parameter is allowed", func(t *testing.T) {
		assert.True(t, evalCondition(t, condition, "http://x/connections", nil, ""))
	})

	t.Run("supplied parameter is denied", func(t *testing.T) {
		assert.False(t, evalCondition(t, condition, "http://x/connections?persnbr=123", nil, ""))
	})

	t.Run("supplied but empty parameter is denied", func(t *testing.T) {
		assert.False(t, evalCondition(t, condition, "http://x/connections?persnbr=", nil, ""))
	})

	t.Run("an unrelated parameter does not trip the rule", func(t *testing.T) {
		assert.True(t, evalCondition(t, condition, "http://x/connections?page=2", nil, ""))
	})
}

// The full RBFCU public policy: the base endpoint only, none of the privileged
// lookup parameters.
func TestAccessConditions_RBFCUPublicPolicy(t *testing.T) {
	absent := apidef.StringRegexMap{MatchPattern: ".*", Reverse: true}
	condition := queryCond(apidef.All, map[string]apidef.StringRegexMap{
		"persnbr":  absent,
		"agreenbr": absent,
		"account":  absent,
	})

	allowed := []string{
		"http://x/connections",
		"http://x/connections?page=2",
	}
	for _, target := range allowed {
		assert.True(t, evalCondition(t, condition, target, nil, ""), target)
	}

	denied := []string{
		"http://x/connections?persnbr=123",
		"http://x/connections?agreenbr=99",
		"http://x/connections?account=7",
		"http://x/connections?persnbr=123&agreenbr=99",
		"http://x/connections?page=2&account=7",
	}
	for _, target := range denied {
		assert.False(t, evalCondition(t, condition, target, nil, ""), target)
	}
}

// Repeating one parameter must not stand in for a different parameter that the
// same condition also requires.
func TestAccessConditions_RepeatedParameterCannotSatisfyAnother(t *testing.T) {
	condition := queryCond(apidef.All, map[string]apidef.StringRegexMap{
		"persnbr": {MatchPattern: "^[0-9]+$"},
		"account": {MatchPattern: "^[0-9]+$"},
	})

	assert.True(t, evalCondition(t, condition, "http://x/connections?persnbr=1&account=2", nil, ""))

	assert.False(t, evalCondition(t, condition, "http://x/connections?persnbr=1&persnbr=2", nil, ""),
		"two values of persnbr must not satisfy the account matcher")
	assert.False(t, evalCondition(t, condition, "http://x/connections?account=1&account=2", nil, ""),
		"two values of account must not satisfy the persnbr matcher")
}

// Every supplied value has to match, so an extra value cannot smuggle anything
// past the pattern.
func TestAccessConditions_EveryValueMustMatch(t *testing.T) {
	condition := queryCond(apidef.All, map[string]apidef.StringRegexMap{
		"persnbr": {MatchPattern: "^[0-9]+$"},
	})

	assert.True(t, evalCondition(t, condition, "http://x/connections?persnbr=123", nil, ""))
	assert.True(t, evalCondition(t, condition, "http://x/connections?persnbr=1&persnbr=2", nil, ""))

	assert.False(t, evalCondition(t, condition, "http://x/connections?persnbr=123&persnbr=evil", nil, ""))
	assert.False(t, evalCondition(t, condition, "http://x/connections?persnbr=evil&persnbr=123", nil, ""))
}

// Headers are counted per configured name too.
func TestAccessConditions_RepeatedHeaderCannotSatisfyAnother(t *testing.T) {
	condition := user.AccessCondition{
		On: apidef.All,
		Options: apidef.RoutingTriggerOptions{
			HeaderMatches: map[string]apidef.StringRegexMap{
				"X-Tenant": {MatchPattern: "^acme$"},
				"X-Region": {MatchPattern: "^eu$"},
			},
		},
	}

	assert.True(t, evalCondition(t, condition, "http://x/connections",
		map[string]string{"X-Tenant": "acme", "X-Region": "eu"}, ""))

	r, err := http.NewRequest(http.MethodGet, "http://x/connections", nil)
	assert.NoError(t, err)
	r.Header.Add("X-Tenant", "acme")
	r.Header.Add("X-Tenant", "acme")

	m := &GranularAccessMiddleware{BaseMiddleware: &BaseMiddleware{}}
	assert.False(t, m.conditionsMatch(r, user.AccessSpec{Conditions: []user.AccessCondition{condition}}),
		"two X-Tenant values must not satisfy the X-Region matcher")
}

// A header can be required to be absent as well.
func TestAccessConditions_RequireHeaderAbsent(t *testing.T) {
	condition := user.AccessCondition{
		On: apidef.All,
		Options: apidef.RoutingTriggerOptions{
			HeaderMatches: map[string]apidef.StringRegexMap{
				"X-Impersonate": {MatchPattern: ".*", Reverse: true},
			},
		},
	}

	assert.True(t, evalCondition(t, condition, "http://x/connections", nil, ""))
	assert.False(t, evalCondition(t, condition, "http://x/connections",
		map[string]string{"X-Impersonate": "someone"}, ""))
}

// A misconfigured condition denies rather than grants.
func TestAccessConditions_FailClosed(t *testing.T) {
	t.Run("uncompilable pattern denies", func(t *testing.T) {
		condition := queryCond(apidef.All, map[string]apidef.StringRegexMap{
			"persnbr": {MatchPattern: "([0-9]+"},
		})
		assert.False(t, evalCondition(t, condition, "http://x/connections?persnbr=123", nil, ""))
	})

	t.Run("uncompilable reversed pattern denies", func(t *testing.T) {
		condition := queryCond(apidef.All, map[string]apidef.StringRegexMap{
			"persnbr": {MatchPattern: "([0-9]+", Reverse: true},
		})
		assert.False(t, evalCondition(t, condition, "http://x/connections", nil, ""))
	})

	t.Run("condition with no options denies", func(t *testing.T) {
		assert.False(t, evalCondition(t, user.AccessCondition{On: apidef.All}, "http://x/connections", nil, ""))
	})

	t.Run("session meta condition without a session denies", func(t *testing.T) {
		condition := user.AccessCondition{
			On: apidef.All,
			Options: apidef.RoutingTriggerOptions{
				SessionMetaMatches: map[string]apidef.StringRegexMap{
					"role": {MatchPattern: "^admin$"},
				},
			},
		}
		assert.False(t, evalCondition(t, condition, "http://x/connections", nil, ""))
	})
}

// on:any is satisfied by one group, on:all needs them all.
func TestAccessConditions_AnyAll(t *testing.T) {
	options := apidef.RoutingTriggerOptions{
		QueryValMatches: map[string]apidef.StringRegexMap{"persnbr": {MatchPattern: "^[0-9]+$"}},
		HeaderMatches:   map[string]apidef.StringRegexMap{"X-Tenant": {MatchPattern: "^acme$"}},
	}

	all := user.AccessCondition{On: apidef.All, Options: options}
	any := user.AccessCondition{On: apidef.Any, Options: options}

	acme := map[string]string{"X-Tenant": "acme"}

	assert.True(t, evalCondition(t, all, "http://x/connections?persnbr=1", acme, ""))
	assert.False(t, evalCondition(t, all, "http://x/connections?persnbr=1", nil, ""))
	assert.False(t, evalCondition(t, all, "http://x/connections", acme, ""))

	assert.True(t, evalCondition(t, any, "http://x/connections?persnbr=1", nil, ""))
	assert.True(t, evalCondition(t, any, "http://x/connections", acme, ""))
	assert.False(t, evalCondition(t, any, "http://x/connections", nil, ""))
}

// Ordering, decoding and case behaviour that the customer asked about.
func TestAccessConditions_OrderingEncodingCase(t *testing.T) {
	condition := queryCond(apidef.All, map[string]apidef.StringRegexMap{
		"persnbr": {MatchPattern: "^[0-9]+$"},
		"account": {MatchPattern: "^[0-9]+$"},
	})

	assert.True(t, evalCondition(t, condition, "http://x/connections?persnbr=1&account=2", nil, ""))
	assert.True(t, evalCondition(t, condition, "http://x/connections?account=2&persnbr=1", nil, ""),
		"parameter order must not change the decision")

	single := queryCond(apidef.All, map[string]apidef.StringRegexMap{
		"persnbr": {MatchPattern: "^123$"},
	})
	assert.True(t, evalCondition(t, single, "http://x/connections?persnbr=%31%32%33", nil, ""),
		"percent-encoded values are matched after decoding")
	assert.False(t, evalCondition(t, single, "http://x/connections?PersNbr=123", nil, ""),
		"parameter names are case sensitive")
}

// Multiple conditions on one spec combine with AND.
func TestAccessConditions_MultipleConditionsAreAnded(t *testing.T) {
	m := &GranularAccessMiddleware{BaseMiddleware: &BaseMiddleware{}}

	spec := user.AccessSpec{
		Conditions: []user.AccessCondition{
			queryCond(apidef.All, map[string]apidef.StringRegexMap{"persnbr": {MatchPattern: "^[0-9]+$"}}),
			queryCond(apidef.All, map[string]apidef.StringRegexMap{"account": {MatchPattern: ".*", Reverse: true}}),
		},
	}

	r, _ := http.NewRequest(http.MethodGet, "http://x/connections?persnbr=1", nil)
	assert.True(t, m.conditionsMatch(r, spec))

	r, _ = http.NewRequest(http.MethodGet, "http://x/connections?persnbr=1&account=2", nil)
	assert.False(t, m.conditionsMatch(r, spec), "second condition must still be enforced")
}

// The payload matcher keeps working, and leaves the body readable downstream.
func TestAccessConditions_Payload(t *testing.T) {
	condition := user.AccessCondition{
		On: apidef.All,
		Options: apidef.RoutingTriggerOptions{
			PayloadMatches: apidef.StringRegexMap{MatchPattern: `"tenant":\s*"acme"`},
		},
	}

	assert.True(t, evalCondition(t, condition, "http://x/connections", nil, `{"tenant": "acme"}`))
	assert.False(t, evalCondition(t, condition, "http://x/connections", nil, `{"tenant": "globex"}`))

	reverse := user.AccessCondition{
		On: apidef.All,
		Options: apidef.RoutingTriggerOptions{
			PayloadMatches: apidef.StringRegexMap{MatchPattern: `"admin":\s*true`, Reverse: true},
		},
	}
	assert.True(t, evalCondition(t, reverse, "http://x/connections", nil, `{"admin": false}`))
	assert.False(t, evalCondition(t, reverse, "http://x/connections", nil, `{"admin": true}`))

	// Body survives evaluation for the middleware that follows.
	r, err := http.NewRequest(http.MethodGet, "http://x/connections", strings.NewReader(`{"tenant": "acme"}`))
	assert.NoError(t, err)

	m := &GranularAccessMiddleware{BaseMiddleware: &BaseMiddleware{}}
	assert.True(t, m.conditionsMatch(r, user.AccessSpec{Conditions: []user.AccessCondition{condition}}))

	remaining, err := io.ReadAll(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, `{"tenant": "acme"}`, string(remaining), "request body must still be readable")
}

// Path parts stay "some part matches", and reverse means no part matches.
func TestAccessConditions_PathParts(t *testing.T) {
	condition := user.AccessCondition{
		On: apidef.All,
		Options: apidef.RoutingTriggerOptions{
			PathPartMatches: map[string]apidef.StringRegexMap{
				"segment": {MatchPattern: "^admin$"},
			},
		},
	}

	assert.True(t, evalCondition(t, condition, "http://x/admin/connections", nil, ""))
	assert.False(t, evalCondition(t, condition, "http://x/public/connections", nil, ""))

	reverse := user.AccessCondition{
		On: apidef.All,
		Options: apidef.RoutingTriggerOptions{
			PathPartMatches: map[string]apidef.StringRegexMap{
				"segment": {MatchPattern: "^admin$", Reverse: true},
			},
		},
	}
	assert.False(t, evalCondition(t, reverse, "http://x/admin/connections", nil, ""))
	assert.True(t, evalCondition(t, reverse, "http://x/public/connections", nil, ""))
}

// TestAccessConditions_EveryTriggerOptionIsEvaluated guards the coupling
// between access conditions and apidef.RoutingTriggerOptions, which access
// conditions borrow as their configuration shape.
//
// An option the evaluator does not know about is not merely unimplemented: the
// condition would be accepted, appear to constrain the request, and then be
// ignored, granting access the operator believed they had restricted. So a
// field added here for URL Rewrite's benefit has to be handled here too, or
// deliberately rejected at validation.
func TestAccessConditions_EveryTriggerOptionIsEvaluated(t *testing.T) {
	evaluated := map[string]bool{
		"HeaderMatches":         true,
		"QueryValMatches":       true,
		"PathPartMatches":       true,
		"SessionMetaMatches":    true,
		"RequestContextMatches": true,
		"PayloadMatches":        true,
	}

	optionsType := reflect.TypeOf(apidef.RoutingTriggerOptions{})
	for i := 0; i < optionsType.NumField(); i++ {
		name := optionsType.Field(i).Name

		if !evaluated[name] {
			t.Errorf("apidef.RoutingTriggerOptions gained field %q, which the access condition evaluator ignores. "+
				"Either evaluate it in conditionMatch or reject it in AccessCondition.Validate, "+
				"then add it here.", name)

			continue
		}

		delete(evaluated, name)
	}

	for name := range evaluated {
		t.Errorf("the access condition evaluator handles %q, which apidef.RoutingTriggerOptions no longer has", name)
	}
}

// TestAccessConditions_AbsenceSpellings pins the two ways a condition says
// "this name must not be supplied". The empty pattern is the one to document:
// it says nothing about the value, so reversing it can only be about presence.
func TestAccessConditions_AbsenceSpellings(t *testing.T) {
	for _, spelling := range []struct {
		name   string
		option apidef.StringRegexMap
	}{
		{name: "empty pattern reversed", option: apidef.StringRegexMap{Reverse: true}},
		{name: "match anything reversed", option: apidef.StringRegexMap{MatchPattern: ".*", Reverse: true}},
	} {
		t.Run(spelling.name, func(t *testing.T) {
			condition := user.AccessCondition{
				On:      apidef.All,
				Options: apidef.RoutingTriggerOptions{QueryValMatches: map[string]apidef.StringRegexMap{"persnbr": spelling.option}},
			}

			for _, tc := range []struct {
				query string
				want  bool
			}{
				{query: "", want: true},
				{query: "?page=2", want: true},
				{query: "?persnbr=123", want: false},
				{query: "?persnbr=", want: false},
				{query: "?persnbr=1&persnbr=2", want: false},
			} {
				got := evalCondition(t, condition, "http://x/connections"+tc.query, nil, "")

				if got != tc.want {
					t.Errorf("%q: got %v, want %v", tc.query, got, tc.want)
				}
			}
		})
	}
}

// readTracker records whether anything read from it.
type readTracker struct {
	reader io.Reader
	read   bool
}

func (t *readTracker) Read(p []byte) (int, error) {
	t.read = true
	return t.reader.Read(p)
}

// TestAccessConditions_PayloadNotReadWhenAlreadyDecided checks that a request
// whose cheaper conditions have already settled the outcome does not have its
// body read.
//
// This is a resource concern, not a correctness one: reading the payload pulls
// the whole body into memory, and the Gateway only bounds that when
// max_request_body_size is configured, which it is not by default. A request
// that was going to be refused on its headers regardless should not pay for it.
func TestAccessConditions_PayloadNotReadWhenAlreadyDecided(t *testing.T) {
	newRequest := func(t *testing.T) (*http.Request, *readTracker) {
		t.Helper()

		tracker := &readTracker{reader: strings.NewReader(`{"tenant": "acme"}`)}

		r, err := http.NewRequest(http.MethodPost, "http://x/connections?persnbr=123", io.NopCloser(tracker))
		assert.NoError(t, err)

		return r, tracker
	}

	m := &GranularAccessMiddleware{BaseMiddleware: &BaseMiddleware{}}

	payload := apidef.StringRegexMap{MatchPattern: `"tenant":\s*"acme"`}

	t.Run("all: an earlier failure means the body is never read", func(t *testing.T) {
		r, tracker := newRequest(t)

		spec := user.AccessSpec{Conditions: []user.AccessCondition{{
			On: apidef.All,
			Options: apidef.RoutingTriggerOptions{
				// Not satisfied, so the condition is already decided.
				QueryValMatches: map[string]apidef.StringRegexMap{"persnbr": {MatchPattern: "^nope$"}},
				PayloadMatches:  payload,
			},
		}}}

		assert.False(t, m.conditionsMatch(r, spec))
		assert.False(t, tracker.read, "the body was read even though the query condition had already failed")
	})

	t.Run("any: an earlier success means the body is never read", func(t *testing.T) {
		r, tracker := newRequest(t)

		spec := user.AccessSpec{Conditions: []user.AccessCondition{{
			On: apidef.Any,
			Options: apidef.RoutingTriggerOptions{
				QueryValMatches: map[string]apidef.StringRegexMap{"persnbr": {MatchPattern: "^[0-9]+$"}},
				PayloadMatches:  payload,
			},
		}}}

		assert.True(t, m.conditionsMatch(r, spec))
		assert.False(t, tracker.read, "the body was read even though the query condition had already passed")
	})

	t.Run("the body is still read when it is what decides the outcome", func(t *testing.T) {
		r, tracker := newRequest(t)

		spec := user.AccessSpec{Conditions: []user.AccessCondition{{
			On: apidef.All,
			Options: apidef.RoutingTriggerOptions{
				QueryValMatches: map[string]apidef.StringRegexMap{"persnbr": {MatchPattern: "^[0-9]+$"}},
				PayloadMatches:  payload,
			},
		}}}

		assert.True(t, m.conditionsMatch(r, spec))
		assert.True(t, tracker.read)
	})
}
