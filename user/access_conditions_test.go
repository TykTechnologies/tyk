package user

import (
	"errors"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
)

func queryCondition(on apidef.RoutingTriggerOnType, matches map[string]apidef.StringRegexMap) AccessCondition {
	return AccessCondition{
		On:      on,
		Options: apidef.RoutingTriggerOptions{QueryValMatches: matches},
	}
}

func TestAccessConditionValidate(t *testing.T) {
	testCases := []struct {
		name      string
		condition AccessCondition
		wantErr   error
		// wantMsg, when set, has to appear in the error so that the operator
		// can tell which option was rejected.
		wantMsg string
	}{
		{
			name:      "present and valid",
			condition: queryCondition(apidef.All, map[string]apidef.StringRegexMap{"persnbr": {MatchPattern: "^[0-9]+$"}}),
		},
		{
			name: "must be absent, spelled as an empty reversed pattern",
			condition: queryCondition(apidef.All, map[string]apidef.StringRegexMap{
				"persnbr": {Reverse: true},
			}),
		},
		{
			name:      "on defaults to all when empty",
			condition: queryCondition("", map[string]apidef.StringRegexMap{"persnbr": {MatchPattern: ".+"}}),
		},
		{
			name:      "on any is accepted",
			condition: queryCondition(apidef.Any, map[string]apidef.StringRegexMap{"persnbr": {MatchPattern: ".+"}}),
		},
		{
			name:      "unrecognised on is rejected",
			condition: queryCondition("ALL", map[string]apidef.StringRegexMap{"persnbr": {MatchPattern: ".+"}}),
			wantErr:   ErrAccessConditionOn,
		},
		{
			name:      "condition with no options is rejected",
			condition: AccessCondition{On: apidef.All},
			wantErr:   ErrAccessConditionEmpty,
		},
		{
			name:      "condition with an empty option map is rejected",
			condition: queryCondition(apidef.All, map[string]apidef.StringRegexMap{}),
			wantErr:   ErrAccessConditionEmpty,
		},
		{
			name:      "uncompilable pattern is rejected",
			condition: queryCondition(apidef.All, map[string]apidef.StringRegexMap{"persnbr": {MatchPattern: "^[0-9"}}),
			wantMsg:   "query_val_matches.persnbr",
		},
		{
			name: "uncompilable reversed pattern is rejected too",
			condition: queryCondition(apidef.All, map[string]apidef.StringRegexMap{
				"persnbr": {MatchPattern: "*bad", Reverse: true},
			}),
			wantMsg: "query_val_matches.persnbr",
		},
		{
			name: "uncompilable header pattern is rejected",
			condition: AccessCondition{
				On:      apidef.All,
				Options: apidef.RoutingTriggerOptions{HeaderMatches: map[string]apidef.StringRegexMap{"X-Role": {MatchPattern: "("}}},
			},
			wantMsg: "header_matches.X-Role",
		},
		{
			name: "uncompilable payload pattern is rejected",
			condition: AccessCondition{
				On:      apidef.All,
				Options: apidef.RoutingTriggerOptions{PayloadMatches: apidef.StringRegexMap{MatchPattern: "("}},
			},
			wantMsg: "payload_matches",
		},
		{
			name: "payload matches on its own counts as configured",
			condition: AccessCondition{
				On:      apidef.All,
				Options: apidef.RoutingTriggerOptions{PayloadMatches: apidef.StringRegexMap{MatchPattern: "ok"}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.condition.Validate()

			switch {
			case testCase.wantErr != nil:
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("got %v, want %v", err, testCase.wantErr)
				}
			case testCase.wantMsg != "":
				if err == nil || !strings.Contains(err.Error(), testCase.wantMsg) {
					t.Fatalf("got %v, want it to mention %q", err, testCase.wantMsg)
				}
			default:
				if err != nil {
					t.Fatalf("got %v, want no error", err)
				}
			}
		})
	}
}

func TestValidateAccessSpecs(t *testing.T) {
	t.Run("a spec without conditions is always valid", func(t *testing.T) {
		specs := []AccessSpec{{URL: "/anything", Methods: []string{"GET"}}}

		if err := ValidateAccessSpecs(specs); err != nil {
			t.Fatalf("got %v, want no error", err)
		}
	})

	t.Run("the error names the URL and the condition index", func(t *testing.T) {
		specs := []AccessSpec{
			{URL: "/fine", Conditions: []AccessCondition{queryCondition(apidef.All, map[string]apidef.StringRegexMap{"a": {MatchPattern: ".+"}})}},
			{
				URL: "/broken",
				Conditions: []AccessCondition{
					queryCondition(apidef.All, map[string]apidef.StringRegexMap{"a": {MatchPattern: ".+"}}),
					queryCondition(apidef.All, map[string]apidef.StringRegexMap{"b": {MatchPattern: "[unclosed"}}),
				},
			},
		}

		err := ValidateAccessSpecs(specs)
		if err == nil {
			t.Fatal("got no error, want one")
		}

		for _, want := range []string{`"/broken"`, "conditions[1]", "query_val_matches.b"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want it to mention %q", err, want)
			}
		}
	})
}
